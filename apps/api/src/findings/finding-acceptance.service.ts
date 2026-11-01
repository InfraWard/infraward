import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { scanEnabledSql } from '@infraward/domain';
import {
  byCodeUnit,
  FINDING_ACCEPT_MAX,
  FINDING_ACCEPT_MAX_DAYS,
  type FindingAcceptance,
  type FindingAcceptanceResult,
  type FindingStatus,
} from '@infraward/shared-types';
import type { DataSource, EntityManager } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import type {
  AcceptFindingsDto,
  ReopenFindingsDto,
} from './finding-acceptance.dto.js';

/** CVE que se guardan en el detalle de la auditoría (el resto, como número). */
const AUDIT_CVES_MAX = 10;

/** La aceptación de una fila de `findings f` como JSON (null si nunca se aceptó). */
export const ACCEPTANCE_JSON = `CASE WHEN f.accepted_at IS NULL THEN NULL ELSE jsonb_build_object(
  'by', f.accepted_by, 'at', f.accepted_at, 'reason', f.accept_reason,
  'expiresAt', f.accept_expires_at) END`;

/** Columnas de la aceptación en una fila de `findings`. */
export interface AcceptanceRow {
  accepted_at: Date | null;
  accepted_by: string | null;
  accept_reason: string | null;
  accept_expires_at: Date | null;
}

export function acceptanceOf(row: AcceptanceRow): FindingAcceptance | null {
  if (!row.accepted_at) return null;
  return {
    by: row.accepted_by,
    at: row.accepted_at.toISOString(),
    reason: row.accept_reason ?? '',
    expiresAt: row.accept_expires_at?.toISOString() ?? null,
  };
}

/**
 * Caducidad pedida: futura y como mucho a `FINDING_ACCEPT_MAX_DAYS` (null: no caduca). 400 si no.
 */
export function acceptExpiry(
  value: string | null | undefined,
  now = new Date(),
): Date | null {
  if (value === undefined || value === null) return null;
  const at = new Date(value);
  if (Number.isNaN(at.getTime()))
    throw new BadRequestException('Fecha de caducidad inválida');
  if (at.getTime() <= now.getTime())
    throw new BadRequestException('La caducidad tiene que ser futura');
  if (at.getTime() > now.getTime() + FINDING_ACCEPT_MAX_DAYS * 86_400_000)
    throw new BadRequestException(
      `La caducidad no puede pasar de ${FINDING_ACCEPT_MAX_DAYS} días`,
    );
  return at;
}

/**
 * «Aceptar el riesgo» de findings (DESIGN §9): pasan a `accepted` con motivo, autor y caducidad
 * (opcional), y salen de los recuentos de abiertos; siguen contando como «afecta» en el buscador.
 * Reabrir los vuelve a `open`. Cada operación es un evento de auditoría.
 */
@Injectable()
export class FindingAcceptanceService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly audit: AuditService,
  ) {}

  accept(
    body: AcceptFindingsDto,
    actor: AuditActor,
  ): Promise<FindingAcceptanceResult> {
    const expiresAt = acceptExpiry(body.expiresAt);
    const reason = body.reason.trim();
    return this.db.transaction(async (m) => {
      const ids = await this.resolve(m, body, 'open');
      const [rows]: [{ vulnerability_id: string }[], number] = await m.query(
        `UPDATE findings f SET status = 'accepted', accepted_at = now(), accepted_by = $2,
                accept_reason = $3, accept_expires_at = $4
          WHERE f.id = ANY($1::uuid[]) AND f.status = 'open'
         RETURNING f.vulnerability_id`,
        [ids, actor.actorEmail, reason, expiresAt],
      );
      return this.record(m, actor, 'finding.accepted', rows, {
        reason,
        expiresAt: expiresAt?.toISOString() ?? null,
      });
    });
  }

  reopen(
    body: ReopenFindingsDto,
    actor: AuditActor,
  ): Promise<FindingAcceptanceResult> {
    return this.db.transaction(async (m) => {
      const ids = await this.resolve(m, body, 'accepted');
      // Vuelve a abrirse: cuenta como nuevo para «desde tu última visita» y, si es crítico, en KEV
      // y expuesto, el siguiente cálculo de prioridades avisa. La aceptación queda como historial.
      const [rows]: [{ vulnerability_id: string }[], number] = await m.query(
        `UPDATE findings f SET status = 'open', opened_at = now(), kev_alerted_at = NULL
          WHERE f.id = ANY($1::uuid[]) AND f.status = 'accepted'
         RETURNING f.vulnerability_id`,
        [ids],
      );
      return this.record(m, actor, 'finding.reopened', rows, {});
    });
  }

  /**
   * Findings de la operación en estado `status`, bloqueados. Por CVE, los de dueños no retirados
   * que escanean (los mismos que enseña la lista), de un proyecto si se pide.
   */
  private async resolve(
    m: EntityManager,
    target: ReopenFindingsDto,
    status: FindingStatus,
  ): Promise<string[]> {
    const byIds = !!target.findingIds?.length;
    const byCves = !!target.vulnerabilityIds?.length;
    if (byIds === byCves)
      throw new BadRequestException(
        'Indica findingIds o vulnerabilityIds (uno de los dos)',
      );
    let rows: { id: string }[];
    if (byIds) {
      rows = await m.query(
        `SELECT f.id FROM findings f WHERE f.id = ANY($1::uuid[]) AND f.status = $2
          FOR UPDATE`,
        [[...new Set(target.findingIds)], status],
      );
      if (!rows.length) {
        const [{ n }]: { n: number }[] = await m.query(
          `SELECT count(*)::int AS n FROM findings WHERE id = ANY($1::uuid[])`,
          [target.findingIds],
        );
        if (!n) throw new NotFoundException('Finding no encontrado');
      }
    } else {
      const params: unknown[] = [
        target.vulnerabilityIds!.map((v) => v.toUpperCase()),
        status,
      ];
      let project = '';
      if (target.projectId) {
        params.push(target.projectId);
        project = 'AND o.effective_projects @> ARRAY[$3]::uuid[]';
      }
      rows = await m.query(
        `SELECT f.id FROM findings f JOIN assets o ON o.id = f.asset_id
          WHERE upper(f.vulnerability_id) = ANY($1::text[]) AND f.status = $2
            AND o.status <> 'retired' AND ${scanEnabledSql('o')} ${project}
          FOR UPDATE OF f`,
        params,
      );
    }
    if (!rows.length)
      throw new ConflictException(
        status === 'open'
          ? 'No hay findings abiertos que aceptar'
          : 'No hay findings con el riesgo aceptado que reabrir',
      );
    if (rows.length > FINDING_ACCEPT_MAX)
      throw new BadRequestException(
        `Son ${rows.length} findings: como mucho ${FINDING_ACCEPT_MAX} por operación`,
      );
    return rows.map((r) => r.id);
  }

  private async record(
    m: EntityManager,
    actor: AuditActor,
    action: 'finding.accepted' | 'finding.reopened',
    rows: { vulnerability_id: string }[],
    details: Record<string, string | null>,
  ): Promise<FindingAcceptanceResult> {
    const cves = [...new Set(rows.map((r) => r.vulnerability_id))].sort(byCodeUnit);
    await this.audit.record(actor, action, {
      target: {
        type: 'vulnerability',
        label: cves.length === 1 ? cves[0]! : `${cves.length} CVE`,
      },
      details: {
        count: rows.length,
        vulnerabilities: cves.slice(0, AUDIT_CVES_MAX),
        ...(cves.length > AUDIT_CVES_MAX
          ? { moreVulnerabilities: cves.length - AUDIT_CVES_MAX }
          : {}),
        ...details,
      },
      manager: m,
    });
    return { updated: rows.length, vulnerabilities: cves.length };
  }
}
