import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import type {
  AuditAction,
  AuditEvent as AuditEventDto,
  AuditOutcome,
  AuditPage,
  AuditQuery,
} from '@infraward/shared-types';
import { AUDIT_ACTIONS } from '@infraward/shared-types';
import { Brackets, type EntityManager, Repository } from 'typeorm';
import type { AuditActor } from './audit-context.decorator.js';
import { AuditEvent } from './audit-event.entity.js';
import { sanitizeDetails } from './sanitize.js';

export interface AuditTarget {
  type: string;
  id?: string | null;
  label?: string | null;
}

export interface AuditRecordOptions {
  target?: AuditTarget;
  outcome?: AuditOutcome;
  details?: Record<string, unknown>;
  /** Para escribir el evento en la misma transacción que la acción. */
  manager?: EntityManager;
}

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

/** Registro de auditoría (DESIGN §14): solo añade filas y las consulta. */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(
    @InjectRepository(AuditEvent)
    private readonly events: Repository<AuditEvent>,
  ) {}

  async record(
    actor: AuditActor,
    action: AuditAction,
    options: AuditRecordOptions = {},
  ): Promise<void> {
    const repo = options.manager
      ? options.manager.getRepository(AuditEvent)
      : this.events;
    await repo.insert({
      // Fecha de JS (milisegundos) y no now() de PostgreSQL: el cursor de la paginación la
      // compara tal cual.
      occurredAt: new Date(),
      actorId: actor.actorId,
      actorEmail: actor.actorEmail?.slice(0, 320) ?? null,
      action,
      outcome: options.outcome ?? 'success',
      targetType: options.target?.type ?? null,
      targetId: options.target?.id ?? null,
      targetLabel: options.target?.label?.slice(0, 255) ?? null,
      ip: actor.ip,
      details: sanitizeDetails(
        actor.via ? { ...options.details, viaApi: actor.via } : options.details,
      ),
    });
  }

  /** Como `record`, pero un fallo al auditar se registra en el log sin romper la acción. */
  async tryRecord(
    actor: AuditActor,
    action: AuditAction,
    options: AuditRecordOptions = {},
  ): Promise<void> {
    try {
      await this.record(actor, action, options);
    } catch (error) {
      this.logger.error(
        `No se pudo auditar ${action}: ${(error as Error).message}`,
      );
    }
  }

  /** Lo más reciente primero, por cursor `(occurred_at, id)`. */
  async list(query: AuditQuery): Promise<AuditPage> {
    const limit = Math.min(query.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
    const qb = this.events
      .createQueryBuilder('e')
      .orderBy('e.occurred_at', 'DESC')
      .addOrderBy('e.id', 'DESC')
      .take(limit + 1);

    const actions = new Set<string>(query.action ?? []);
    for (const category of query.category ?? [])
      for (const a of AUDIT_ACTIONS)
        if (a.startsWith(`${category}.`)) actions.add(a);
    if (query.action?.length || query.category?.length)
      qb.andWhere('e.action IN (:...actions)', {
        actions: actions.size > 0 ? [...actions] : [''],
      });
    if (query.actorId) qb.andWhere('e.actor_id = :actorId', { actorId: query.actorId });
    if (query.targetId)
      qb.andWhere('e.target_id = :targetId', { targetId: query.targetId });
    if (query.outcome) qb.andWhere('e.outcome = :outcome', { outcome: query.outcome });
    if (query.from) qb.andWhere('e.occurred_at >= :from', { from: query.from });
    if (query.to) qb.andWhere('e.occurred_at <= :to', { to: query.to });
    if (query.q?.trim()) {
      const like = `%${query.q.trim().replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      qb.andWhere(
        new Brackets((w) =>
          w
            .where('e.target_label ILIKE :like', { like })
            .orWhere('e.actor_email ILIKE :like', { like }),
        ),
      );
    }
    if (query.cursor) {
      const { at, id } = decodeCursor(query.cursor);
      qb.andWhere('(e.occurred_at, e.id) < (:at, :id)', { at, id });
    }

    const rows = await qb.getMany();
    const page = rows.slice(0, limit);
    const last = page.at(-1);
    return {
      items: page.map(toDto),
      nextCursor:
        rows.length > limit && last
          ? encodeCursor(last.occurredAt, last.id)
          : null,
    };
  }
}

function toDto(e: AuditEvent): AuditEventDto {
  return {
    id: e.id,
    occurredAt: e.occurredAt.toISOString(),
    actorId: e.actorId,
    actorEmail: e.actorEmail,
    action: e.action,
    outcome: e.outcome,
    targetType: e.targetType,
    targetId: e.targetId,
    targetLabel: e.targetLabel,
    ip: e.ip,
    details: e.details,
  };
}

export function encodeCursor(at: Date, id: string): string {
  return Buffer.from(`${at.toISOString()}|${id}`, 'utf8').toString('base64url');
}

export function decodeCursor(cursor: string): { at: string; id: string } {
  const [at, id] = Buffer.from(cursor, 'base64url').toString('utf8').split('|');
  if (
    !at ||
    !id ||
    Number.isNaN(Date.parse(at)) ||
    !/^[0-9a-f-]{36}$/i.test(id)
  )
    throw new BadRequestException('Cursor no válido');
  return { at, id };
}
