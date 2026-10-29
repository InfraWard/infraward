import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  EXPOSED_ASSETS_SQL,
  kernelPackageUse,
  Notification,
} from '@infraward/domain';
import {
  NOTIFICATION_MAX_ITEMS,
  portExposure,
  scoreFinding,
  type CollectedPort,
  type CollectedProcess,
  type DockerPortBinding,
  type FindingsPrioritizeJobResult,
  type NoiseReason,
  type PriorityInput,
  type PriorityReason,
  type Severity,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';

/** Assets por tanda (sus findings caben de sobra en memoria). */
const ASSET_BATCH = 50;
/** Filas por UPDATE. */
const UPDATE_BATCH = 2000;

/** Contexto de un asset con findings. */
export interface AssetContext {
  id: string;
  name: string;
  type: string;
  kernel: string | null;
  /** null en un servidor o CT sin la v6 (o en una imagen, que no los necesita). */
  processes: CollectedProcess[] | null;
  ports: CollectedPort[];
  /** Contenedores no retirados que usan la imagen (`instance_of`). */
  containers: {
    status: string;
    state: string | null;
    ports: DockerPortBinding[];
  }[];
  publicDomains: { domains: string[]; total: number } | null;
}

/** Finding con lo que hace falta para puntuarlo. */
export interface FindingRow {
  id: string;
  vulnerabilityId: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string | null;
  fixStatus: string | null;
  severity: Severity;
  cvss: number | null;
  status: 'open' | 'accepted';
  inKev: boolean;
  kevRansomware: boolean;
  epss: number | null;
}

export interface Prioritized {
  priority: number;
  reasons: PriorityReason[];
  noise: NoiseReason | null;
  /** Crítico, en KEV y expuesto (puerto o dominio público). */
  kevExposed: boolean;
}

const NO_FIX_PLANNED = new Set(['will_not_fix', 'fix_deferred']);

/** Puntuación, motivos y ruido de un finding en su asset (pura). */
export function prioritizeFinding(f: FindingRow, a: AssetContext): Prioritized {
  const noise: PriorityReason[] = [];
  let noiseReason: NoiseReason | null = null;
  const kernel = kernelPackageUse({
    packageName: f.packageName,
    installedVersion: f.installedVersion,
    runningKernel: a.kernel,
    assetType: a.type,
  });
  if (kernel && kernel.use !== 'running') {
    noiseReason = 'kernel_not_running';
    noise.push(
      kernel.use === 'other'
        ? { code: 'kernel_other', running: kernel.running }
        : kernel.use === 'aux'
          ? { code: 'kernel_aux' }
          : {
              code: 'kernel_guest',
              assetType: a.type === 'lxc' ? 'lxc' : 'image',
            },
    );
  } else if (f.fixStatus && NO_FIX_PLANNED.has(f.fixStatus) && !f.inKev) {
    // Un CVE en KEV no se oculta: explotado activamente, aunque la distribución no lo corrija.
    noiseReason = 'no_fix_planned';
    noise.push({
      code: 'no_fix_planned',
      fixStatus: f.fixStatus as 'will_not_fix' | 'fix_deferred',
    });
  }

  const isImage = a.type === 'image';
  let service: PriorityInput['service'] = null;
  let exposedPorts: number[] = [];
  let runningContainers = 0;
  let unusedImage = false;
  if (isImage) {
    const running = a.containers.filter(
      (c) => c.status === 'active' && c.state === 'running',
    );
    runningContainers = running.length;
    unusedImage = !a.containers.some((c) => c.status === 'active');
    exposedPorts = running.flatMap((c) =>
      c.ports
        .filter(
          (p) =>
            p.hostPort != null &&
            portExposure(p.hostIp ?? '0.0.0.0') !== 'local',
        )
        .map((p) => p.hostPort as number),
    );
  } else if (a.processes && !kernel) {
    // Procesos que usan el paquete (ejecutable o librería), los expuestos primero.
    const users = a.processes
      .map((p) => ({
        p,
        via:
          p.exePackage === f.packageName ? ('exe' as const) : ('lib' as const),
        ports: a.ports
          .filter(
            (port) =>
              port.pid === p.pid && portExposure(port.address) !== 'local',
          )
          .map((port) => port.port),
      }))
      .filter(
        ({ p, via }) => via === 'exe' || p.libPackages.includes(f.packageName),
      )
      .sort(
        (x, y) =>
          Number(y.ports.length > 0) - Number(x.ports.length > 0) ||
          Number(y.via === 'exe') - Number(x.via === 'exe'),
      );
    if (users[0])
      service = {
        process: users[0].p.name || users[0].p.unit || 'proceso',
        unit: users[0].p.unit,
        via: users[0].via,
      };
    exposedPorts = users.flatMap((u) => u.ports);
  }

  const result = scoreFinding({
    severity: f.severity,
    cvss: f.cvss,
    kev: f.inKev ? { ransomware: f.kevRansomware } : null,
    epss: f.epss,
    fixable: f.fixedVersion !== null,
    service,
    exposedPorts,
    runningContainers,
    publicDomains: a.publicDomains,
    unusedImage,
    processData: isImage || a.processes !== null,
    noise,
  });
  return {
    priority: result.score,
    reasons: result.reasons,
    noise: noiseReason,
    kevExposed:
      f.status === 'open' &&
      f.severity === 'CRITICAL' &&
      f.inKev &&
      noiseReason !== 'kernel_not_running' &&
      (exposedPorts.length > 0 || a.publicDomains !== null),
  };
}

interface StoredRow extends FindingRow {
  assetId: string;
  priority: number | null;
  priorityReasons: PriorityReason[] | null;
  noiseReason: NoiseReason | null;
  kevAlertedAt: Date | null;
}

/**
 * Recalcula la prioridad de todos los findings abiertos o aceptados (`findings.prioritize`,
 * DESIGN §9) y avisa de los críticos en KEV y expuestos. Solo escribe lo que cambia; el aviso,
 * una vez por apertura (`kev_alerted_at`), seguro aunque haya dos pasadas a la vez.
 */
@Injectable()
export class FindingPrioritizer {
  private readonly logger = new Logger(FindingPrioritizer.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async run(): Promise<FindingsPrioritizeJobResult> {
    const owners: { id: string }[] = await this.db.query(
      `SELECT a.id FROM assets a
        WHERE a.status <> 'retired'
          AND EXISTS (SELECT 1 FROM findings f
                       WHERE f.asset_id = a.id AND f.status IN ('open', 'accepted'))
        ORDER BY a.id`,
    );
    const exposure = await this.exposure();
    let findings = 0;
    let updated = 0;
    let alerts = 0;
    for (let i = 0; i < owners.length; i += ASSET_BATCH) {
      const ids = owners.slice(i, i + ASSET_BATCH).map((o) => o.id);
      const assets = await this.contexts(ids, exposure);
      const rows = await this.findings(ids);
      findings += rows.length;
      const changes: {
        id: string;
        priority: number;
        reasons: PriorityReason[];
        noise: NoiseReason | null;
      }[] = [];
      const kev = new Map<string, StoredRow[]>();
      for (const row of rows) {
        const asset = assets.get(row.assetId);
        if (!asset) continue;
        const p = prioritizeFinding(row, asset);
        if (
          row.priority !== p.priority ||
          row.noiseReason !== p.noise ||
          JSON.stringify(row.priorityReasons) !== JSON.stringify(p.reasons)
        )
          changes.push({
            id: row.id,
            priority: p.priority,
            reasons: p.reasons,
            noise: p.noise,
          });
        if (p.kevExposed && !row.kevAlertedAt)
          kev.set(row.assetId, [...(kev.get(row.assetId) ?? []), row]);
      }
      for (let j = 0; j < changes.length; j += UPDATE_BATCH) {
        await this.db.query(
          `UPDATE findings f
              SET priority = x.priority, priority_reasons = x.reasons, noise_reason = x.noise
             FROM jsonb_to_recordset($1::jsonb) AS x(
                    id uuid, priority smallint, reasons jsonb, noise varchar)
            WHERE f.id = x.id`,
          [JSON.stringify(changes.slice(j, j + UPDATE_BATCH))],
        );
      }
      updated += changes.length;
      for (const [assetId, list] of kev)
        alerts += await this.alert(assets.get(assetId)!, list);
    }
    this.logger.log(
      `Prioridad de ${findings} findings: ${updated} cambiados${alerts ? `, ${alerts} ${alerts === 1 ? 'CVE avisado' : 'CVE avisados'} (KEV)` : ''}`,
    );
    return { findings, updated, alerts };
  }

  /** Nombres públicos por asset (QoL-5b). */
  private async exposure(): Promise<
    Map<string, { domains: string[]; total: number }>
  > {
    const rows: { asset_id: string; n: number; names: string[] }[] =
      await this.db.query(EXPOSED_ASSETS_SQL);
    return new Map(
      rows.map((r) => [r.asset_id, { domains: r.names, total: r.n }]),
    );
  }

  private async contexts(
    ids: string[],
    exposure: Map<string, { domains: string[]; total: number }>,
  ): Promise<Map<string, AssetContext>> {
    const rows: {
      id: string;
      name: string;
      type: string;
      kernel: string | null;
      processes: CollectedProcess[] | null;
      ports: CollectedPort[] | null;
    }[] = await this.db.query(
      `SELECT a.id, a.name, a.type, a.facts->'os'->>'kernel' AS kernel,
              CASE WHEN jsonb_typeof(a.facts->'processes') = 'array'
                   THEN a.facts->'processes' END AS processes,
              CASE WHEN jsonb_typeof(a.facts->'ports') = 'array'
                   THEN a.facts->'ports' END AS ports
         FROM assets a WHERE a.id = ANY($1::uuid[])`,
      [ids],
    );
    const containers: {
      image_id: string;
      status: string;
      state: string | null;
      ports: DockerPortBinding[] | null;
    }[] = await this.db.query(
      `SELECT r.child_id AS image_id, c.status, c.facts->'docker'->>'state' AS state,
              CASE WHEN jsonb_typeof(c.facts->'docker'->'ports') = 'array'
                   THEN c.facts->'docker'->'ports' END AS ports
         FROM asset_relations r
         JOIN assets c ON c.id = r.parent_id AND c.status <> 'retired'
        WHERE r.type = 'instance_of' AND r.child_id = ANY($1::uuid[])`,
      [ids],
    );
    const out = new Map<string, AssetContext>();
    for (const r of rows)
      out.set(r.id, {
        id: r.id,
        name: r.name,
        type: r.type,
        kernel: r.kernel,
        processes: r.type === 'image' ? null : r.processes,
        ports: r.ports ?? [],
        containers: [],
        publicDomains: exposure.get(r.id) ?? null,
      });
    for (const c of containers)
      out.get(c.image_id)?.containers.push({
        status: c.status,
        state: c.state,
        ports: c.ports ?? [],
      });
    return out;
  }

  private async findings(ids: string[]): Promise<StoredRow[]> {
    return this.db.query(
      `SELECT f.id, f.asset_id AS "assetId", f.vulnerability_id AS "vulnerabilityId",
              f.package_name AS "packageName", f.installed_version AS "installedVersion",
              f.fixed_version AS "fixedVersion", f.fix_status AS "fixStatus", f.severity,
              f.cvss_score AS cvss, f.status, f.priority,
              f.priority_reasons AS "priorityReasons", f.noise_reason AS "noiseReason",
              f.kev_alerted_at AS "kevAlertedAt",
              COALESCE(i.in_kev, false) AS "inKev",
              COALESCE(i.kev_ransomware, false) AS "kevRansomware", i.epss
         FROM findings f
         LEFT JOIN vulnerability_intel i ON i.vulnerability_id = f.vulnerability_id
        WHERE f.asset_id = ANY($1::uuid[]) AND f.status IN ('open', 'accepted')`,
      [ids],
    );
  }

  /**
   * Aviso inmediato de CVE críticos, en KEV y expuestos de un asset. Marca `kev_alerted_at`
   * solo en los que aún no lo tenían (otra pasada a la vez no avisa dos veces).
   */
  private async alert(asset: AssetContext, rows: StoredRow[]): Promise<number> {
    return this.db.transaction(async (m) => {
      // Un UPDATE … RETURNING devuelve [filas, recuento].
      const [marked]: [{ id: string }[], number] = await m.query(
        `UPDATE findings SET kev_alerted_at = now()
          WHERE id = ANY($1::uuid[]) AND kev_alerted_at IS NULL RETURNING id`,
        [rows.map((r) => r.id)],
      );
      const ids = new Set(marked.map((r) => r.id));
      const cves = [
        ...new Map(
          rows.filter((r) => ids.has(r.id)).map((r) => [r.vulnerabilityId, r]),
        ).values(),
      ];
      if (cves.length === 0) return 0;
      const names = cves
        .slice(0, 5)
        .map((r) => `${r.vulnerabilityId} (${r.packageName})`);
      const more = cves.length > 5 ? ` y ${cves.length - 5} más` : '';
      await m.insert(Notification, {
        kind: 'vulnerability_kev',
        assetId: asset.id,
        assetName: asset.name,
        message: `${asset.name}: ${cves.length === 1 ? '1 CVE crítico explotado activamente (KEV) y expuesto' : `${cves.length} CVE críticos explotados activamente (KEV) y expuestos`} — ${names.join(', ')}${more}`,
        items: cves.slice(0, NOTIFICATION_MAX_ITEMS).map((r) => ({
          id: r.vulnerabilityId,
          name: `${r.vulnerabilityId} (${r.packageName})`,
          type: 'vulnerability' as const,
        })),
        total: cves.length,
      });
      this.logger.warn(
        `Aviso de KEV en ${asset.name}: ${cves.map((r) => r.vulnerabilityId).join(', ')}`,
      );
      return cves.length;
    });
  }
}
