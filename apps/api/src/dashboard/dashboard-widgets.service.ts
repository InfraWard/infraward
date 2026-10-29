import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  dnsWarningSql,
  expiryWarningDays,
  scanEnabledSql,
} from '@infraward/domain';
import {
  ASSET_STATUSES,
  ASSET_TYPES,
  ATTENTION_KINDS,
  hasPermission,
  PRIORITY_BAND_MIN,
  PRIORITY_BANDS,
  priorityInfo,
  SEVERITIES,
  SSH_CA_CONFIG_VERSION,
  TREND_RANGE_DAYS,
  type AssetCountsData,
  type AssetStatus,
  type AssetSummary,
  type AssetType,
  type AttentionData,
  type AttentionKind,
  type DashboardAttention,
  type ExpirationsData,
  type FixableVulnerabilitiesData,
  type FindingListQuery,
  type NewVulnerabilitiesData,
  type PendingEnrollmentData,
  type PriorityBand,
  type PriorityReason,
  type RecentActivityData,
  type RunningJobsData,
  type Severity,
  type TopVulnerabilitiesData,
  type TrendData,
  type TrendMetric,
  type TrendPoint,
  type TrendRange,
  type UserRole,
  type VulnerabilityCountsData,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { findingWhere } from '../findings/finding-where.js';
import {
  JOB_RUN_COLUMNS,
  JobRunsService,
  toJobRunSummary,
} from '../jobs/job-runs.service.js';
import { SshCaTrustService } from '../secrets/ssh-ca-trust.service.js';
import { vaultRotationOverdue } from '../vault/vault-settings.js';
import {
  assetScopeSql,
  scopeSearchQuery,
  SqlParams,
  type WidgetScope,
} from './widget-scope.js';

const SEVERITY_BY_RANK = [...SEVERITIES].reverse();
const SEVERITY_RANK = `ARRAY[${SEVERITY_BY_RANK.map((v) => `'${v}'`).join(',')}]::text[]`;
const ATTENTION_SAMPLE = 5;
const DAY_MS = 86_400_000;

type Push = (value: unknown) => string;

/** Condición (sobre `assets a`) de cada aviso; `soon` es el umbral mayor de caducidad. */
const ATTENTION_SQL: Record<
  Exclude<AttentionKind, 'vaultRotationOverdue' | 'sshCaOutdated'>,
  (push: Push, soon: number) => string
> = {
  sudoersOutdated: () =>
    `(a.facts->'infraward'->'sudoersOutdated') = 'true'::jsonb`,
  partialCollection: () =>
    `jsonb_typeof(a.facts->'infraward'->'warnings') = 'array'
     AND jsonb_array_length(a.facts->'infraward'->'warnings') > 0`,
  // Assets cuya última ejecución de algún tipo de job (en 24 h) falló.
  failedJobs: () => `a.id IN (
     SELECT asset_id FROM (
       SELECT DISTINCT ON (r.asset_id, r.name) r.asset_id, r.state
         FROM job_runs r
        WHERE r.asset_id IS NOT NULL AND r.created_at > now() - interval '24 hours'
        ORDER BY r.asset_id, r.name, r.created_at DESC) last
      WHERE last.state = 'failed')`,
  duplicates: () => `a.duplicate_of_id IS NOT NULL`,
  clones: () =>
    `jsonb_typeof(a.facts->'infraward'->'machineIdClone') = 'object'`,
  // Certificados y dominios caducados o que caducan antes del umbral mayor.
  certificatesExpiring: (push, soon) => `a.type = 'certificate'
     AND jsonb_typeof(a.facts->'certificate'->'notAfter') = 'string'
     AND (a.facts->'certificate'->>'notAfter')::timestamptz < now() + make_interval(days => ${push(soon)})`,
  domainsExpiring: (push, soon) => `a.type = 'domain'
     AND jsonb_typeof(a.facts->'registration'->'expiresAt') = 'string'
     AND (a.facts->'registration'->>'expiresAt')::timestamptz < now() + make_interval(days => ${push(soon)})`,
  // Registros DNS colgantes sin marcar como esperados: alto e informativo.
  dnsDangling: () => `a.type = 'dns_record' AND EXISTS (
     SELECT 1 FROM dns_record_checks c
      WHERE c.asset_id = a.id AND c.level = 'high' AND ${dnsWarningSql('c')})`,
  dnsUnknown: () => `a.type = 'dns_record' AND EXISTS (
     SELECT 1 FROM dns_record_checks c
      WHERE c.asset_id = a.id AND c.level = 'info' AND ${dnsWarningSql('c')})`,
  // sshd admite root o contraseñas (`sshd -T`, sudoers v7): misma regla que `sshdAuthRisk`.
  sshdPasswordLogin: () => `jsonb_typeof(a.facts->'sshd') = 'object'
     AND ((a.facts->'sshd'->>'permitRootLogin') = 'yes'
          OR (a.facts->'sshd'->'passwordAuthentication') = 'true'::jsonb
          OR (a.facts->'sshd'->'kbdInteractiveAuthentication') = 'true'::jsonb)`,
};

/** Fecha `YYYY-MM-DD` (UTC). */
function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/**
 * Datos de cada widget del panel (QoL-8, DESIGN §15): solo lo suyo, con agregados y `LIMIT` en
 * SQL, nunca el inventario entero. La caché va en el controlador.
 */
@Injectable()
export class DashboardWidgetsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly runs: JobRunsService,
    private readonly sshCa: SshCaTrustService,
  ) {}

  /**
   * CVE de la vista principal de Vulnerabilidades (abiertas, sin ruido, sin imágenes sin uso ni
   * escaneo desactivado; `extra` añade prioridad mínima o fecha), uno por fila con su prioridad
   * máxima. Los tags y tipos van al asset afectado, como en la lista.
   */
  private vulnerabilityGroups(
    scope: WidgetScope,
    extra: Partial<FindingListQuery>,
  ): { sql: string; params: unknown[] } {
    const { where, params } = findingWhere(
      {
        status: 'open',
        inUse: true,
        projectId: scope.projectId,
        q: scopeSearchQuery(scope),
        ...extra,
      },
      { where: [`o.status <> 'retired'`], params: [] },
    );
    return {
      sql: `
      SELECT f.vulnerability_id, max(f.priority) AS score,
             (array_agg(f.priority_reasons ORDER BY f.priority DESC NULLS LAST, f.id))[1] AS reasons,
             min(array_position(${SEVERITY_RANK}, f.severity::text)) AS rank,
             bool_or(COALESCE(vi.in_kev, false)) AS kev,
             count(DISTINCT f.asset_id)::int AS assets
        FROM findings f JOIN assets o ON o.id = f.asset_id
        LEFT JOIN vulnerability_intel vi ON vi.vulnerability_id = f.vulnerability_id
       WHERE ${where.join(' AND ')}
       GROUP BY f.vulnerability_id`,
      params,
    };
  }

  async vulnerabilityCounts(
    scope: WidgetScope,
  ): Promise<VulnerabilityCountsData> {
    const groups = this.vulnerabilityGroups(scope, { minPriority: 'medium' });
    const [row] = (await this.db.query(
      `SELECT count(*) FILTER (WHERE score >= ${PRIORITY_BAND_MIN.urgent})::int AS urgent,
              count(*) FILTER (WHERE score >= ${PRIORITY_BAND_MIN.high}
                                 AND score < ${PRIORITY_BAND_MIN.urgent})::int AS high,
              count(*) FILTER (WHERE score < ${PRIORITY_BAND_MIN.high})::int AS medium,
              count(*) FILTER (WHERE kev)::int AS kev,
              count(*)::int AS cves
         FROM (${groups.sql}) g`,
      groups.params,
    )) as VulnerabilityCountsData[];
    return row!;
  }

  /** Los `limit` CVE más prioritarios (de prioridad ≥ `minPriority`) y cuántos cumplen. */
  async topVulnerabilities(
    scope: WidgetScope,
    limit: number,
    minPriority: PriorityBand,
  ): Promise<TopVulnerabilitiesData> {
    return this.topOf(this.vulnerabilityGroups(scope, { minPriority }), limit);
  }

  /** CVE abiertos desde `since` (sin ruido ni imágenes sin uso), por prioridad. */
  async newVulnerabilities(
    scope: WidgetScope,
    since: Date,
    limit: number,
  ): Promise<NewVulnerabilitiesData> {
    const top = await this.topOf(
      this.vulnerabilityGroups(scope, { openedSince: since.toISOString() }),
      limit,
    );
    return { ...top, since: since.toISOString(), kev: top.kevTotal };
  }

  private async topOf(
    groups: { sql: string; params: unknown[] },
    limit: number,
  ): Promise<TopVulnerabilitiesData & { kevTotal: number }> {
    const p = [...groups.params, limit];
    const rows = (await this.db.query(
      `SELECT g.*, count(*) OVER ()::int AS total,
              count(*) FILTER (WHERE g.kev) OVER ()::int AS kev_total
         FROM (${groups.sql}) g
        ORDER BY score DESC NULLS LAST, rank, vulnerability_id
        LIMIT $${p.length}`,
      p,
    )) as {
      vulnerability_id: string;
      score: number | null;
      reasons: PriorityReason[] | null;
      rank: number;
      kev: boolean;
      assets: number;
      total: number;
      kev_total: number;
    }[];
    let total = rows[0]?.total ?? 0;
    let kevTotal = rows[0]?.kev_total ?? 0;
    if (limit === 0) {
      const [c] = (await this.db.query(
        `SELECT count(*)::int AS total, count(*) FILTER (WHERE kev)::int AS kev
           FROM (${groups.sql}) g`,
        groups.params,
      )) as { total: number; kev: number }[];
      total = c?.total ?? 0;
      kevTotal = c?.kev ?? 0;
    }
    return {
      total,
      kevTotal,
      items: rows.map((r) => ({
        vulnerabilityId: r.vulnerability_id,
        severity: SEVERITY_BY_RANK[r.rank - 1]!,
        priority: priorityInfo(r.score, r.reasons) ?? {
          score: 0,
          band: 'low',
          reasons: [],
        },
        kev: r.kev,
        assets: r.assets,
      })),
    };
  }

  /**
   * Fecha de «Marcar como vistos» del usuario (la primera vez empieza a contar desde ahora, como
   * el panel de CVE nuevos de Vulnerabilidades).
   */
  async seenAt(userId: string): Promise<Date> {
    const [rows]: [{ seen: Date }[], number] = await this.db.query(
      `UPDATE users SET vulnerabilities_seen_at = coalesce(vulnerabilities_seen_at, now())
        WHERE id = $1 RETURNING vulnerabilities_seen_at AS seen`,
      [userId],
    );
    return rows[0]?.seen ?? new Date();
  }

  /**
   * Hallazgos abiertos por severidad, críticos y altos con parche y CVE distintos, con el criterio
   * de la tarjeta de un proyecto (`ProjectsService.stats`): dueños no retirados que escanean, ruido
   * incluido; los tags y tipos se aplican al dueño.
   */
  async fixableVulnerabilities(
    scope: WidgetScope,
  ): Promise<FixableVulnerabilitiesData> {
    const p = new SqlParams();
    const where = [
      `f.status = 'open'`,
      `o.status <> 'retired'`,
      scanEnabledSql('o'),
      ...assetScopeSql('o', scope, p.push),
    ];
    const from = `findings f JOIN assets o ON o.id = f.asset_id WHERE ${where.join(' AND ')}`;
    const [bySeverity, [cves]] = await Promise.all([
      this.db.query(
        `SELECT f.severity::text AS severity, count(*)::int AS n,
                count(*) FILTER (WHERE f.fixed_version IS NOT NULL)::int AS fixable
           FROM ${from} GROUP BY f.severity`,
        p.values,
      ) as Promise<{ severity: Severity; n: number; fixable: number }[]>,
      this.db.query(
        `SELECT count(DISTINCT f.vulnerability_id)::int AS n FROM ${from}`,
        p.values,
      ) as Promise<{ n: number }[]>,
    ]);
    const openFindings = Object.fromEntries(
      SEVERITIES.map((s) => [s, 0]),
    ) as Record<Severity, number>;
    const fixableFindings = { CRITICAL: 0, HIGH: 0 };
    for (const r of bySeverity) {
      openFindings[r.severity] = r.n;
      if (r.severity === 'CRITICAL' || r.severity === 'HIGH')
        fixableFindings[r.severity] = r.fixable;
    }
    return { openFindings, fixableFindings, openVulnerabilities: cves?.n ?? 0 };
  }

  /** Assets por tipo (sin retirados) o por estado (todos). */
  async assetCounts(
    scope: WidgetScope,
    groupBy: 'type' | 'status',
  ): Promise<AssetCountsData> {
    const p = new SqlParams();
    const where = assetScopeSql('a', scope, p.push);
    if (groupBy === 'type') where.push(`a.status <> 'retired'`);
    const rows = (await this.db.query(
      `SELECT a.${groupBy}::text AS k, count(*)::int AS n FROM assets a
        ${where.length ? `WHERE ${where.join(' AND ')}` : ''} GROUP BY 1`,
      p.values,
    )) as { k: AssetType | AssetStatus; n: number }[];
    const keys: readonly string[] =
      groupBy === 'type' ? ASSET_TYPES : ASSET_STATUSES;
    const counts: AssetCountsData['counts'] = {};
    for (const row of rows) if (keys.includes(row.k)) counts[row.k] = row.n;
    return {
      groupBy,
      counts,
      total: rows.reduce((sum, r) => sum + r.n, 0),
    };
  }

  async pendingEnrollment(
    scope: WidgetScope,
    limit: number,
  ): Promise<PendingEnrollmentData> {
    const { count, assets } = await this.assetsWhere(
      scope,
      () => `a.status = 'pending_enrollment'`,
      Math.max(limit, 0),
      true,
    );
    return { count, assets };
  }

  async runningJobs(scope: WidgetScope): Promise<RunningJobsData> {
    await this.runs.reconcileOrphans();
    return { count: await this.countRunning(scope) };
  }

  private async countRunning(scope: WidgetScope): Promise<number> {
    const p = new SqlParams();
    const where = [
      `r.state IN ('queued', 'active')`,
      ...assetScopeSql('a', scope, p.push),
    ];
    const [row] = (await this.db.query(
      `SELECT count(*)::int AS n FROM job_runs r LEFT JOIN assets a ON a.id = r.asset_id
        WHERE ${where.join(' AND ')}`,
      p.values,
    )) as { n: number }[];
    return row?.n ?? 0;
  }

  async recentActivity(
    scope: WidgetScope,
    limit: number,
    state: 'all' | 'failed' | 'running',
  ): Promise<RecentActivityData> {
    await this.runs.reconcileOrphans();
    const p = new SqlParams();
    const where = assetScopeSql('a', scope, p.push);
    if (state === 'failed') where.push(`r.state = 'failed'`);
    if (state === 'running') where.push(`r.state IN ('queued', 'active')`);
    const lim = p.push(limit);
    const [rows, running] = await Promise.all([
      this.db.query(
        `SELECT ${JOB_RUN_COLUMNS}
           FROM job_runs r LEFT JOIN assets a ON a.id = r.asset_id
          ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
          ORDER BY r.created_at DESC, r.id LIMIT ${lim}`,
        p.values,
      ) as Promise<Parameters<typeof toJobRunSummary>[0][]>,
      this.countRunning(scope),
    ]);
    const now = Date.now();
    return { items: rows.map((r) => toJobRunSummary(r, now)), running };
  }

  /**
   * Los avisos pedidos (todos con su recuento y los primeros assets, aunque sea 0) y las
   * credenciales sin rotar (null sin `vault.manage` o si no se pidió). La caja fuerte solo
   * filtra por proyecto.
   */
  async attentionAll(
    scope: WidgetScope,
    kinds: readonly AttentionKind[],
    role: UserRole | undefined,
  ): Promise<{
    attention: Partial<Record<AttentionKind, DashboardAttention>>;
    vaultRotationOverdue: number | null;
    expiryWarningDays: number[];
  }> {
    const days = await expiryWarningDays(this.db.manager);
    const soon = Math.max(...days);
    const wanted = kinds.filter((k) => k !== 'vaultRotationOverdue');
    const results = await Promise.all(
      wanted.map((kind) =>
        kind === 'sshCaOutdated'
          ? this.sshCaAttention(scope)
          : this.assetsWhere(
              scope,
              (push) => ATTENTION_SQL[kind](push, soon),
              ATTENTION_SAMPLE,
            ),
      ),
    );
    const vault =
      kinds.includes('vaultRotationOverdue') &&
      hasPermission(role, 'vault.manage')
        ? await vaultRotationOverdue(this.db.manager, scope.projectId ?? null)
        : null;
    return {
      attention: Object.fromEntries(wanted.map((k, i) => [k, results[i]!])),
      vaultRotationOverdue: vault,
      expiryWarningDays: days,
    };
  }

  async attention(
    scope: WidgetScope,
    kinds: readonly AttentionKind[],
    role: UserRole | undefined,
  ): Promise<AttentionData> {
    const all = await this.attentionAll(scope, kinds, role);
    const items: AttentionData['items'] = [];
    for (const kind of ATTENTION_KINDS) {
      if (!kinds.includes(kind)) continue;
      if (kind === 'vaultRotationOverdue') {
        if (all.vaultRotationOverdue)
          items.push({ kind, count: all.vaultRotationOverdue, assets: [] });
        continue;
      }
      const a = all.attention[kind];
      if (a?.count) items.push({ kind, ...a });
    }
    return { items, expiryWarningDays: all.expiryWarningDays };
  }

  /**
   * Servidores en modo CA cuyo conjunto de CA confiables (`facts.infraward.sshCa`) no es el
   * vigente o tiene una versión antigua (misma regla que `sshCaOutdated` de shared-types).
   * Las rutas `->` van entre paréntesis: `@>` y `->` tienen la misma precedencia.
   */
  private async sshCaAttention(
    scope: WidgetScope,
  ): Promise<DashboardAttention> {
    const current = await this.sshCa.currentFingerprints();
    if (current.length === 0) return { count: 0, assets: [] };
    return this.assetsWhere(
      scope,
      (push) => {
        const version = push(SSH_CA_CONFIG_VERSION);
        const trusted = push(JSON.stringify(current));
        return `a.ssh_auth = 'ca_certificate'
         AND jsonb_typeof(a.facts->'infraward'->'sshCa') = 'object'
         AND (coalesce((a.facts->'infraward'->'sshCa'->>'version')::int, 0) < ${version}
              OR NOT ((a.facts->'infraward'->'sshCa'->'trusted') @> ${trusted}::jsonb
                      AND ${trusted}::jsonb @> (a.facts->'infraward'->'sshCa'->'trusted')))`;
      },
      ATTENTION_SAMPLE,
    );
  }

  /**
   * Assets (no retirados, salvo los pendientes de alta si `pending`) del ámbito que cumplen la
   * condición (sobre `assets a`): cuántos y los primeros `limit` por nombre.
   */
  private async assetsWhere(
    scope: WidgetScope,
    condition: (push: Push) => string,
    limit: number,
    pending = false,
  ): Promise<DashboardAttention> {
    const p = new SqlParams();
    const where = [
      ...(pending ? [] : [`a.status <> 'retired'`]),
      ...assetScopeSql('a', scope, p.push),
      condition(p.push),
    ];
    if (limit === 0) {
      const [row] = (await this.db.query(
        `SELECT count(*)::int AS n FROM assets a WHERE ${where.join(' AND ')}`,
        p.values,
      )) as { n: number }[];
      return { count: row?.n ?? 0, assets: [] };
    }
    const lim = p.push(limit);
    const rows = (await this.db.query(
      `SELECT a.id, a.name, a.type, a.status, count(*) OVER ()::int AS total
         FROM assets a
        WHERE ${where.join(' AND ')}
        ORDER BY a.name, a.id
        LIMIT ${lim}`,
      p.values,
    )) as (AssetSummary & { total: number })[];
    if (!rows.length) return { count: 0, assets: [] };
    return {
      count: rows[0]!.total,
      assets: rows.map(({ id, name, type, status }) => ({
        id,
        name,
        type,
        status,
      })),
    };
  }

  /**
   * Dominios y certificados caducados o que caducan en menos de `horizonDays` (por defecto, el
   * umbral mayor de los avisos), los más próximos primero.
   */
  async expirations(
    scope: WidgetScope,
    kinds: readonly ('domain' | 'certificate')[],
    horizonDays: number | null,
    limit: number,
  ): Promise<ExpirationsData> {
    const days = await expiryWarningDays(this.db.manager);
    const horizon = horizonDays ?? Math.max(...days);
    const p = new SqlParams();
    const expires = `CASE
      WHEN a.type = 'certificate' AND jsonb_typeof(a.facts->'certificate'->'notAfter') = 'string'
        THEN (a.facts->'certificate'->>'notAfter')::timestamptz
      WHEN a.type = 'domain' AND jsonb_typeof(a.facts->'registration'->'expiresAt') = 'string'
        THEN (a.facts->'registration'->>'expiresAt')::timestamptz END`;
    const where = [
      `a.status <> 'retired'`,
      `a.type::text = ANY(${p.push(kinds)}::text[])`,
      ...assetScopeSql('a', { ...scope, types: undefined }, p.push),
    ];
    const h = p.push(horizon);
    const lim = p.push(limit);
    const rows = (await this.db.query(
      `SELECT x.*, count(*) OVER ()::int AS total FROM (
         SELECT a.id, a.name, a.type, a.status, ${expires} AS expires_at
           FROM assets a WHERE ${where.join(' AND ')}) x
        WHERE x.expires_at IS NOT NULL AND x.expires_at < now() + make_interval(days => ${h})
        ORDER BY x.expires_at, x.name, x.id
        LIMIT ${lim}`,
      p.values,
    )) as (AssetSummary & { expires_at: Date; total: number })[];
    const now = Date.now();
    return {
      horizonDays: horizon,
      expiryWarningDays: days,
      total: rows[0]?.total ?? 0,
      items: rows.map((r) => ({
        asset: { id: r.id, name: r.name, type: r.type, status: r.status },
        kind: r.type as 'domain' | 'certificate',
        expiresAt: r.expires_at.toISOString(),
        daysLeft: Math.floor((r.expires_at.getTime() - now) / DAY_MS),
      })),
    };
  }

  /** Gráfico de evolución (DESIGN §15): reconstruido de los findings o de las muestras diarias. */
  async trend(
    scope: WidgetScope,
    metric: TrendMetric,
    range: TrendRange,
  ): Promise<TrendData> {
    const today = new Date(isoDay(new Date()) + 'T00:00:00Z');
    const start = new Date(
      today.getTime() - (TREND_RANGE_DAYS[range] - 1) * DAY_MS,
    );
    if (metric === 'open-findings' || metric === 'new-vs-fixed')
      return this.findingTrend(scope, metric, range, start, today);
    return this.sampledTrend(scope, metric, start);
  }

  /**
   * Hallazgos abiertos por severidad o nuevos y corregidos, reconstruidos de `opened_at` y
   * `fixed_at` (sin ruido y con la política de escaneo de hoy): aproximado, porque un finding
   * reabierto pierde sus ciclos anteriores y los de assets purgados ya no están.
   */
  private async findingTrend(
    scope: WidgetScope,
    metric: 'open-findings' | 'new-vs-fixed',
    range: TrendRange,
    rangeStart: Date,
    today: Date,
  ): Promise<TrendData> {
    const { where, params } = findingWhere(
      { projectId: scope.projectId, q: scopeSearchQuery(scope) },
      { where: [], params: [] },
    );
    const from = `findings f JOIN assets o ON o.id = f.asset_id WHERE ${where.join(' AND ') || 'true'}`;
    const [first] = (await this.db.query(
      `SELECT min(f.opened_at) AS since FROM ${from}`,
      params,
    )) as { since: Date | null }[];
    const bucket = range === '1y' ? 'week' : 'day';
    // De más a menos grave: lo crítico, abajo en el apilado y primero en la leyenda.
    const severities: Severity[] = [...SEVERITY_BY_RANK];
    const series =
      metric === 'open-findings'
        ? severities.map((s) => ({ key: s, label: s, severity: s }))
        : [
            { key: 'opened', label: 'Nuevos' },
            { key: 'fixed', label: 'Corregidos' },
          ];
    const base: TrendData = {
      metric,
      bucket,
      approximate: true,
      since: first?.since ? first.since.toISOString() : null,
      ignoredFilters: false,
      series,
      points: [],
    };
    if (!first?.since) return base;
    const sinceDay = new Date(isoDay(first.since) + 'T00:00:00Z');
    const start = sinceDay > rangeStart ? sinceDay : rangeStart;
    const s = params.length + 1;
    const events = (await this.db.query(
      `WITH f AS (SELECT f.severity::text AS severity, f.opened_at, f.fixed_at FROM ${from})
       SELECT NULL::text AS day, severity,
              (count(*) FILTER (WHERE opened_at < $${s}))::int AS opened,
              (count(*) FILTER (WHERE fixed_at < $${s}))::int AS fixed
         FROM f GROUP BY severity
       UNION ALL
       SELECT d.day, d.severity, sum(d.opened)::int, sum(d.fixed)::int FROM (
         SELECT (opened_at AT TIME ZONE 'UTC')::date::text AS day, severity, 1 AS opened, 0 AS fixed
           FROM f WHERE opened_at >= $${s}
         UNION ALL
         SELECT (fixed_at AT TIME ZONE 'UTC')::date::text, severity, 0, 1
           FROM f WHERE fixed_at >= $${s}) d
        GROUP BY d.day, d.severity`,
      [...params, start],
    )) as {
      /** `YYYY-MM-DD` en texto: un `date` de pg llegaría como medianoche local. */
      day: string | null;
      severity: string;
      opened: number;
      fixed: number;
    }[];
    const open: Record<string, number> = Object.fromEntries(
      severities.map((v) => [v, 0]),
    );
    const byDay = new Map<
      string,
      { opened: Record<string, number>; fixed: Record<string, number> }
    >();
    for (const e of events) {
      if (e.day === null) {
        open[e.severity] = (open[e.severity] ?? 0) + e.opened - e.fixed;
        continue;
      }
      const key = e.day;
      const entry = byDay.get(key) ?? { opened: {}, fixed: {} };
      entry.opened[e.severity] = (entry.opened[e.severity] ?? 0) + e.opened;
      entry.fixed[e.severity] = (entry.fixed[e.severity] ?? 0) + e.fixed;
      byDay.set(key, entry);
    }
    const points: TrendPoint[] = [];
    let opened = 0;
    let fixed = 0;
    for (let t = start.getTime(); t <= today.getTime(); t += DAY_MS) {
      const day = isoDay(new Date(t));
      const entry = byDay.get(day);
      for (const sev of severities)
        open[sev] =
          open[sev]! + (entry?.opened[sev] ?? 0) - (entry?.fixed[sev] ?? 0);
      opened += Object.values(entry?.opened ?? {}).reduce((a, b) => a + b, 0);
      fixed += Object.values(entry?.fixed ?? {}).reduce((a, b) => a + b, 0);
      // En semanas, un punto por semana (el último día de cada una, o hoy).
      const weekday = new Date(t).getUTCDay();
      const close = bucket === 'day' || weekday === 0 || t === today.getTime();
      if (!close) continue;
      points.push({
        day,
        values: metric === 'open-findings' ? { ...open } : { opened, fixed },
      });
      opened = 0;
      fixed = 0;
    }
    return { ...base, points };
  }

  /**
   * CVE por banda o assets por estado de las muestras diarias (`metric_samples`): exactas, pero
   * solo desde que hay muestras y solo por proyecto.
   */
  private async sampledTrend(
    scope: WidgetScope,
    metric: 'cves-by-band' | 'assets-by-status',
    start: Date,
  ): Promise<TrendData> {
    const sample =
      metric === 'cves-by-band' ? 'cves_by_band' : 'assets_by_status';
    const project = scope.projectId ?? null;
    const [rows, [first]] = await Promise.all([
      this.db.query(
        `SELECT day::text AS day, "values" FROM metric_samples
          WHERE metric = $1 AND project_id IS NOT DISTINCT FROM $2 AND day >= $3::date
          ORDER BY day`,
        [sample, project, isoDay(start)],
      ) as Promise<{ day: string; values: Record<string, number> }[]>,
      this.db.query(
        `SELECT min(day)::text AS since FROM metric_samples
          WHERE metric = $1 AND project_id IS NOT DISTINCT FROM $2`,
        [sample, project],
      ) as Promise<{ since: string | null }[]>,
    ]);
    const series =
      metric === 'cves-by-band'
        ? [...PRIORITY_BANDS]
            .reverse()
            .filter((b) => b !== 'low')
            .map((b) => ({ key: b, label: b, band: b }))
        : // Retirados no: solo crecen y aplastarían lo demás.
          ASSET_STATUSES.filter((s) => s !== 'retired').map((s) => ({
            key: s,
            label: s,
          }));
    return {
      metric,
      bucket: 'day',
      approximate: false,
      since: first?.since ?? null,
      ignoredFilters: !!(scope.tags?.length || scope.types?.length),
      series,
      points: rows.map((r) => ({
        day: r.day,
        values: Object.fromEntries(
          series.map((s) => [s.key, r.values[s.key] ?? 0]),
        ),
      })),
    };
  }
}
