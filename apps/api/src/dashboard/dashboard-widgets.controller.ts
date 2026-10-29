import { Controller, Get, Query, Res } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiBadRequestResponse,
  ApiCookieAuth,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  ATTENTION_KINDS,
  DASHBOARD_WIDGETS,
  hasPermission,
  type AssetCountsData,
  type AttentionData,
  type ExpirationsData,
  type FixableVulnerabilitiesData,
  type NewVulnerabilitiesData,
  type PendingEnrollmentData,
  type RecentActivityData,
  type RunningJobsData,
  type TopVulnerabilitiesData,
  type TrendData,
  type VulnerabilityCountsData,
  type WidgetType,
} from '@infraward/shared-types';
import type { FastifyReply } from 'fastify';
import type { AuthenticatedUser } from '../auth/authenticated-user.js';
import { CurrentUser } from '../auth/current-user.decorator.js';
import { TtlCache } from '../common/ttl-cache.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import {
  AssetCountsDataDto,
  AssetCountsQueryDto,
  AttentionDataDto,
  AttentionQueryDto,
  ExpirationsDataDto,
  ExpirationsQueryDto,
  FixableVulnerabilitiesDataDto,
  NewVulnerabilitiesDataDto,
  NewVulnerabilitiesQueryDto,
  PendingEnrollmentDataDto,
  PendingEnrollmentQueryDto,
  RecentActivityDataDto,
  RecentActivityQueryDto,
  RunningJobsDataDto,
  TopVulnerabilitiesDataDto,
  TopVulnerabilitiesQueryDto,
  TrendDataDto,
  TrendQueryDto,
  VulnerabilityCountsDataDto,
  WidgetScopeQueryDto,
} from './dashboard-widgets.dto.js';
import { DashboardWidgetsService } from './dashboard-widgets.service.js';
import { scopeKey, type WidgetScope } from './widget-scope.js';

/** Entradas como mucho en la caché (cada una, el resultado de un widget con sus filtros). */
const CACHE_ENTRIES = 1000;
const DAY_MS = 86_400_000;

function scopeOf(q: WidgetScopeQueryDto): WidgetScope {
  return { projectId: q.projectId?.toLowerCase(), tags: q.tag, types: q.type };
}

/**
 * Datos de cada widget del panel (QoL-8, DESIGN §15): una petición por widget, solo con lo suyo.
 * Caché corta en memoria por tipo y filtros (`DASHBOARD_CACHE_TTL`; 5 s los de tareas), con lo
 * que depende del usuario en la clave (si ve la caja fuerte, su última visita).
 */
@ApiTags('dashboard')
@ApiCookieAuth()
@ApiUnauthorizedResponse()
@ApiBadRequestResponse()
@Controller('dashboard/widgets')
export class DashboardWidgetsController {
  private readonly cache = new TtlCache<unknown>(CACHE_ENTRIES);
  private readonly defaultTtl: number;

  constructor(
    private readonly widgets: DashboardWidgetsService,
    config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.defaultTtl = config.get('DASHBOARD_CACHE_TTL', { infer: true });
  }

  private cached<T>(
    type: WidgetType,
    key: unknown[],
    reply: FastifyReply,
    load: () => Promise<T>,
  ): Promise<T> {
    const ttl = DASHBOARD_WIDGETS[type].ttl ?? this.defaultTtl;
    reply.header(
      'Cache-Control',
      ttl > 0 ? `private, max-age=${ttl}` : 'no-store',
    );
    return this.cache.get(
      JSON.stringify([type, ...key]),
      ttl * 1000,
      load,
    ) as Promise<T>;
  }

  /** Total de assets (sin retirados) y por tipo, como la tarjeta de un proyecto. */
  @Get('asset-summary')
  @ApiOkResponse({ type: AssetCountsDataDto })
  assetSummary(
    @Query() q: WidgetScopeQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<AssetCountsData> {
    const scope = scopeOf(q);
    return this.cached('asset-summary', [scopeKey(scope)], reply, () =>
      this.widgets.assetCounts(scope, 'type'),
    );
  }

  /** Críticos y altos con parche, CVE abiertos y hallazgos por severidad. */
  @Get('fixable-vulnerabilities')
  @ApiOkResponse({ type: FixableVulnerabilitiesDataDto })
  fixableVulnerabilities(
    @Query() q: WidgetScopeQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<FixableVulnerabilitiesData> {
    const scope = scopeOf(q);
    return this.cached(
      'fixable-vulnerabilities',
      [scopeKey(scope)],
      reply,
      () => this.widgets.fixableVulnerabilities(scope),
    );
  }

  /** CVE de la vista principal por banda de prioridad y cuántos en KEV. */
  @Get('vulnerability-counts')
  @ApiOkResponse({ type: VulnerabilityCountsDataDto })
  vulnerabilityCounts(
    @Query() q: WidgetScopeQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<VulnerabilityCountsData> {
    const scope = scopeOf(q);
    return this.cached('vulnerability-counts', [scopeKey(scope)], reply, () =>
      this.widgets.vulnerabilityCounts(scope),
    );
  }

  /** Assets por tipo (sin retirados) o por estado. */
  @Get('asset-counts')
  @ApiOkResponse({ type: AssetCountsDataDto })
  assetCounts(
    @Query() q: AssetCountsQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<AssetCountsData> {
    const scope = scopeOf(q);
    const groupBy = q.groupBy ?? 'type';
    return this.cached('asset-counts', [scopeKey(scope), groupBy], reply, () =>
      this.widgets.assetCounts(scope, groupBy),
    );
  }

  @Get('pending-enrollment')
  @ApiOkResponse({ type: PendingEnrollmentDataDto })
  pendingEnrollment(
    @Query() q: PendingEnrollmentQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<PendingEnrollmentData> {
    const scope = scopeOf(q);
    const limit = Number(q.limit ?? 0);
    return this.cached(
      'pending-enrollment',
      [scopeKey(scope), limit],
      reply,
      () => this.widgets.pendingEnrollment(scope, limit),
    );
  }

  @Get('running-jobs')
  @ApiOkResponse({ type: RunningJobsDataDto })
  runningJobs(
    @Query() q: WidgetScopeQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<RunningJobsData> {
    const scope = scopeOf(q);
    return this.cached('running-jobs', [scopeKey(scope)], reply, () =>
      this.widgets.runningJobs(scope),
    );
  }

  /** Los CVE más prioritarios con su porqué. */
  @Get('top-vulnerabilities')
  @ApiOkResponse({ type: TopVulnerabilitiesDataDto })
  topVulnerabilities(
    @Query() q: TopVulnerabilitiesQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<TopVulnerabilitiesData> {
    const scope = scopeOf(q);
    const limit = Number(q.limit ?? 5);
    const min = q.minPriority ?? 'medium';
    return this.cached(
      'top-vulnerabilities',
      [scopeKey(scope), limit, min],
      reply,
      () => this.widgets.topVulnerabilities(scope, limit, min),
    );
  }

  /** CVE nuevos desde la última visita del usuario o en los últimos 7 o 30 días. */
  @Get('new-vulnerabilities')
  @ApiOkResponse({ type: NewVulnerabilitiesDataDto })
  async newVulnerabilities(
    @Query() q: NewVulnerabilitiesQueryDto,
    @CurrentUser() user: AuthenticatedUser,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<NewVulnerabilitiesData> {
    const scope = scopeOf(q);
    const limit = Number(q.limit ?? 5);
    const since =
      (q.since ?? 'lastVisit') === 'lastVisit'
        ? await this.widgets.seenAt(user.id)
        : // Al día: la clave de la caché no cambia en cada petición.
          new Date(
            Math.floor(Date.now() / DAY_MS) * DAY_MS -
              (q.since === '7d' ? 7 : 30) * DAY_MS,
          );
    return this.cached(
      'new-vulnerabilities',
      [scopeKey(scope), limit, since.toISOString()],
      reply,
      () => this.widgets.newVulnerabilities(scope, since, limit),
    );
  }

  /** Avisos con los primeros assets (las credenciales sin rotar, solo con `vault.manage`). */
  @Get('attention')
  @ApiOkResponse({ type: AttentionDataDto })
  attention(
    @Query() q: AttentionQueryDto,
    @CurrentUser() user: AuthenticatedUser,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<AttentionData> {
    const scope = scopeOf(q);
    const kinds = ATTENTION_KINDS.filter(
      (k) => !q.kinds || q.kinds.includes(k),
    );
    const vault = hasPermission(user.role, 'vault.manage');
    return this.cached(
      'attention',
      [scopeKey(scope), kinds, vault],
      reply,
      () => this.widgets.attention(scope, kinds, user.role),
    );
  }

  /** Dominios y certificados que caducan, los más próximos primero. */
  @Get('expirations')
  @ApiOkResponse({ type: ExpirationsDataDto })
  expirations(
    @Query() q: ExpirationsQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<ExpirationsData> {
    const scope = scopeOf(q);
    const kinds = (['domain', 'certificate'] as const).filter(
      (k) => !q.kinds || q.kinds.includes(k),
    );
    const horizon = q.horizonDays ?? null;
    const limit = Number(q.limit ?? 10);
    return this.cached(
      'expirations',
      [scopeKey(scope), kinds, horizon, limit],
      reply,
      () => this.widgets.expirations(scope, kinds, horizon, limit),
    );
  }

  @Get('recent-activity')
  @ApiOkResponse({ type: RecentActivityDataDto })
  recentActivity(
    @Query() q: RecentActivityQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<RecentActivityData> {
    const scope = scopeOf(q);
    const limit = Number(q.limit ?? 8);
    const state = q.state ?? 'all';
    return this.cached(
      'recent-activity',
      [scopeKey(scope), limit, state],
      reply,
      () => this.widgets.recentActivity(scope, limit, state),
    );
  }

  /** Gráfico de evolución: reconstruido de los findings (aproximado) o de las muestras diarias. */
  @Get('trend')
  @ApiOkResponse({ type: TrendDataDto })
  trend(
    @Query() q: TrendQueryDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<TrendData> {
    const scope = scopeOf(q);
    const metric = q.metric ?? 'open-findings';
    const range = q.range ?? '90d';
    return this.cached('trend', [scopeKey(scope), metric, range], reply, () =>
      this.widgets.trend(scope, metric, range),
    );
  }
}
