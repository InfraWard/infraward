import { Injectable } from '@nestjs/common';
import {
  ASSET_TYPES,
  ATTENTION_KINDS,
  type AssetType,
  type DashboardAttention,
  type DashboardSummary,
  type UserRole,
} from '@infraward/shared-types';
import { DashboardWidgetsService } from './dashboard-widgets.service.js';

const RECENT_ACTIVITY = 8;
const EMPTY: DashboardAttention = { count: 0, assets: [] };

/**
 * Resumen de una vez (`GET /dashboard`, el panel de antes de QoL-8): se conserva para los tokens
 * de API y se monta con las mismas funciones que los widgets (DESIGN §15).
 */
@Injectable()
export class DashboardService {
  constructor(private readonly widgets: DashboardWidgetsService) {}

  /** Con `projectId`, solo lo de ese proyecto (assets, vulnerabilidades, avisos y actividad). */
  async summary(
    projectId?: string,
    role?: UserRole,
  ): Promise<DashboardSummary> {
    const scope = { projectId };
    const [counts, top, byType, pending, attention, activity] =
      await Promise.all([
        this.widgets.vulnerabilityCounts(scope),
        this.widgets.topVulnerabilities(scope, 5, 'medium'),
        this.widgets.assetCounts(scope, 'type'),
        this.widgets.pendingEnrollment(scope, 0),
        this.widgets.attentionAll(scope, ATTENTION_KINDS, role),
        this.widgets.recentActivity(scope, RECENT_ACTIVITY, 'all'),
      ]);
    const assetsByType = Object.fromEntries(
      ASSET_TYPES.map((t) => [t, byType.counts[t] ?? 0]),
    ) as Record<AssetType, number>;
    const a = attention.attention;
    return {
      assetsByType,
      pendingEnrollment: pending.count,
      vulnerabilities: { ...counts, top: top.items },
      attention: {
        sudoersOutdated: a.sudoersOutdated ?? EMPTY,
        partialCollection: a.partialCollection ?? EMPTY,
        failedJobs: a.failedJobs ?? EMPTY,
        duplicates: a.duplicates ?? EMPTY,
        clones: a.clones ?? EMPTY,
        certificatesExpiring: a.certificatesExpiring ?? EMPTY,
        domainsExpiring: a.domainsExpiring ?? EMPTY,
        dnsDangling: a.dnsDangling ?? EMPTY,
        dnsUnknown: a.dnsUnknown ?? EMPTY,
        sshCaOutdated: a.sshCaOutdated ?? EMPTY,
        sshdPasswordLogin: a.sshdPasswordLogin ?? EMPTY,
      },
      vaultRotationOverdue: attention.vaultRotationOverdue,
      expiryWarningDays: attention.expiryWarningDays,
      runningJobs: activity.running,
      recentActivity: activity.items,
    };
  }
}
