// Panel de inicio (GET /dashboard).
import type { AssetSummary, AssetType } from './assets.js';
import type { Severity } from './findings.js';
import type { JobRunSummary } from './jobs.js';
import type { PriorityInfo } from './priority.js';

/** Un aviso del panel: cuántos assets lo tienen y los primeros. */
export interface DashboardAttention {
  count: number;
  /** Como mucho 5. */
  assets: AssetSummary[];
}


/** Un CVE del panel con su prioridad y sus motivos. */
export interface DashboardVulnerability {
  vulnerabilityId: string;
  severity: Severity;
  priority: PriorityInfo;
  kev: boolean;
  /** Assets afectados (servidores, CT e imágenes). */
  assets: number;
}

export interface DashboardSummary {
  /** Assets no retirados por tipo. */
  assetsByType: Record<AssetType, number>;
  /** Servidores pendientes de alta. */
  pendingEnrollment: number;
  /**
   * Lo prioritario de la vista principal de Vulnerabilidades (abiertas, sin ruido ni imágenes sin
   * uso, DESIGN §9): CVE por banda de prioridad, cuántos están en KEV y los primeros.
   */
  vulnerabilities: {
    urgent: number;
    high: number;
    medium: number;
    /** CVE de la vista en el catálogo KEV. */
    kev: number;
    /** CVE distintos de la vista (prioridad ≥ media). */
    cves: number;
    /** Los 5 más prioritarios, con su porqué. */
    top: DashboardVulnerability[];
  };
  attention: {
    sudoersOutdated: DashboardAttention;
    partialCollection: DashboardAttention;
    /** Assets cuya última ejecución falló en las últimas 24 h. */
    failedJobs: DashboardAttention;
    /** Servidores cuyo machine-id ya es de otro asset (la misma máquina dos veces). */
    duplicates: DashboardAttention;
    /** Servidores clonados que comparten machine-id con otros (hay que regenerarlo). */
    clones: DashboardAttention;
    /** Certificados caducados o que caducan antes del umbral mayor (`expiryWarningDays`). */
    certificatesExpiring: DashboardAttention;
    /** Dominios caducados o que caducan antes del umbral mayor (RDAP). */
    domainsExpiring: DashboardAttention;
    /** Registros DNS colgantes de prioridad alta sin marcar como esperados. */
    dnsDangling: DashboardAttention;
    /** Registros DNS a IPs públicas desconocidas sin marcar como esperados (informativo). */
    dnsUnknown: DashboardAttention;
    /** Servidores en modo CA que no confían exactamente en las CA vigentes. */
    sshCaOutdated: DashboardAttention;
    /** Servidores cuyo sshd admite el login de root o por contraseña (`sshd -T`, v7). */
    sshdPasswordLogin: DashboardAttention;
  };
  /**
   * Credenciales de la caja fuerte con la rotación vencida (solo con `vault.manage`; null si no
   * se tiene el permiso o la caja fuerte no está configurada).
   */
  vaultRotationOverdue: number | null;
  /** Umbrales de aviso de caducidad (días, de mayor a menor). */
  expiryWarningDays: number[];
  /** Jobs en cola o en curso. */
  runningJobs: number;
  recentActivity: JobRunSummary[];
}

export interface DashboardQuery {
  /** Solo lo de este proyecto (assets, vulnerabilidades, avisos y actividad). */
  projectId?: string;
}
