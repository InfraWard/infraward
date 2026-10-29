import type {
  AssetCollectJobData,
  AssetCollectJobResult,
  AssetDiscoverJobData,
  AssetDiscoverJobResult,
} from './collection.js';
import type {
  EnrollmentVerifyJobData,
  EnrollmentVerifyJobResult,
} from './enrollment.js';
import type { AssetType } from './assets.js';
import type { BulkAssetAction } from './bulk.js';
import type {
  HostScanJobData,
  HostScanJobResult,
  ImageScanJobData,
  ImageScanJobResult,
  SbomReevaluateJobData,
  SbomReevaluateJobResult,
  VulnerabilityLookupJobData,
  VulnerabilityLookupJobResult,
} from './findings.js';
import type {
  DomainsSyncJobData,
  DomainsSyncJobResult,
  DomainsTestJobData,
  DomainsTestJobResult,
} from './domains.js';
import type {
  InventoryReconcileJobData,
  InventoryReconcileJobResult,
} from './inventory.js';
import type {
  FindingsPrioritizeJobData,
  FindingsPrioritizeJobResult,
  VulnerabilityIntelJobData,
  VulnerabilityIntelJobResult,
} from './priority.js';

/** Prefijo de las claves de BullMQ en Redis (API y worker deben usar el mismo). */
export const QUEUE_PREFIX = 'infraward';

/**
 * Colas de BullMQ: una por tipo de trabajo, cada una con su concurrencia en el worker (DESIGN
 * §20). `scan` es la cola anterior a la separación (sesión W-0): ya no se encola en ella; el
 * worker la sigue consumiendo para terminar lo que quedara al actualizar.
 */
export const QUEUE_NAMES = {
  system: 'system',
  enrollment: 'enrollment',
  collect: 'collect',
  discovery: 'discovery',
  domains: 'domains',
  reconcile: 'reconcile',
  imageScan: 'image-scan',
  hostScan: 'host-scan',
  sbom: 'sbom',
  scan: 'scan',
} as const;

export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

export const JOB_NAMES = {
  ping: 'ping',
  enrollmentVerify: 'enrollment.verify',
  assetCollect: 'asset.collect',
  assetDiscover: 'asset.discover',
  imageScan: 'image.scan',
  hostScan: 'host.scan',
  sbomReevaluate: 'sbom.reevaluate',
  vulnerabilityLookup: 'vulnerability.lookup',
  inventoryReconcile: 'inventory.reconcile',
  domainsTest: 'domains.test',
  domainsSync: 'domains.sync',
  servicesLink: 'services.link',
  assetsBulk: 'assets.bulk',
  vulnerabilityIntel: 'vulnerability.intel',
  findingsPrioritize: 'findings.prioritize',
  metricsSample: 'metrics.sample',
} as const;

/** Id fijo de `services.link`: como mucho uno en cola (no es un UUID: no sale en la Actividad). */
export const SERVICES_LINK_JOB_ID = 'services-link';

/** Recalcula los caminos de todos los registros DNS (QoL-5b). */
export interface ServicesLinkJobData {
  /** Qué lo pidió (para el log): `nat`, `pin`… */
  reason?: string;
}

export interface ServicesLinkJobResult {
  paths: number;
  complete: number;
  partial: number;
  servedBy: number;
  routesTo: number;
}

/** Job de prueba: recorre `steps` pasos esperando `stepDelayMs` en cada uno. */
export interface PingJobData {
  steps: number;
  stepDelayMs: number;
  message?: string;
}

export interface PingJobResult {
  pong: true;
  message?: string;
  steps: number;
  processedAt: string;
}

/** Contrato de cada job: cola en la que va, datos de entrada y resultado. */
export interface JobContracts {
  ping: {
    queue: typeof QUEUE_NAMES.system;
    data: PingJobData;
    result: PingJobResult;
  };
  /** Comprueba que el worker entra por SSH con la clave del alta y fija la host key. */
  'enrollment.verify': {
    queue: typeof QUEUE_NAMES.enrollment;
    data: EnrollmentVerifyJobData;
    result: EnrollmentVerifyJobResult;
  };
  /** Recoge un servidor con Ansible: facts, roles y snapshot (DESIGN §8). */
  'asset.collect': {
    queue: typeof QUEUE_NAMES.collect;
    data: AssetCollectJobData;
    result: AssetCollectJobResult;
  };
  /** Lista los hijos de un asset con su descubridor (Proxmox: CT y VMs) y los reconcilia. */
  'asset.discover': {
    queue: typeof QUEUE_NAMES.discovery;
    data: AssetDiscoverJobData;
    result: AssetDiscoverJobResult;
  };
  /** Escanea una imagen con Trivy (docker save desde un host) y sincroniza sus findings. */
  'image.scan': {
    queue: typeof QUEUE_NAMES.imageScan;
    data: ImageScanJobData;
    result: ImageScanJobResult;
  };
  /** SBOM de un servidor o CT (`trivy rootfs` sobre sus BDs de paquetes) y sus findings. */
  'host.scan': {
    queue: typeof QUEUE_NAMES.hostScan;
    data: HostScanJobData;
    result: HostScanJobResult;
  };
  /** Re-evalúa todos los SBOMs guardados con `trivy sbom`, sin conectarse a nada (DESIGN §9). */
  'sbom.reevaluate': {
    queue: typeof QUEUE_NAMES.sbom;
    data: SbomReevaluateJobData;
    result: SbomReevaluateJobResult;
  };
  /**
   * Detalles de un CVE en la BD de Trivy del worker (buscador de CVEs, DESIGN §9). Rápido y sin
   * historial: su id no es un UUID, así que no aparece en la Actividad.
   */
  'vulnerability.lookup': {
    queue: typeof QUEUE_NAMES.system;
    data: VulnerabilityLookupJobData;
    result: VulnerabilityLookupJobResult;
  };
  /** Encola la recolección de los nodos raíz con el intervalo vencido (DESIGN §10). */
  'inventory.reconcile': {
    queue: typeof QUEUE_NAMES.reconcile;
    data: InventoryReconcileJobData;
    result: InventoryReconcileJobResult;
  };
  /** Prueba el token de un conector de dominios (QoL-5); lo espera la API (`runQuick`). */
  'domains.test': {
    queue: typeof QUEUE_NAMES.domains;
    data: DomainsTestJobData;
    result: DomainsTestJobResult;
  };
  /**
   * Sincroniza un conector de dominios: zonas y registros, caducidad por RDAP, certificados del
   * 443, enlaces `resolves_to` y registros colgantes (DESIGN §13).
   */
  'domains.sync': {
    queue: typeof QUEUE_NAMES.domains;
    data: DomainsSyncJobData;
    result: DomainsSyncJobResult;
  };
  /** Caminos de los registros DNS hasta el asset que los sirve (QoL-5b, DESIGN §13). */
  'services.link': {
    queue: typeof QUEUE_NAMES.domains;
    data: ServicesLinkJobData;
    result: ServicesLinkJobResult;
  };
  /** Descarga CISA KEV y EPSS (con caché HTTP; un fallo conserva los datos, DESIGN §9). */
  'vulnerability.intel': {
    queue: typeof QUEUE_NAMES.system;
    data: VulnerabilityIntelJobData;
    result: VulnerabilityIntelJobResult;
  };
  /**
   * Prioridad, ruido y alertas de todos los findings (DESIGN §9). Id fijo
   * (`FINDINGS_PRIORITIZE_ID`): como mucho uno en cola, y no sale en la Actividad.
   */
  'findings.prioritize': {
    queue: typeof QUEUE_NAMES.system;
    data: FindingsPrioritizeJobData;
    result: FindingsPrioritizeJobResult;
  };
  /**
   * Muestra diaria de los gráficos de evolución (QoL-8): global y por proyecto, idempotente por
   * día, con su retención (DESIGN §15).
   */
  'metrics.sample': {
    queue: typeof QUEUE_NAMES.system;
    data: MetricsSampleJobData;
    result: MetricsSampleJobResult;
  };
  /** Solo historial (Actividad): nunca se encola. */
  'assets.bulk': {
    queue: typeof QUEUE_NAMES.system;
    data: AssetsBulkJobData;
    result: null;
  };
}

export type JobName = keyof JobContracts;
export type JobQueue<N extends JobName> = JobContracts[N]['queue'];
export type JobData<N extends JobName> = JobContracts[N]['data'];
export type JobResult<N extends JobName> = JobContracts[N]['result'];

/**
 * Operación en lote (QoL-6). **Nunca se encola**: la API graba su fila en `job_runs` ya
 * terminada para que se vea en la Actividad, y los jobs que lanza llevan su id de padre.
 */
export interface AssetsBulkJobData {
  action: BulkAssetAction;
  count: number;
}

/** Métricas de las muestras diarias (`metric_samples`). */
export const SAMPLE_METRICS = ['cves_by_band', 'assets_by_status'] as const;
export type SampleMetric = (typeof SAMPLE_METRICS)[number];

/** Id del job scheduler de las muestras y de su deduplicación (como mucho una en cola). */
export const METRICS_SAMPLE_ID = 'metrics-sample';

export interface MetricsSampleJobData {
  /** Qué lo pidió (`schedule`, `startup`). */
  reason?: string;
}

export interface MetricsSampleJobResult {
  /** Día de la muestra (`YYYY-MM-DD`, UTC). */
  day: string;
  /** Ámbitos muestreados: el global más uno por proyecto. */
  scopes: number;
  /** Muestras diarias pasadas a semanales y semanales borradas por la retención. */
  compacted: number;
  deleted: number;
}

/** Cola en la que se encola cada job. */
export const JOB_QUEUES: { [N in JobName]: JobQueue<N> } = {
  ping: QUEUE_NAMES.system,
  'enrollment.verify': QUEUE_NAMES.enrollment,
  'asset.collect': QUEUE_NAMES.collect,
  'asset.discover': QUEUE_NAMES.discovery,
  'image.scan': QUEUE_NAMES.imageScan,
  'host.scan': QUEUE_NAMES.hostScan,
  'sbom.reevaluate': QUEUE_NAMES.sbom,
  'vulnerability.lookup': QUEUE_NAMES.system,
  'inventory.reconcile': QUEUE_NAMES.reconcile,
  'domains.test': QUEUE_NAMES.domains,
  'domains.sync': QUEUE_NAMES.domains,
  'services.link': QUEUE_NAMES.domains,
  'assets.bulk': QUEUE_NAMES.system,
  'vulnerability.intel': QUEUE_NAMES.system,
  'findings.prioritize': QUEUE_NAMES.system,
  'metrics.sample': QUEUE_NAMES.system,
};

/** Colas en las que solo se encolaba antes de la sesión W-0 (se drenan, no se encola). */
export const LEGACY_QUEUES: readonly QueueName[] = [QUEUE_NAMES.scan];

/**
 * Prefijo de las claves de Redis con las que se coordinan las réplicas del worker (líder,
 * identidades, locks y semáforos por host; DESIGN §20). No hay ninguna cola llamada `workers`.
 */
export const WORKER_KEY_PREFIX = `${QUEUE_PREFIX}:workers:`;

/** Clave con el nombre de la réplica líder; la escribe el worker y la lee la API. */
export const WORKER_LEADER_KEY = `${WORKER_KEY_PREFIX}leader`;

/**
 * Ficha de cada réplica viva (`<prefijo>replica:<nombre>` = JSON de `WorkerReplicaInfo`), con la
 * misma caducidad que su nombre: la publica el worker y la lee la API (`GET /jobs/workers`).
 */
export const WORKER_REPLICA_KEY_PREFIX = `${WORKER_KEY_PREFIX}replica:`;

export interface WorkerReplicaInfo {
  name: string;
  host: string;
  queues: QueueName[];
  /** ISO 8601. */
  startedAt: string;
}

/** Una réplica del worker conectada a Redis (`GET /jobs/workers`). */
export interface WorkerReplica {
  /** Identificador estable (`worker-1`, o `WORKER_NAME`). */
  name: string;
  /** Colas que consume. */
  queues: QueueName[];
  /** Máquina (hostname) en la que corre. */
  host: string;
  /** Segundos desde que arrancó. */
  uptimeSeconds: number;
  /** Es el líder: programa los jobs periódicos, registra la Actividad y recupera huérfanos. */
  leader: boolean;
}

/** Evento de progreso que el worker registra en el log del job. */
export interface JobProgressEvent {
  /** Porcentaje 0-100. */
  progress: number;
  message: string;
  at: string;
}

export type JobState =
  | 'waiting'
  | 'active'
  | 'delayed'
  | 'prioritized'
  | 'waiting-children'
  | 'completed'
  | 'failed'
  | 'unknown';

export interface EnqueueJobResponse {
  id: string;
  name: JobName;
  queue: QueueName;
  /** Ya había uno igual pendiente o en curso: es ese. */
  deduplicated?: boolean;
}

export interface JobStatus<N extends JobName = JobName> {
  id: string;
  name: N;
  queue: QueueName;
  state: JobState;
  /** Porcentaje 0-100. */
  progress: number;
  events: JobProgressEvent[];
  result?: JobResult<N>;
  failedReason?: string;
  createdAt: string;
  finishedAt?: string;
}

// --- Historial de ejecuciones (tabla job_runs; BullMQ borra los jobs terminados) ---

/** Estado de una ejecución registrada. */
export const JOB_RUN_STATES = [
  'queued',
  'active',
  'completed',
  'failed',
] as const;
export type JobRunState = (typeof JOB_RUN_STATES)[number];

/** Filtro de estado de GET /jobs: `running` = en cola o en curso. */
export const JOB_RUN_STATE_FILTERS = [...JOB_RUN_STATES, 'running'] as const;
export type JobRunStateFilter = (typeof JOB_RUN_STATE_FILTERS)[number];

/** Una ejecución de un job, con el asset sobre el que trabaja. Sin sus datos ni su resultado. */
export interface JobRunSummary {
  id: string;
  name: JobName;
  queue: QueueName;
  /** null si no trabaja sobre un asset (ping) o si el asset se purgó. */
  assetId: string | null;
  /** Nombre del asset (el que tenía al encolarse si ya no existe). */
  assetName: string | null;
  assetType: AssetType | null;
  state: JobRunState;
  /** Porcentaje 0-100. */
  progress: number;
  /** Último mensaje de progreso. */
  message: string | null;
  /** Motivo del fallo (apto para mostrarse: sin secretos). */
  error: string | null;
  /** Job que lo encoló (cadenas: recolección → descubrimiento → …). */
  parentJobId: string | null;
  /** Réplica del worker que lo ejecuta o lo ejecutó por última vez (`worker-2`); null si no empezó. */
  worker: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  /** De inicio a fin (o hasta ahora si sigue en curso); null si no ha empezado. */
  durationMs: number | null;
  /**
   * Jobs que colgaron de este (los de una operación en lote, `assets.bulk`, o los encadenados):
   * cuántos, cuántos siguen en curso y cuántos fallaron. Solo si tiene alguno.
   */
  children?: { total: number; running: number; failed: number };
}

export interface JobRunListQuery {
  /** Del asset y, si es un contenedor, también de su imagen. */
  assetId?: string;
  /** Los que lanzó una operación en lote (o encadenó otro job). */
  parentJobId?: string;
  state?: JobRunStateFilter;
  name?: JobName;
  limit?: number;
  offset?: number;
}
