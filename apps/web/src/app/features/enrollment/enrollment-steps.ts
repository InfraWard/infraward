import type {
  EnrollmentJobProgress,
  EnrollmentPhase,
  JobName,
} from '@infraward/shared-types';
import type { TagSeverity } from '../../shared/labels';

/** Pasos del stepper (DESIGN §7). */
export const ENROLL_STEPS = [
  'Comando generado',
  'Esperando clave',
  'Conectando',
  'Escaneando',
  'Listo',
] as const;

/** Paso activo (1..5) según la fase; un fallo se queda en «Conectando». */
export function stepOf(phase: EnrollmentPhase): number {
  switch (phase) {
    case 'waiting':
      return 2;
    case 'connecting':
    case 'failed':
      return 3;
    case 'scanning':
      return 4;
    case 'ready':
      return 5;
    case 'cancelled':
      return 1;
  }
}

export const JOB_LABELS: Record<JobName, string> = {
  ping: 'Ping',
  'enrollment.verify': 'Verificación SSH',
  'asset.collect': 'Recolección',
  'asset.discover': 'Descubrimiento',
  'image.scan': 'Escaneo de imagen',
  'host.scan': 'SBOM del sistema',
  'sbom.reevaluate': 'Re-evaluación de SBOMs',
  'vulnerability.lookup': 'Consulta de un CVE',
  'inventory.reconcile': 'Reconciliación',
  'domains.test': 'Prueba de conector',
  'domains.sync': 'Sincronización de dominios',
  'services.link': 'Caminos de los dominios',
  'assets.bulk': 'Operación en lote',
  'vulnerability.intel': 'Descarga de KEV y EPSS',
  'findings.prioritize': 'Prioridad de las vulnerabilidades',
  'metrics.sample': 'Muestra diaria de métricas',
  'alert.deliver': 'Envío de una alerta',
  'alert.test': 'Prueba de un canal de alertas',
};

export const JOB_STATE_LABELS: Record<EnrollmentJobProgress['state'], string> =
  {
    waiting: 'En cola',
    delayed: 'En cola',
    prioritized: 'En cola',
    'waiting-children': 'En cola',
    active: 'En curso',
    completed: 'Hecho',
    failed: 'Falló',
    unknown: 'Caducado',
  };

export const JOB_STATE_SEVERITY: Record<
  EnrollmentJobProgress['state'],
  TagSeverity
> = {
  waiting: 'secondary',
  delayed: 'secondary',
  prioritized: 'secondary',
  'waiting-children': 'secondary',
  active: 'info',
  completed: 'success',
  failed: 'danger',
  unknown: 'secondary',
};

export interface JobGroup {
  name: JobName;
  label: string;
  total: number;
  done: number;
  failed: number;
  /** Job en curso del grupo con su último mensaje, si lo hay. */
  active: EnrollmentJobProgress | null;
}

/** Jobs agrupados por tipo para el paso «Escaneando»: «Recolección 2/3», etc. */
export function groupJobs(jobs: readonly EnrollmentJobProgress[]): JobGroup[] {
  const groups = new Map<JobName, JobGroup>();
  for (const job of jobs) {
    const g = groups.get(job.name) ?? {
      name: job.name,
      label: JOB_LABELS[job.name],
      total: 0,
      done: 0,
      failed: 0,
      active: null,
    };
    g.total++;
    if (job.state === 'completed' || job.state === 'unknown') g.done++;
    if (job.state === 'failed') g.failed++;
    if (job.state === 'active' && !g.active) g.active = job;
    groups.set(job.name, g);
  }
  return [...groups.values()];
}

/** Errores de los jobs encadenados (el alta sigue siendo válida, pero conviene verlos). */
export function chainFailures(
  jobs: readonly EnrollmentJobProgress[],
): string[] {
  return jobs
    .filter((j) => j.name !== 'enrollment.verify' && j.state === 'failed')
    .map((j) => `${JOB_LABELS[j.name]}: ${j.failedReason ?? 'falló'}`);
}
