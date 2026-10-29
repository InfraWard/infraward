// Prioridad de un finding con contexto (DESIGN §9, sesión 19). Función pura: la calcula el
// worker; la web, la API y la exportación usan los mismos textos.
import type { Severity } from './findings.js';
import type { JobRunState } from './jobs.js';

/** Bandas de prioridad, de menor a mayor. */
export const PRIORITY_BANDS = ['low', 'medium', 'high', 'urgent'] as const;
export type PriorityBand = (typeof PRIORITY_BANDS)[number];

/**
 * ÚNICO sitio con los pesos (un test fija cada uno). La puntuación va de 0 a 100: la base
 * (CVSS × 4, o la severidad si no hay CVSS) más los factores de contexto; una imagen sin uso
 * vale la mitad.
 */
export const PRIORITY_WEIGHTS = {
  /** Multiplicador del CVSS (0–10 ⇒ 0–40). */
  cvss: 4,
  /** CVSS supuesto por severidad cuando Trivy no da ninguno. */
  severityCvss: {
    CRITICAL: 9.5,
    HIGH: 7.5,
    MEDIUM: 5,
    LOW: 2.5,
    UNKNOWN: 4,
  } satisfies Record<Severity, number>,
  /** En el catálogo KEV de CISA (explotado activamente). */
  kev: 30,
  /** EPSS: umbrales de probabilidad de explotación en 30 días, de mayor a menor. */
  epss: [
    { min: 0.5, points: 15 },
    { min: 0.1, points: 10 },
    { min: 0.01, points: 4 },
  ],
  /** Hay versión corregida: se puede actuar ya. */
  fixAvailable: 5,
  /** El paquete es de un proceso en marcha (ejecutable o librería) o el contenedor está en marcha. */
  running: 5,
  /** Ese proceso escucha fuera de loopback o el contenedor publica puertos fuera de loopback. */
  exposedPort: 10,
  /** Un nombre público llega al asset (QoL-5b). */
  publicDomain: 10,
  /** Imagen sin ningún contenedor activo: multiplica. */
  unusedImageFactor: 0.5,
} as const;

/** Límites inferiores de cada banda (puntuación ≥). */
export const PRIORITY_BAND_MIN: Record<PriorityBand, number> = {
  low: 0,
  medium: 30,
  high: 50,
  urgent: 70,
};

export function priorityBand(score: number): PriorityBand {
  if (score >= PRIORITY_BAND_MIN.urgent) return 'urgent';
  if (score >= PRIORITY_BAND_MIN.high) return 'high';
  if (score >= PRIORITY_BAND_MIN.medium) return 'medium';
  return 'low';
}

/** Bandas iguales o más altas que `min`. */
export function bandsAtLeast(min: PriorityBand): PriorityBand[] {
  return PRIORITY_BANDS.slice(PRIORITY_BANDS.indexOf(min));
}

/**
 * Motivos por los que un finding sale de la vista principal y se guardan en el finding. Las
 * imágenes sin uso y el escaneo desactivado se calculan al consultar (no se guardan).
 */
export const NOISE_REASONS = ['kernel_not_running', 'no_fix_planned'] as const;
export type NoiseReason = (typeof NOISE_REASONS)[number];

/**
 * Todo lo que se oculta de la vista principal, con su recuento en la lista. Un finding cuenta en
 * el primero que lo oculta, en este orden.
 */
export const HIDDEN_REASONS = [
  'scan_disabled',
  'unused_image',
  'kernel_not_running',
  'no_fix_planned',
  'low_priority',
] as const;
export type HiddenReason = (typeof HIDDEN_REASONS)[number];

export const HIDDEN_REASON_LABELS: Record<HiddenReason, string> = {
  kernel_not_running: 'kernel no en uso',
  no_fix_planned: 'sin corrección prevista',
  unused_image: 'de imágenes sin uso',
  scan_disabled: 'con el escaneo desactivado',
  low_priority: 'de prioridad baja',
};

/**
 * Un motivo, con sus datos (nunca texto: el texto sale de `priorityReasonText`). Los de ruido
 * (`kernel_*`, `no_fix_planned`) no suman: explican por qué sale de la vista principal.
 */
export type PriorityReason =
  | { code: 'kev'; ransomware: boolean }
  | { code: 'epss'; epss: number }
  | {
      code: 'port';
      ports: number[];
      /** Proceso que escucha (en un servidor) o null en un contenedor. */
      process: string | null;
    }
  | { code: 'public'; domains: string[]; total: number }
  | {
      code: 'service';
      process: string;
      unit: string | null;
      /** `exe`: el paquete es el ejecutable; `lib`: una librería que tiene cargada. */
      via: 'exe' | 'lib';
    }
  | { code: 'container'; running: number }
  | { code: 'fix' }
  | { code: 'no_fix' }
  | { code: 'cvss'; score: number }
  | { code: 'severity'; severity: Severity }
  | { code: 'unused_image' }
  | { code: 'no_process_data' }
  | { code: 'kernel_other'; running: string }
  | { code: 'kernel_aux' }
  | { code: 'kernel_guest'; assetType: 'lxc' | 'image' }
  | { code: 'no_fix_planned'; fixStatus: 'will_not_fix' | 'fix_deferred' };
export type PriorityReasonCode = PriorityReason['code'];

/** Contexto de un finding para puntuarlo. */
export interface PriorityInput {
  severity: Severity;
  /** CVSS de Trivy (NVD primero); null si no hay. */
  cvss: number | null;
  /** En KEV (con ransomware conocido o no); null si no. */
  kev: { ransomware: boolean } | null;
  /** EPSS (0–1); null si no hay dato. */
  epss: number | null;
  fixable: boolean;
  /** Proceso en marcha al que pertenece el paquete (sudoers v6); null si ninguno o sin datos. */
  service: { process: string; unit: string | null; via: 'exe' | 'lib' } | null;
  /** Puertos expuestos (fuera de loopback) de ese proceso o publicados por el contenedor. */
  exposedPorts: number[];
  /** Contenedores en marcha que usan la imagen (solo imágenes). */
  runningContainers: number;
  /** Nombres públicos que llegan al asset (QoL-5b). */
  publicDomains: { domains: string[]; total: number } | null;
  unusedImage: boolean;
  /** false en un servidor o CT sin datos de procesos (sudoers anterior a la v6). */
  processData: boolean;
  /** Motivos de ruido ya decididos (se ponen delante y no suman). */
  noise?: PriorityReason[];
}

export interface PriorityResult {
  score: number;
  band: PriorityBand;
  /** Motivos en orden de peso: primero el ruido, luego lo que más suma. */
  reasons: PriorityReason[];
}

function epssPoints(epss: number | null): number {
  if (epss == null) return 0;
  return PRIORITY_WEIGHTS.epss.find((t) => epss >= t.min)?.points ?? 0;
}

/** Puntuación y motivos de un finding. */
export function scoreFinding(input: PriorityInput): PriorityResult {
  const w = PRIORITY_WEIGHTS;
  const base = (input.cvss ?? w.severityCvss[input.severity]) * w.cvss;
  // [puntos, motivo]: se ordenan por lo que suman (estable ante empates).
  const factors: [number, PriorityReason][] = [];
  if (input.kev)
    factors.push([w.kev, { code: 'kev', ransomware: input.kev.ransomware }]);
  if (input.exposedPorts.length)
    factors.push([
      w.exposedPort,
      {
        code: 'port',
        ports: [...new Set(input.exposedPorts)].sort((a, b) => a - b),
        process: input.service?.process ?? null,
      },
    ]);
  if (input.publicDomains)
    factors.push([w.publicDomain, { code: 'public', ...input.publicDomains }]);
  const epss = epssPoints(input.epss);
  if (epss) factors.push([epss, { code: 'epss', epss: input.epss ?? 0 }]);
  if (input.service)
    factors.push([w.running, { code: 'service', ...input.service }]);
  else if (input.runningContainers > 0)
    factors.push([
      w.running,
      { code: 'container', running: input.runningContainers },
    ]);
  factors.push(
    input.fixable ? [w.fixAvailable, { code: 'fix' }] : [0, { code: 'no_fix' }],
  );

  let score = base + factors.reduce((sum, [points]) => sum + points, 0);
  if (input.unusedImage) score *= w.unusedImageFactor;
  score = Math.max(0, Math.min(100, Math.round(score)));

  const reasons: PriorityReason[] = [
    ...(input.noise ?? []),
    ...factors
      .map((f, i) => [f, i] as const)
      .sort(([a, i], [b, j]) => b[0] - a[0] || i - j)
      .map(([[, reason]]) => reason),
    input.cvss != null
      ? { code: 'cvss', score: input.cvss }
      : { code: 'severity', severity: input.severity },
  ];
  if (input.unusedImage) reasons.push({ code: 'unused_image' });
  if (!input.processData) reasons.push({ code: 'no_process_data' });
  return { score, band: priorityBand(score), reasons };
}

const plural = (n: number, one: string, many: string) =>
  `${n} ${n === 1 ? one : many}`;

function percent(value: number): string {
  const pct = value * 100;
  if (pct < 1) return '<1 %';
  return `${Math.round(pct)} %`;
}

/** Texto de un motivo, en español. */
export function priorityReasonText(reason: PriorityReason): string {
  switch (reason.code) {
    case 'kev':
      return reason.ransomware ? 'en KEV (usado por ransomware)' : 'en KEV';
    case 'epss':
      return `EPSS ${percent(reason.epss)}`;
    case 'port': {
      const ports = reason.ports.slice(0, 4).join(', ');
      const more =
        reason.ports.length > 4 ? ` y ${reason.ports.length - 4} más` : '';
      return `expuesto en ${ports}${more}${reason.process ? ` (${reason.process})` : ''}`;
    }
    case 'public': {
      const more = reason.total - reason.domains.length;
      return `dominio público: ${reason.domains.join(', ')}${more > 0 ? ` y ${more} más` : ''}`;
    }
    case 'service':
      return reason.via === 'exe'
        ? `${reason.process} en marcha`
        : `cargado por ${reason.process}`;
    case 'container':
      return plural(
        reason.running,
        'contenedor en marcha',
        'contenedores en marcha',
      );
    case 'fix':
      return 'parche disponible';
    case 'no_fix':
      return 'sin parche aún';
    case 'cvss':
      return `CVSS ${reason.score.toLocaleString('es-ES', { minimumFractionDigits: 1, maximumFractionDigits: 1 })}`;
    case 'severity':
      return `severidad ${reason.severity} (sin CVSS)`;
    case 'unused_image':
      return 'imagen sin uso';
    case 'no_process_data':
      return 'sin datos de procesos (sudoers v6)';
    case 'kernel_other':
      return `kernel no en uso (en ejecución: ${reason.running})`;
    case 'kernel_aux':
      return 'kernel no en uso (cabeceras o herramientas, no el kernel en ejecución)';
    case 'kernel_guest':
      return reason.assetType === 'lxc'
        ? 'kernel no en uso (un CT usa el kernel del nodo)'
        : 'kernel no en uso (un contenedor usa el kernel del host)';
    case 'no_fix_planned':
      return reason.fixStatus === 'will_not_fix'
        ? 'sin corrección prevista (la distribución no lo corregirá)'
        : 'sin corrección prevista (corrección aplazada)';
  }
}

/** Motivos de ruido (no suman: explican por qué sale de la vista principal). */
export const NOISE_REASON_CODES: readonly PriorityReasonCode[] = [
  'kernel_other',
  'kernel_aux',
  'kernel_guest',
  'no_fix_planned',
];

/** «en KEV · expuesto en 443 (nginx) · parche disponible»: los `max` primeros motivos. */
export function priorityExplanation(
  reasons: readonly PriorityReason[],
  max = 4,
): string {
  return reasons.slice(0, max).map(priorityReasonText).join(' · ');
}

export const PRIORITY_BAND_LABELS: Record<PriorityBand, string> = {
  urgent: 'Urgente',
  high: 'Alta',
  medium: 'Media',
  low: 'Baja',
};

// --- Inteligencia de vulnerabilidades: CISA KEV y EPSS de FIRST ---

export const INTEL_SOURCES = ['kev', 'epss'] as const;
export type IntelSource = (typeof INTEL_SOURCES)[number];

/** Estado de una fuente (`GET /vulnerabilities/intel`). */
export interface IntelFeedStatus {
  source: IntelSource;
  /** false si su URL está vacía (entorno sin salida o desactivada). */
  enabled: boolean;
  /** Cuándo se cargaron los datos vigentes (null = nunca). */
  fetchedAt: string | null;
  /** Última comprobación correcta (un 304 o la misma versión también cuentan). */
  checkedAt: string | null;
  /** `catalogVersion` de KEV o fecha de las puntuaciones de EPSS. */
  version: string | null;
  recordCount: number | null;
  /** Último fallo (los datos anteriores se conservan). */
  lastError: string | null;
  lastErrorAt: string | null;
  /** Datos de hace más de `INTEL_STALE_DAYS` días o sin datos. */
  stale: boolean;
}

/**
 * BD de vulnerabilidades de Trivy, vista desde lo evaluado (la API no toca la caché del worker):
 * la fecha de la BD con la que se evaluaron los SBOMs y la última re-evaluación.
 */
export interface TrivyDbStatus {
  /** Fecha (de Trivy) de la BD más reciente con la que se ha evaluado algún SBOM. */
  dbUpdatedAt: string | null;
  /** Última evaluación de un SBOM (escaneo o re-evaluación). */
  evaluatedAt: string | null;
  /** SBOMs guardados de assets no retirados. */
  sboms: number;
  /** Última re-evaluación de todos los SBOMs (`sbom.reevaluate`), o null si no hay en el historial. */
  lastRun: {
    jobId: string;
    state: JobRunState;
    /** Resumen («12 de 12 SBOMs evaluados: 3 findings nuevos y 1 corregido») o progreso. */
    message: string | null;
    error: string | null;
    finishedAt: string | null;
  } | null;
  /** BD de hace más de `TRIVY_STALE_DAYS` días (o sin ninguna). */
  stale: boolean;
}

/** A partir de cuántos días se avisa de que la BD de Trivy está desactualizada. */
export const TRIVY_STALE_DAYS = 2;

export interface IntelStatus {
  feeds: IntelFeedStatus[];
  trivy: TrivyDbStatus;
}

/** A partir de cuántos días se avisa de que los datos están desactualizados. */
export const INTEL_STALE_DAYS = 3;

export interface KevEntry {
  /** `dateAdded` (AAAA-MM-DD). */
  added: string | null;
  /** `dueDate` de CISA. */
  due: string | null;
  ransomware: boolean;
  name: string | null;
}

export interface EpssScore {
  /** 0–1. */
  score: number;
  /** 0–1. */
  percentile: number | null;
}

/** KEV y EPSS de un CVE (null = no está en KEV / sin puntuación). */
export interface VulnerabilityEnrichment {
  kev: KevEntry | null;
  epss: EpssScore | null;
}

/** Datos del job `vulnerability.intel`. */
export interface VulnerabilityIntelJobData {
  /** Descargar aunque no haya pasado el intervalo (manual). */
  force?: boolean;
}

export interface VulnerabilityIntelFeedResult {
  source: IntelSource;
  outcome: 'updated' | 'not_modified' | 'unchanged' | 'disabled' | 'failed';
  records?: number;
  error?: string;
}

export interface VulnerabilityIntelJobResult {
  feeds: VulnerabilityIntelFeedResult[];
}

export const VULNERABILITY_INTEL_ID = 'vulnerability-intel';

/** Datos del job `findings.prioritize` (siempre todo: es una pasada barata y deduplicada). */
export type FindingsPrioritizeJobData = Record<string, never>;

export interface FindingsPrioritizeJobResult {
  findings: number;
  updated: number;
  alerts: number;
}

export const FINDINGS_PRIORITIZE_ID = 'findings-prioritize';

/** Prioridad de un finding o de un CVE (la de su finding más prioritario). */
export interface PriorityInfo {
  score: number;
  band: PriorityBand;
  reasons: PriorityReason[];
}

/** Banda de una puntuación guardada (null = aún sin calcular). */
export function priorityInfo(
  score: number | null,
  reasons: PriorityReason[] | null,
): PriorityInfo | null {
  return score == null
    ? null
    : { score, band: priorityBand(score), reasons: reasons ?? [] };
}
