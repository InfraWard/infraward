// Escaneo de imágenes con Trivy y findings (DESIGN §9).
import type { PublicExposure } from './service-paths.js';
import type {
  AssetRuntimeState,
  AssetStatus,
  AssetType,
} from './assets.js';
import type { EnqueueJobResponse } from './jobs.js';
import type {
  HiddenReason,
  NoiseReason,
  PriorityBand,
  PriorityInfo,
  VulnerabilityEnrichment,
} from './priority.js';

/** Severidades de Trivy, de menor a mayor. */
export const SEVERITIES = [
  'UNKNOWN',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Severidades iguales o más graves que `min`. */
export function severitiesAtLeast(min: Severity): Severity[] {
  return SEVERITIES.slice(SEVERITIES.indexOf(min));
}

/**
 * Estado de un finding (de una imagen o, en el futuro, de un servidor): `open` mientras el último
 * escaneo lo vea, `fixed` cuando un escaneo deja de verlo y `accepted` si se acepta el riesgo
 * (para todos los contenedores de la imagen).
 */
export const FINDING_STATUSES = ['open', 'fixed', 'accepted'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

/** Longitud del motivo al aceptar el riesgo (obligatorio: queda en la auditoría). */
export const FINDING_ACCEPT_REASON_MIN = 10;
export const FINDING_ACCEPT_REASON_MAX = 1000;
/** Caducidad máxima de una aceptación (días); sin fecha, no caduca. */
export const FINDING_ACCEPT_MAX_DAYS = 365;
/** Findings que se aceptan o reabren como mucho en una operación. */
export const FINDING_ACCEPT_MAX = 5000;

/**
 * Riesgo aceptado de un finding: quién, cuándo, por qué y hasta cuándo. Se conserva al reabrirlo
 * (historial de la última aceptación); solo describe el estado actual si `status = 'accepted'`.
 */
export interface FindingAcceptance {
  /** Email de quien lo aceptó (null si fue una API sin usuario). */
  by: string | null;
  at: string;
  reason: string;
  /** Al llegar, el worker lo reabre (`open`); null: no caduca. */
  expiresAt: string | null;
}

/**
 * Aceptar el riesgo: por findings o por CVE (todos los findings abiertos de esos CVE, como la
 * acción en lote de la lista; con `projectId`, solo los de assets del proyecto).
 */
export interface AcceptFindingsRequest {
  findingIds?: string[];
  vulnerabilityIds?: string[];
  projectId?: string;
  reason: string;
  /** ISO; futura y como mucho a `FINDING_ACCEPT_MAX_DAYS`. Sin ella, no caduca. */
  expiresAt?: string | null;
}

/** Reabrir findings aceptados: por findings o por CVE. */
export interface ReopenFindingsRequest {
  findingIds?: string[];
  vulnerabilityIds?: string[];
  projectId?: string;
}

export interface FindingAcceptanceResult {
  /** Findings que cambiaron de estado. */
  updated: number;
  /** CVE distintos de esos findings. */
  vulnerabilities: number;
}

/**
 * Estado del escaneo de una imagen: `skipped` = no escaneada por un motivo conocido (tamaño,
 * tiempo, sudoers desactualizado…), no es un fallo; `failed` = error al escanear.
 */
export const IMAGE_SCAN_STATUSES = [
  'pending',
  'scanned',
  'skipped',
  'failed',
] as const;
export type ImageScanStatus = (typeof IMAGE_SCAN_STATUSES)[number];

/** De dónde sale la imagen que analiza Trivy (DESIGN §9). */
export type ImageScanSource = 'docker_save';

/** Vulnerabilidad de una imagen, normalizada desde el JSON de Trivy. */
export interface ImageVulnerability {
  /** CVE, GHSA… */
  vulnerabilityId: string;
  packageName: string;
  installedVersion: string;
  /** null si no hay versión corregida. */
  fixedVersion: string | null;
  severity: Severity;
  title: string | null;
  /** Estado según la distribución (`fixed`, `affected`, `will_not_fix`…). */
  fixStatus: string | null;
  /** `os-pkgs` o `lang-pkgs`. */
  class: string | null;
  /** Gestor (`debian`, `npm`, `jar`…). */
  pkgType: string | null;
  /** Ruta del paquete en la imagen (lang-pkgs). */
  pkgPath: string | null;
  purl: string | null;
  primaryUrl: string | null;
  /** CVSS (NVD primero; V3, si no V4 o V2). null si Trivy no da ninguno. */
  cvss: number | null;
  /** Identidad estable dentro de la imagen: sha256(vuln|paquete|versión|clase|tipo|ruta). */
  fingerprint: string;
}

/** Imagen de contenedor identificada por su image ID y su último escaneo. */
export interface ContainerImageSummary {
  /** Asset `image` de la imagen (de él cuelgan sus findings). */
  assetId: string;
  imageId: string;
  repoDigests: string[];
  repoTags: string[];
  platform: string | null;
  scanStatus: ImageScanStatus;
  /** Motivo de `skipped`/`failed`. */
  scanReason: string | null;
  scannedAt: string | null;
  scanSource: ImageScanSource | null;
  trivyVersion: string | null;
  /** Fecha de la BD de vulnerabilidades de Trivy con la que se escaneó. */
  dbUpdatedAt: string | null;
  /** Vulnerabilidades del último escaneo (null si nunca se escaneó). */
  vulnerabilityCount: number | null;
}

/** Asset afectado por un finding: el propio asset o, si es una imagen, cada contenedor que la usa. */
export interface AffectedAsset {
  id: string;
  name: string;
  type: AssetType;
  status: AssetStatus;
  /** Padre `contains` (el host Docker de un contenedor), para situarlo en el árbol. */
  parentId: string | null;
}

export interface Finding {
  id: string;
  /** Asset en el que se detectó: la imagen (asset `image`) en los contenedores. */
  assetId: string;
  vulnerabilityId: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  title: string | null;
  fixStatus: string | null;
  pkgPath: string | null;
  primaryUrl: string | null;
  status: FindingStatus;
  firstSeenAt: string;
  lastSeenAt: string;
  fixedAt: string | null;
  /** CVSS de Trivy (null si no lo da). */
  cvss: number | null;
  /** Prioridad con contexto (DESIGN §9); null hasta que el worker la calcula. */
  priority: PriorityInfo | null;
  /** Por qué sale de la vista principal (kernel no en uso, sin corrección prevista). */
  noiseReason: NoiseReason | null;
  /** La última aceptación del riesgo (vigente si `status = 'accepted'`). */
  acceptance: FindingAcceptance | null;
}

/** Finding de la búsqueda global, con los assets a los que afecta. */
export interface FindingSearchResult extends Finding {
  /** Asset en el que se detectó (la imagen, en los contenedores). */
  owner: AffectedAsset;
  affected: AffectedAsset[];
}

export interface FindingListQuery {
  status?: FindingStatus;
  severity?: Severity;
  /** Severidad mínima (esta y las más graves). */
  minSeverity?: Severity;
  /** true: solo los que tienen versión corregida (hay parche). */
  fixable?: boolean;
  /**
   * true: sin los de imágenes «sin uso» (ningún contenedor activo las usa), que tienen prioridad
   * baja. El criterio «accionable» de la web (y el panel) lo usa.
   */
  inUse?: boolean;
  /** CVE exacto (sin distinguir mayúsculas). */
  vulnerabilityId?: string;
  /** Búsqueda libre: CVE que empiece por el texto o paquete que lo contenga. */
  q?: string;
  /** Solo los abiertos desde esta fecha (ISO): aparecidos o reabiertos después. */
  openedSince?: string;
  /**
   * `public`: solo los de assets que sirven o dejan pasar un nombre público (QoL-5b); `any`:
   * expuestos de cualquier forma (puerto fuera de loopback, contenedor publicado o nombre público).
   */
  exposure?: 'public' | 'any';
  /** Prioridad mínima (esta banda y las más altas). */
  minPriority?: PriorityBand;
  /** true: solo los CVE del catálogo KEV de CISA. */
  kev?: boolean;
  /** EPSS mínimo (0–1). */
  minEpss?: number;
  /**
   * true: también el ruido (kernel no en uso, sin corrección prevista), que por defecto sale de las
   * listas globales. La lista de un asset lo incluye siempre (marcado).
   */
  includeNoise?: boolean;
  /** Solo lo que la vista principal oculta por este motivo (los recuentos de `hidden`). */
  hidden?: HiddenReason;
  /** Orden: por prioridad (por defecto) o por severidad. */
  sort?: 'priority' | 'severity';
  /**
   * true: también los de assets con el escaneo desactivado por su política (§10), que por defecto
   * no salen en las listas globales. La lista de un asset los incluye siempre.
   */
  includeScanDisabled?: boolean;
  /**
   * Solo los de assets de este proyecto (heredados incluidos; las imágenes, por quienes las usan);
   * los contenedores afectados se cuentan solo dentro del proyecto.
   */
  projectId?: string;
  limit?: number;
  offset?: number;
}

/**
 * Findings de un asset y, si es un contenedor o una imagen, el estado del escaneo de la imagen. Los
 * de un contenedor son los de su imagen (relación `instance_of`).
 */
export interface AssetFindingsPage {
  items: Finding[];
  total: number;
  image: ContainerImageSummary | null;
  /** SBOM del que salen (el de la imagen, en un contenedor); null si no tiene. */
  sbom: SbomSummary | null;
}

/** Paquete afectado por una vulnerabilidad (un finding). */
export interface VulnerablePackage {
  findingId: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string | null;
  pkgPath: string | null;
  status: FindingStatus;
  priority: number | null;
  noiseReason: NoiseReason | null;
  /** La última aceptación del riesgo (vigente si `status = 'accepted'`). */
  acceptance?: FindingAcceptance | null;
}

/** Findings agrupados por vulnerabilidad: un CVE con todos los paquetes en los que aparece. */
export interface VulnerabilityGroup {
  vulnerabilityId: string;
  /** La más grave de sus findings. */
  severity: Severity;
  title: string | null;
  primaryUrl: string | null;
  /** Algún paquete tiene versión corregida. */
  fixable: boolean;
  packages: VulnerablePackage[];
  /** La de su finding más prioritario, con sus motivos. */
  priority: PriorityInfo | null;
  /** Todos sus findings son ruido: el motivo (el del más prioritario). */
  noiseReason: NoiseReason | null;
  kev: boolean;
  epss: number | null;
  cvss: number | null;
}

/** GET /assets/:id/vulnerabilities: como `AssetFindingsPage`, pero una fila por CVE. */
export interface AssetVulnerabilitiesPage {
  items: VulnerabilityGroup[];
  /** Número de CVE distintos. */
  total: number;
  image: ContainerImageSummary | null;
  sbom: SbomSummary | null;
  /** El asset sirve (o deja pasar) nombres públicos (QoL-5b). null si no. */
  exposure?: PublicExposure | null;
  /**
   * Con `includeNoise=false`: findings del asset que el filtro deja fuera por ser ruido (kernel no
   * en uso, sin corrección prevista), por motivo. null (o ausente) si no se quitó el ruido.
   */
  hidden?: Partial<Record<NoiseReason, number>> | null;
}

export interface ScanAssetResponse {
  /** El del SBOM de un servidor o CT y uno por imagen (deduplicado por image ID). */
  jobs: EnqueueJobResponse[];
}

export interface ImageScanJobData {
  /** `sha256:…` */
  imageId: string;
  /** Re-analizar aunque ya esté escaneada (y tenga SBOM). */
  force?: boolean;
  /**
   * Escaneo de relleno (backfill) de una imagen escaneada antes de los SBOMs: se saca de este
   * host y, al terminar, se encola la siguiente del mismo host (una a la vez por host).
   */
  backfillHostId?: string;
}

export interface ImageScanJobResult {
  imageId: string;
  scanStatus: ImageScanStatus;
  scanReason: string | null;
  /** true si no se ejecutó Trivy (imagen ya escaneada). */
  cached: boolean;
  vulnerabilityCount: number | null;
  /** Contenedores activos que usan la imagen. */
  containers: number;
  /** Findings de la imagen creados y pasados a `fixed` en este escaneo. */
  findingsCreated: number;
  findingsFixed: number;
}

// --- SBOMs (DESIGN §5, §9) ---

/** Tipos de asset con SBOM propio de su sistema (`host.scan` con `trivy rootfs`). */
export const HOST_SBOM_ASSET_TYPES = ['server', 'lxc'] as const;

/** De dónde sale un SBOM: `docker save` de una imagen o la copia de las BDs de paquetes de un host. */
export const SBOM_SOURCES = ['docker_save', 'rootfs'] as const;
export type SbomSource = (typeof SBOM_SOURCES)[number];

/** SBOM guardado de un asset (servidor, CT o imagen), sin su contenido. */
export interface SbomSummary {
  /** Asset del SBOM (la imagen, en un contenedor). */
  assetId: string;
  source: SbomSource;
  format: 'cyclonedx';
  specVersion: string;
  /** Sistema detectado por Trivy (`debian` `13.1`). */
  os: { family: string; name: string } | null;
  packageCount: number;
  sizeBytes: number;
  trivyVersion: string | null;
  generatedAt: string;
  /** Última evaluación con `trivy sbom` (escaneo o re-evaluación periódica). */
  evaluatedAt: string | null;
  /** Fecha de la BD de vulnerabilidades de Trivy de esa evaluación. */
  dbUpdatedAt: string | null;
  vulnerabilityCount: number | null;
  /** Motivo si la última re-evaluación falló (los findings se quedan como estaban). */
  evaluationError: string | null;
}

/** Paquete instalado según el SBOM (DESIGN §5: `Package`). */
export interface PackageSummary {
  id: string;
  name: string;
  version: string;
  /** Tipo del purl (`deb`, `rpm`, `apk`, `npm`, `pypi`, `golang`, `maven`…). */
  ecosystem: string;
  purl: string | null;
  /** Fichero del que sale (paquetes de lenguajes en imágenes). */
  pkgPath: string | null;
}

export interface PackageListQuery {
  /** Nombre que contenga el texto (sin distinguir mayúsculas). */
  q?: string;
  ecosystem?: string;
  limit?: number;
  offset?: number;
}

/** GET /assets/:id/packages: paquetes del SBOM (en un contenedor, los de su imagen). */
export interface AssetPackagesPage {
  items: PackageSummary[];
  total: number;
  sbom: SbomSummary | null;
}

export interface HostScanJobData {
  /** Servidor con conexión o CT. */
  assetId: string;
  /** Evaluar de nuevo aunque el SBOM no haya cambiado y la BD de Trivy sea la misma. */
  force?: boolean;
}

export interface HostScanJobResult {
  assetId: string;
  /** `skipped`: sin forma de leerlo o sin ninguna BD de paquetes reconocida (no es un fallo). */
  status: 'scanned' | 'skipped';
  reason: string | null;
  /** Paquetes iguales que en el SBOM guardado (no se reescribe). */
  unchanged: boolean;
  /** Sin evaluar: SBOM igual y ya evaluado con la misma BD de Trivy. */
  cached: boolean;
  packageCount: number;
  vulnerabilityCount: number | null;
  findingsCreated: number;
  findingsFixed: number;
}

/** Id de deduplicación de `host.scan`. */
export function hostScanDeduplicationId(assetId: string): string {
  return `host-scan:${assetId}`;
}

/** Re-evaluación de todos los SBOMs guardados (la programa el worker o la pide la API). */
export interface SbomReevaluateJobData {
  /**
   * Descargar antes la BD de Trivy aunque no haya caducado (`TRIVY_DB_MAX_AGE`): la pide un
   * usuario desde Vulnerabilidades. Sin ella, solo se descarga si está caducada.
   */
  downloadDb?: boolean;
}

export interface SbomReevaluateJobResult {
  /** SBOMs de assets no retirados. */
  sboms: number;
  evaluated: number;
  /** Reemplazados por un escaneo mientras se evaluaban (ya están al día). */
  superseded: number;
  failed: number;
  findingsCreated: number;
  findingsFixed: number;
  /** Fecha de la BD de vulnerabilidades usada. */
  dbUpdatedAt: string | null;
  /** Si no se pudo actualizar la BD (sin red), se evalúa con la que hay y se dice aquí. */
  dbUpdateError: string | null;
  /** Escaneos de relleno encolados (imágenes escaneadas antes de los SBOMs). */
  backfillQueued: number;
}

/** Id del job scheduler de BullMQ de la re-evaluación periódica (y deduplicación de la manual). */
export const SBOM_REEVALUATE_ID = 'sbom-reevaluate';

/** Id de deduplicación de `image.scan`: una imagen se escanea una vez aunque esté en varios contenedores. */
export function scanDeduplicationId(imageId: string): string {
  return `scan:${imageId}`;
}

/** Vulnerabilidad del inventario (GET /vulnerabilities): un CVE con lo que afecta. */
export interface VulnerabilitySummary {
  vulnerabilityId: string;
  /** La más grave de sus findings. */
  severity: Severity;
  title: string | null;
  primaryUrl: string | null;
  /** Algún paquete tiene versión corregida. */
  fixable: boolean;
  /** Paquetes afectados (nombres distintos). */
  packageNames: string[];
  /** Imágenes con el CVE. */
  images: number;
  /** Contenedores no retirados que usan esas imágenes. */
  containers: number;
  /** Otros assets con el CVE (servidores y CT). */
  otherAssets: number;
  /** De `images`, cuántas no usa ningún contenedor activo («sin uso»). */
  unusedImages: number;
  /**
   * Algún afectado sirve (o deja pasar) un nombre público (QoL-5b): uno de los motivos de su
   * prioridad. null si ninguno.
   */
  exposure: PublicExposure | null;
  /** La de su finding más prioritario, con sus motivos (null si aún no se calculó). */
  priority: PriorityInfo | null;
  /** En el catálogo KEV de CISA. */
  kev: boolean;
  /** EPSS (0–1); null sin dato. */
  epss: number | null;
  /** El mayor CVSS de sus findings. */
  cvss: number | null;
}

/** GET /vulnerabilities: la página y lo que la vista oculta con su motivo. */
export interface VulnerabilitiesPage {
  items: VulnerabilitySummary[];
  total: number;
  /**
   * Findings que el filtro deja fuera, por el primer motivo que los oculta (solo los motivos que
   * aplica el filtro). null si no oculta nada.
   */
  hidden: Partial<Record<HiddenReason, number>> | null;
}

// --- Buscador de CVEs (DESIGN §9, §15; sesión 16) ---

/** Puntuación CVSS de una fuente (`nvd`, `ghsa`, `redhat`, `ubuntu`…), según la BD de Trivy. */
export interface CvssScore {
  source: string;
  v2Score: number | null;
  v2Vector: string | null;
  v3Score: number | null;
  v3Vector: string | null;
  v40Score: number | null;
  v40Vector: string | null;
}

/** Detalles de un CVE en la BD de vulnerabilidades de Trivy. */
export interface VulnerabilityDetails {
  title: string | null;
  description: string | null;
  /** Severidad general según Trivy (la de cada distribución va en los findings). */
  severity: string | null;
  cweIds: string[];
  cvss: CvssScore[];
  references: string[];
  publishedAt: string | null;
  lastModifiedAt: string | null;
}

/**
 * Resultado de buscar un CVE en la BD de Trivy: `found`, `not_found` (Trivy no lo conoce) o
 * `unavailable` (sin BD, esquema no reconocido, actualizándose o el worker no respondió).
 */
export const VULNERABILITY_DETAILS_STATUSES = [
  'found',
  'not_found',
  'unavailable',
] as const;
export type VulnerabilityDetailsStatus =
  (typeof VULNERABILITY_DETAILS_STATUSES)[number];

export interface VulnerabilityLookupJobData {
  vulnerabilityId: string;
}

export interface VulnerabilityLookupJobResult {
  status: VulnerabilityDetailsStatus;
  details: VulnerabilityDetails | null;
  /** Fecha de la BD de Trivy consultada. */
  dbUpdatedAt: string | null;
  /** Motivo de `unavailable`. */
  reason: string | null;
}

/** Prefijo del id de `vulnerability.lookup` (no es un UUID: no se registra en `job_runs`). */
export const VULNERABILITY_LOOKUP_JOB_PREFIX = 'lookup-';

/** Identificador aceptable de una vulnerabilidad (CVE, GHSA, DSA, TEMP…). */
export const VULNERABILITY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$/;

/** Forma de un CVE (para saltar directamente a su ficha desde la barra de búsqueda). */
export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

/** Qué hacer con un afectado: actualizar el paquete en el sistema o reconstruir la imagen. */
export type SuggestedAction = 'update_package' | 'rebuild_image';

/** Paquete de un afectado en el que aparece el CVE. */
export interface AffectedPackage extends VulnerablePackage {
  /** Estado según la distribución (`fixed`, `affected`, `will_not_fix`…). */
  fixStatus: string | null;
}

/** Puerto por el que se llega a un afectado desde fuera de la máquina. */
export interface ExposedPort {
  port: number;
  proto: string;
  /** Dirección de escucha o de publicación (`0.0.0.0`, una IP…). */
  address: string;
  /** Proceso que escucha (servidores y CT), si se conoce. */
  process: string | null;
}

/**
 * Nodo del árbol de afectados de un CVE, con la jerarquía real (nodo → CT → contenedor →
 * imagen). Los nodos de contexto (`affected = false`) solo sitúan a los afectados.
 */
export interface AffectedNode {
  id: string;
  name: string;
  type: AssetType;
  status: AssetStatus;
  runtimeState: AssetRuntimeState | null;
  /** Tiene el CVE (sus findings o, en un contenedor, los de su imagen). */
  affected: boolean;
  /** Paquetes con el CVE (en un contenedor, los de su imagen). */
  packages: AffectedPackage[];
  /** Puertos expuestos: en escucha fuera de loopback o publicados por Docker. */
  exposedPorts: ExposedPort[];
  /** Nombres públicos que sirve o que pasan por él (QoL-5b; hasta 3). Ausente si ninguno. */
  publicDomains?: string[];
  action: SuggestedAction | null;
  /** Imagen sin uso: ningún contenedor activo la usa (cuelga del host que la guarda). */
  unused?: boolean;
  /**
   * La de su finding más prioritario de este CVE (en un contenedor, la de su imagen). Ausente en
   * los nodos de contexto.
   */
  priority?: PriorityInfo | null;
  /** Ese finding es ruido (kernel no en uso, sin corrección prevista). */
  noiseReason?: NoiseReason | null;
  children: AffectedNode[];
}

/** GET /vulnerabilities/:id: resumen del CVE y su árbol de afectados. */
export interface VulnerabilityDetail {
  vulnerabilityId: string;
  detailsStatus: VulnerabilityDetailsStatus;
  details: VulnerabilityDetails | null;
  /** Motivo de `unavailable`. */
  detailsReason: string | null;
  /** Fecha de la BD de Trivy consultada. */
  trivyDbUpdatedAt: string | null;
  /** Severidad máxima de sus findings abiertos o aceptados (null si no afecta a nada). */
  severity: Severity | null;
  /** Título y referencia de los findings (si no hay detalles de Trivy). */
  title: string | null;
  primaryUrl: string | null;
  /** Versiones que lo corrigen, según los findings (distintas). */
  fixedVersions: string[];
  /** Estados de la distribución (`fixed`, `affected`, `will_not_fix`…) de los findings. */
  fixStatuses: string[];
  /** CISA KEV y EPSS del CVE (sesión 19). */
  enrichment: VulnerabilityEnrichment;
  /** La de su finding más prioritario, con sus motivos (null si no afecta a nada). */
  priority: PriorityInfo | null;
  inventory: {
    /** Assets afectados (contenedores, imágenes, servidores y CT; sin retirados). */
    affectedAssets: number;
    /** Findings abiertos o aceptados. */
    openFindings: number;
    /** Findings ya corregidos (`fixed`) y la fecha del último. */
    fixedFindings: number;
    lastFixedAt: string | null;
    /** SBOMs de assets no retirados y la fecha de la última evaluación. */
    sboms: number;
    lastEvaluatedAt: string | null;
  };
  tree: AffectedNode[];
}

/** POST /vulnerabilities/:id/rescan. */
export interface RescanAffectedResponse {
  /** Un job por servidor, CT o imagen, con el asset al que corresponde. */
  jobs: (EnqueueJobResponse & { assetId: string; assetName: string })[];
  /** Afectados que no se pueden escanear ahora, con el motivo. */
  skipped: { assetId: string; name: string; reason: string }[];
}

/** Asset sugerido por la barra de búsqueda global. */
export interface SuggestedAsset {
  id: string;
  name: string;
  type: AssetType;
  status: AssetStatus;
  /** Host de conexión o IPv4 del equipo, si tiene. */
  address: string | null;
  /** Padre `contains` (el nodo de un CT, el host de un contenedor…). */
  parentName: string | null;
}

/** Sugerencias de la barra de búsqueda global (GET /search/suggest). */
export interface SearchSuggestions {
  /** Cualquier recurso del inventario (sin retirados) por nombre, dirección, rol o etiqueta. */
  assets: SuggestedAsset[];
  vulnerabilities: {
    vulnerabilityId: string;
    severity: Severity;
    title: string | null;
  }[];
  packages: {
    name: string;
    /** CVE abiertos en el paquete. */
    vulnerabilities: number;
    /** Assets con el paquete instalado (según sus SBOMs) o con findings en él. */
    assets: number;
  }[];
}

/** GET /vulnerabilities/new: CVE abiertos desde la última vez que el usuario marcó «vistos». */
export interface NewVulnerabilitiesPage extends VulnerabilitiesPage {
  /** Fecha de «Marcar como vistos» (o de la primera visita). */
  since: string;
  /** De los nuevos visibles, cuántos CVE están en KEV. */
  kev: number;
}
