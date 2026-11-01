import type {
  AssetRelationType,
  AssetRuntimeState,
  AssetStatus,
  AssetType,
  JobName,
  JobRunOrigin,
  JobRunParent,
  JobRunState,
  ServiceCutReason,
  ServicePathStatus,
  ServiceResolverKind,
  Severity,
} from '@infraward/shared-types';

/** Severidad visual de `p-tag`. */
export type TagSeverity =
  | 'success'
  | 'secondary'
  | 'info'
  | 'warn'
  | 'danger'
  | 'contrast';

export const ASSET_TYPE_LABELS: Record<AssetType, string> = {
  server: 'Servidor',
  vm: 'VM',
  lxc: 'CT (LXC)',
  container: 'Contenedor',
  domain: 'Dominio',
  dns_record: 'Registro DNS',
  database: 'Base de datos',
  image: 'Imagen',
  volume: 'Volumen',
  network: 'Red',
  subscription: 'Suscripción',
  certificate: 'Certificado',
  dns_provider: 'Conector de dominios',
};

/** Iconos de Bootstrap Icons (`bi bi-…`). */
export const ASSET_TYPE_ICONS: Record<AssetType, string> = {
  server: 'bi-hdd-rack',
  vm: 'bi-pc-display',
  lxc: 'bi-box',
  container: 'bi-box-seam',
  domain: 'bi-globe2',
  dns_record: 'bi-signpost-split',
  database: 'bi-database',
  image: 'bi-layers',
  volume: 'bi-device-hdd',
  network: 'bi-diagram-2',
  subscription: 'bi-person-badge',
  certificate: 'bi-patch-check',
  dns_provider: 'bi-cloud',
};

export const ASSET_STATUS_LABELS: Record<AssetStatus, string> = {
  pending_enrollment: 'Pendiente de alta',
  active: 'Activo',
  missing: 'Desaparecido',
  retired: 'Retirado',
};

export const ASSET_STATUS_SEVERITY: Record<AssetStatus, TagSeverity> = {
  pending_enrollment: 'info',
  active: 'success',
  missing: 'warn',
  retired: 'secondary',
};

/** Estado de ejecución (Docker o Proxmox), distinto del estado de inventario. */
export const RUNTIME_LABELS: Record<AssetRuntimeState, string> = {
  running: 'En marcha',
  stopped: 'Parado',
  paused: 'Pausado',
  other: 'Otro',
};

export const RUNTIME_SEVERITY: Record<AssetRuntimeState, TagSeverity> = {
  running: 'success',
  stopped: 'secondary',
  paused: 'warn',
  other: 'info',
};

export const RUNTIME_ICONS: Record<AssetRuntimeState, string> = {
  running: 'bi-play-circle',
  stopped: 'bi-stop-circle',
  paused: 'bi-pause-circle',
  other: 'bi-question-circle',
};

export const RELATION_LABELS: Record<AssetRelationType, string> = {
  contains: 'contiene',
  resolves_to: 'resuelve a',
  depends_on: 'depende de',
  instance_of: 'instancia de',
  mounts: 'monta',
  attached_to: 'conectado a',
  stores: 'tiene la imagen',
  secured_by: 'usa el certificado',
  served_by: 'servido por',
  routes_to: 'envía a',
};

/** Relación leída desde el destino (`incoming`). */
export const RELATION_INCOMING_LABELS: Record<AssetRelationType, string> = {
  contains: 'contenido en',
  resolves_to: 'apuntado por',
  depends_on: 'requerido por',
  instance_of: 'imagen de',
  mounts: 'montado por',
  attached_to: 'red de',
  stores: 'está en',
  secured_by: 'certificado de',
  served_by: 'sirve',
  routes_to: 'recibe de',
};

export const SEVERITY_ORDER: readonly Severity[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNKNOWN',
];

export const SEVERITY_TAG: Record<Severity, TagSeverity> = {
  CRITICAL: 'danger',
  HIGH: 'warn',
  MEDIUM: 'info',
  LOW: 'secondary',
  UNKNOWN: 'contrast',
};

export const JOB_LABELS: Record<JobName, string> = {
  ping: 'Prueba (ping)',
  'enrollment.verify': 'Verificación de alta',
  'asset.collect': 'Recolección',
  'asset.discover': 'Descubrimiento',
  'image.scan': 'Escaneo de vulnerabilidades',
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

export const JOB_ICONS: Record<JobName, string> = {
  ping: 'bi-broadcast',
  'enrollment.verify': 'bi-key',
  'asset.collect': 'bi-cloud-download',
  'asset.discover': 'bi-diagram-3',
  'image.scan': 'bi-shield-check',
  'host.scan': 'bi-box-seam',
  'sbom.reevaluate': 'bi-arrow-repeat',
  'vulnerability.lookup': 'bi-search',
  'inventory.reconcile': 'bi-arrow-clockwise',
  'domains.test': 'bi-plug',
  'domains.sync': 'bi-globe2',
  'services.link': 'bi-signpost-split',
  'assets.bulk': 'bi-ui-checks',
  'vulnerability.intel': 'bi-cloud-arrow-down',
  'findings.prioritize': 'bi-sort-down',
  'metrics.sample': 'bi-graph-up',
  'alert.deliver': 'bi-send',
  'alert.test': 'bi-send-check',
};

export const JOB_STATE_LABELS: Record<JobRunState, string> = {
  queued: 'En cola',
  active: 'En curso',
  completed: 'Terminado',
  failed: 'Fallido',
};

export const JOB_STATE_SEVERITY: Record<JobRunState, TagSeverity> = {
  queued: 'secondary',
  active: 'info',
  completed: 'success',
  failed: 'danger',
};

/** De dónde viene una ejecución (Actividad). */
export const JOB_ORIGIN_LABELS: Record<JobRunOrigin, string> = {
  bulk: 'En lote',
  chain: 'Encadenada',
  manual: 'Manual',
  schedule: 'Programada',
  enrollment: 'Alta',
};

export const JOB_ORIGIN_ICONS: Record<JobRunOrigin, string> = {
  bulk: 'bi-ui-checks',
  chain: 'bi-diagram-2',
  manual: 'bi-person',
  schedule: 'bi-clock-history',
  enrollment: 'bi-box-arrow-in-down',
};

export const JOB_ORIGIN_HINTS: Record<JobRunOrigin, string> = {
  bulk: 'La lanzó una operación en lote',
  chain: 'La encoló otra tarea (recolección → descubrimiento → escaneos, reconciliación → recolecciones)',
  manual: 'Pedida desde la web o la API',
  schedule: 'La lanzó la comprobación periódica del inventario',
  enrollment: 'La lanzó el alta del servidor',
};

/** «Recolectar · 12 assets» del resumen de un lote (sin omitidos, tareas ni quién lo lanzó). */
export function bulkSummary(message: string | null | undefined): string | null {
  if (!message) return null;
  return message.split(' · ').slice(0, 2).join(' · ');
}

/** La tarea de la que cuelga una ejecución: «Recolección de pve1» o el resumen del lote. */
export function parentLabel(parent: JobRunParent): string {
  if (parent.name === 'assets.bulk')
    return bulkSummary(parent.message) ?? JOB_LABELS['assets.bulk'];
  const label = JOB_LABELS[parent.name] ?? parent.name;
  return parent.assetName ? `${label} de ${parent.assetName}` : label;
}

/** «850 ms», «12 s», «3 min 05 s», «1 h 02 min»; «—» sin duración. */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0)
    return '—';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${String(s % 60).padStart(2, '0')} s`;
  return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, '0')} min`;
}

/** Una ejecución sigue pendiente (en cola o en curso). */
export function isRunning(run: { state: JobRunState }): boolean {
  return run.state === 'queued' || run.state === 'active';
}

/** Qué ha dado cada salto del camino de un dominio (QoL-5b). */
export const SERVICE_RESOLVER_LABELS: Record<ServiceResolverKind, string> = {
  dns: 'DNS',
  tunnel: 'Túnel de Cloudflare',
  nat: 'Reenvío NAT',
  'docker-proxy': 'Puerto publicado (Docker)',
  traefik: 'Traefik',
  caddy: 'Caddy',
  nginx: 'nginx',
  npm: 'Nginx Proxy Manager',
  listener: 'Proceso en escucha',
  manual: 'Fijado a mano',
};

export const SERVICE_RESOLVER_ICONS: Record<ServiceResolverKind, string> = {
  dns: 'bi-signpost',
  tunnel: 'bi-cloud-arrow-down',
  nat: 'bi-router',
  'docker-proxy': 'bi-box-arrow-in-right',
  traefik: 'bi-shuffle',
  caddy: 'bi-shuffle',
  nginx: 'bi-shuffle',
  npm: 'bi-shuffle',
  listener: 'bi-ear',
  manual: 'bi-pin-angle',
};

/** Por qué se corta el camino de un dominio. */
export const SERVICE_CUT_TEXT: Record<ServiceCutReason, string> = {
  no_target:
    'El registro no apunta a nada del inventario y no hay ningún reenvío NAT declarado para su IP (Ajustes › Inventario).',
  no_listener: 'No se ve nada escuchando en ese puerto (¿falta recoger el servidor o el puerto está cerrado?).',
  no_route_for_host: 'El proxy no tiene ninguna ruta para este nombre.',
  unknown_upstream: 'El proxy envía a un destino que no está en el inventario.',
  proxy_unreadable:
    'No se pudo leer la configuración del proxy. Con un sudoers anterior a la v5, vuelve a ejecutar el script de alta.',
  tunnel_unknown:
    'Apunta a un túnel de Cloudflare que no se ve: falta el permiso opcional «Account · Cloudflare Tunnel · Read» del conector o el túnel es de otra cuenta.',
  tunnel_no_config:
    'El túnel se gestiona localmente (config.yml): su configuración no está en la API de Cloudflare.',
  no_cloudflared: 'No hay ningún cloudflared en el inventario que ejecute el túnel.',
  max_hops: 'El camino tiene demasiados saltos.',
  cycle: 'El camino vuelve sobre sí mismo (un proxy se envía a sí mismo).',
};

export const SERVICE_STATUS_LABELS: Record<ServicePathStatus, string> = {
  complete: 'Completo',
  partial: 'Cortado',
  manual: 'Fijado a mano',
  none: 'Sin destino',
};

export const SERVICE_STATUS_SEVERITY: Record<ServicePathStatus, TagSeverity> = {
  complete: 'success',
  partial: 'warn',
  manual: 'info',
  none: 'secondary',
};
