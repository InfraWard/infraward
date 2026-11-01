// Contratos del inventario (DESIGN §5): Asset, AssetRelation y Snapshot.
import type {
  AssetConnection,
  AssetCredentials,
  CredentialRevocation,
  SshAuthMode,
} from './enrollment.js';
import type { SshdRiskLevel } from './collection.js';
import type { AdminAccess } from './terminal.js';
import type { DnsCheckLevel } from './domains.js';
import type { Severity } from './findings.js';
import type {
  EffectiveInventoryPolicy,
  SnapshotChangeSummary,
  SnapshotDiff,
  SnapshotSource,
} from './inventory.js';

export const ASSET_TYPES = [
  'server',
  'vm',
  'lxc',
  'container',
  'domain',
  'dns_record',
  'database',
  /** Imagen de contenedor (clave natural = image ID); sus contenedores la enlazan con `instance_of`. */
  'image',
  /** Volumen de Docker de un host (`mounts` desde sus contenedores). */
  'volume',
  /** Red de Docker de un host (`attached_to` desde sus contenedores). */
  'network',
  /** Suscripción de Plesk (hija del servidor; sus dominios cuelgan de ella). */
  'subscription',
  /**
   * Certificado TLS (de Plesk: hijo del dominio de cuyo repositorio es, o del servidor; leído en
   * el 443 de un registro DNS: hijo de su dominio). Una huella SHA-256, un único asset.
   */
  'certificate',
  /**
   * Cuenta de un proveedor de dominios (Cloudflare): raíz de sus dominios (`domain`) y registros
   * (`dns_record`). La crea `/connectors`; su token va como referencia en `credentials.apiToken`.
   */
  'dns_provider',
] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

/** Tipos que solo crean los descubridores y el escaneo (nunca a mano). */
export const DISCOVERED_ASSET_TYPES = [
  'image',
  'volume',
  'network',
  'subscription',
  'certificate',
  'dns_provider',
] as const satisfies readonly AssetType[];

/** Tipos que se pueden crear a mano (POST). */
export const MANUAL_ASSET_TYPES = ASSET_TYPES.filter(
  (t): t is Exclude<AssetType, (typeof DISCOVERED_ASSET_TYPES)[number]> =>
    !(DISCOVERED_ASSET_TYPES as readonly string[]).includes(t),
);
export type ManualAssetType = (typeof MANUAL_ASSET_TYPES)[number];

/**
 * Tipos que no salen en el árbol del inventario: las imágenes (compartidas entre hosts) y los
 * volúmenes y redes de Docker (se ven en la ficha del host y en las relaciones de sus
 * contenedores; un host con decenas de volúmenes ahogaría el árbol).
 */
export const TREE_HIDDEN_ASSET_TYPES = [
  'image',
  'volume',
  'network',
] as const satisfies readonly AssetType[];

export const ASSET_STATUSES = [
  'pending_enrollment',
  'active',
  'missing',
  'retired',
] as const;
export type AssetStatus = (typeof ASSET_STATUSES)[number];

/**
 * Estados que se pueden fijar a mano (POST/PATCH). `retired` solo se alcanza con DELETE (que
 * aplica la cascada y, desde la sesión 6, la revocación de credenciales); `missing` y `retired`
 * también los pone la reconciliación.
 */
export const MANUAL_ASSET_STATUSES = [
  'pending_enrollment',
  'active',
] as const satisfies readonly AssetStatus[];
export type ManualAssetStatus = (typeof MANUAL_ASSET_STATUSES)[number];

/**
 * `contains` es la jerarquía (un único padre, sin ciclos) que forma el árbol del inventario.
 * El resto son relaciones no jerárquicas (p. ej. `dns_record → server`) y no entran en el árbol.
 */
export const ASSET_RELATION_TYPES = [
  'contains',
  'resolves_to',
  'depends_on',
  /** Contenedor → imagen que ejecuta (como mucho una por contenedor). */
  'instance_of',
  /** Contenedor → volumen de Docker que monta. */
  'mounts',
  /** Contenedor → red de Docker a la que está conectado. */
  'attached_to',
  /** Host Docker → imagen que tiene (aunque ningún contenedor la use). */
  'stores',
  /** Dominio o registro DNS → certificado TLS que usa (Plesk) o que sirve en su 443. */
  'secured_by',
  /** Registro DNS → asset final que sirve el nombre (camino de QoL-5b, o fijado a mano). */
  'served_by',
  /** Eslabón de un camino → el siguiente (proxy → contenedor, host → contenedor publicado). */
  'routes_to',
] as const;
export type AssetRelationType = (typeof ASSET_RELATION_TYPES)[number];

/** Relaciones que mantienen el worker y los descubridores (nunca a mano). */
export const DISCOVERED_RELATION_TYPES = [
  'instance_of',
  'mounts',
  'attached_to',
  'stores',
  'secured_by',
  /**
   * Registro DNS → asset al que apunta: A/AAAA → servidor, VM o CT con esa IP; CNAME → registro
   * o dominio del inventario con ese nombre (QoL-5).
   */
  'resolves_to',
  /** Registro DNS → asset final que lo sirve (QoL-5b; también el fijado a mano). */
  'served_by',
  /** Eslabón → siguiente eslabón de los caminos de los registros (QoL-5b). */
  'routes_to',
] as const satisfies readonly AssetRelationType[];

/** Relaciones que se pueden crear a mano. */
export const MANUAL_ASSET_RELATION_TYPES = ASSET_RELATION_TYPES.filter(
  (
    t,
  ): t is Exclude<AssetRelationType, (typeof DISCOVERED_RELATION_TYPES)[number]> =>
    !(DISCOVERED_RELATION_TYPES as readonly string[]).includes(t),
);
export type ManualAssetRelationType =
  (typeof MANUAL_ASSET_RELATION_TYPES)[number];

/** Datos variables recogidos del asset (JSONB). */
export type AssetFacts = Record<string, unknown>;

export interface Asset {
  id: string;
  type: AssetType;
  /** Nombre visible: el puesto a mano (`displayName`) o, si no, el descubierto. */
  name: string;
  /** Nombre que pone el descubridor (o el del alta a mano); la reconciliación lo mantiene. */
  discoveredName: string;
  /** Nombre puesto a mano; null = se ve el descubierto. */
  displayName: string | null;
  /** Notas en Markdown (solo en `GET /assets/:id`). */
  notes?: string | null;
  /** Proyectos a los que pertenece, heredados incluidos (DESIGN §5). */
  projects: string[];
  status: AssetStatus;
  /** Identificador estable entre ejecuciones (machine-id, clúster + vmid…). Único por tipo. */
  naturalKey: string | null;
  roles: string[];
  tags: string[];
  facts: AssetFacts;
  /** Cómo se conecta el worker (servidores enrolados). */
  connection: AssetConnection | null;
  /** Solo referencias `secret://…`. */
  credentials: AssetCredentials;
  /** Clave estática o certificados de la CA SSH (DESIGN §6). */
  sshAuth: SshAuthMode;
  /** Huella (`SHA256:…`) de la host key fijada en el primer contacto. */
  hostKeyFingerprint: string | null;
  /**
   * Acceso interactivo de administración instalado por el script (DESIGN §7); null si no lo
   * tiene. Lo tiene el servidor con SSH; sus CT y contenedores se alcanzan a través de él.
   */
  adminAccess: AdminAccess | null;
  /**
   * Otro asset no retirado que ya tiene el machine-id de este servidor (la misma máquina dada
   * de alta dos veces). Mientras esté puesto, la recolección no guarda nada.
   */
  duplicateOfId: string | null;
  /** Solo en `GET /assets/:id`: el asset del que este es duplicado. */
  duplicateOf?: AssetSummary | null;
  /** Solo en `GET /assets/:id`: assets marcados como duplicados de este. */
  duplicates?: AssetSummary[];
  /** Política de inventario efectiva (DESIGN §10); el detalle, en `GET /assets/:id/policy`. */
  effectivePolicy: EffectiveInventoryPolicy;
  /**
   * Descubrimientos completos de su ámbito sin verlo (`missing`); a `RECONCILE_RETIRE_AFTER`
   * pasa a `retired`. 0 si está visto.
   */
  missingRuns: number;
  /** Desde cuándo está `missing` (null si no lo está). */
  missingSince: string | null;
  /** Retirado por la reconciliación (no a mano): vuelve a `active` si reaparece. */
  retiredAuto: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateAssetRequest {
  type: ManualAssetType;
  name: string;
  status?: ManualAssetStatus;
  naturalKey?: string | null;
  roles?: string[];
  tags?: string[];
  facts?: AssetFacts;
}

/**
 * El tipo de un asset no cambia y el nombre descubierto tampoco (lo mantiene la reconciliación):
 * se renombra con `displayName` (null = volver al descubierto).
 */
export interface UpdateAssetRequest
  extends Partial<Omit<CreateAssetRequest, 'type' | 'name'>> {
  displayName?: string | null;
  /** Markdown; null o vacío = sin notas. */
  notes?: string | null;
}

/** Longitud máxima de las notas de un asset. */
export const ASSET_NOTES_MAX = 20_000;

export interface AssetListQuery {
  type?: AssetType;
  status?: AssetStatus;
  tag?: string;
  role?: string;
  /** Solo los assets de este proyecto (heredados incluidos). */
  projectId?: string;
  /** Búsqueda por nombre visible o descubierto (contiene, sin distinguir mayúsculas). */
  q?: string;
  /** Objeto JSON que deben contener los facts (operador `@>`). */
  facts?: string;
  limit?: number;
  offset?: number;
}

export interface Page<T> {
  items: T[];
  total: number;
}

/** Lo mínimo para identificar y enlazar un asset (extremos de relaciones, listas…). */
export interface AssetSummary {
  id: string;
  name: string;
  type: AssetType;
  status: AssetStatus;
}

/** Volumen, red o imagen de un host Docker con su uso. */
export interface DockerResource extends AssetSummary {
  /** Contenedores activos que lo usan (`mounts`, `attached_to`, `instance_of`; de cualquier host en las imágenes). */
  containers: number;
  /** false = «sin uso» (ningún contenedor activo). */
  inUse: boolean;
}

/** `GET /assets/:id/docker`: lo que tiene un host Docker además de sus contenedores. */
export interface DockerHostResources {
  volumes: DockerResource[];
  networks: DockerResource[];
  /** Imágenes del host (`stores`), las use o no algún contenedor. */
  images: DockerResource[];
}

/**
 * Nodo del árbol del inventario: siempre resumido (nunca facts, conexión ni credenciales; la ficha
 * los carga con GET /assets/:id) para que el árbol no crezca con el tamaño de los facts.
 */
export interface AssetTreeSummaryNode extends AssetSummary {
  /** Nombre descubierto, solo si el asset está renombrado (si no, null). */
  discoveredName: string | null;
  roles: string[];
  tags: string[];
  /** Proyectos a los que pertenece (heredados incluidos). */
  projects: string[];
  /**
   * Cómo se llega al asset, para distinguir dos con el mismo nombre: el host de conexión (o la IP
   * por defecto) de un servidor, la IPv4 de un CT/VM y los puertos publicados de un contenedor.
   */
  address: string | null;
  /**
   * IPs del asset para la búsqueda `ip:` (host de conexión si es una IP, IPv4 por defecto, las de
   * sus interfaces y la fija de `net0`), sin repetir.
   */
  ips: string[];
  /** Estado de ejecución (Docker o Proxmox), independiente del estado de inventario. */
  runtimeState: AssetRuntimeState | null;
  /** Estado tal como lo da la fuente (`exited`, `created`…). */
  runtimeDetail: string | null;
  /**
   * Findings `open` por severidad. Los de un contenedor son los de su imagen (`instance_of`). Sin
   * los de un kernel que no está en ejecución (`kernelNotRunningFindings`).
   */
  openFindings: Record<Severity, number>;
  /** Findings `open` CRITICAL y HIGH con versión corregida (hay parche), con el mismo criterio. */
  fixableFindings: Record<'CRITICAL' | 'HIGH', number>;
  /**
   * Findings `open` de paquetes de un kernel instalado que no es el que corre (o de cabeceras y
   * herramientas): no cuentan en los dos de arriba. Opcional: 0 si falta.
   */
  kernelNotRunningFindings?: number;
  /** La última recolección vio el sudoers por debajo de la versión que necesitan sus roles. */
  sudoersOutdated: boolean;
  /** Avisos de recolección parcial de la última recolección (`facts.infraward.warnings`). */
  collectionWarnings: number;
  /** Id del asset del que este es duplicado (mismo machine-id), o null. */
  duplicateOf: string | null;
  /** Comparte machine-id con otros assets con host keys distintas (clon sin regenerar). */
  machineIdClone: boolean;
  /**
   * Certificados: fin de validez (`notAfter`); dominios: caducidad del registro (RDAP); null en
   * el resto.
   */
  expiresAt: string | null;
  /**
   * Registros DNS: aviso de registro colgante sin marcar como esperado (`high`: riesgo de
   * subdomain takeover o asset retirado; `info`: IP pública desconocida); null si no hay.
   */
  dnsWarning: DnsCheckLevel | null;
  /**
   * Modo CA y el servidor confía en un conjunto de CA distinto del vigente en el proveedor (p. ej.
   * durante una rotación): hay que volver a ejecutar el script de alta.
   */
  sshCaOutdated: boolean;
  /**
   * sshd admite el login de root o por contraseña (`sshd -T`, sudoers v7): `root-password` = las
   * dos cosas, `root` = PermitRootLogin yes, `password` = contraseñas; null si no (o sin datos).
   */
  sshdRisk: SshdRiskLevel | null;
  /**
   * Escaneo de vulnerabilidades desactivado por su política: sus findings (y los de la imagen de
   * un contenedor) no cuentan en `openFindings` ni `fixableFindings`.
   */
  scanDisabled: boolean;
  children: AssetTreeSummaryNode[];
}

export const ASSET_RUNTIME_STATES = [
  'running',
  'stopped',
  'paused',
  'other',
] as const;
export type AssetRuntimeState = (typeof ASSET_RUNTIME_STATES)[number];

export interface AssetRelation {
  id: string;
  parentId: string;
  childId: string;
  type: AssetRelationType;
  createdAt: string;
}

export interface CreateAssetRelationRequest {
  parentId: string;
  childId: string;
  type: ManualAssetRelationType;
}

/** Relación vista desde uno de sus extremos, con el resumen del otro (`peer`). */
export interface AssetRelationWithPeer extends AssetRelation {
  peer: AssetSummary;
}

export interface AssetRelations {
  /** Relaciones en las que el asset es el padre/origen (`peer` = hijo/destino). */
  outgoing: AssetRelationWithPeer[];
  /** Relaciones en las que el asset es el hijo/destino (`peer` = padre/origen). */
  incoming: AssetRelationWithPeer[];
}

/** Resultado de DELETE /assets/:id: retirada lógica (por defecto) o purga física del subárbol. */
export interface DeleteAssetResponse {
  mode: 'retired' | 'purged';
  /** El asset y todos sus descendientes `contains`. */
  affectedIds: string[];
  /** Assets con credenciales: se borran del proveedor y se indica cómo quitar el acceso. */
  revocations: CredentialRevocation[];
}

export interface SnapshotSummary {
  id: string;
  assetId: string;
  collectedAt: string;
  roles: string[];
  jobId: string | null;
  /** Recolección (Ansible) o descubrimiento (facts del descubridor). */
  source: SnapshotSource;
  /** Snapshot anterior con el que se calculó el diff (null en el primero). */
  previousId: string | null;
  /** Cambios por sección respecto al anterior; null en el primero y en los anteriores al diff. */
  changeSummary: SnapshotChangeSummary[] | null;
}

/**
 * Foto de un asset cuando cambia (DESIGN §10): solo se guarda si hay cambios reales respecto al
 * anterior, con el diff calculado al guardarla.
 */
export interface Snapshot extends SnapshotSummary {
  facts: AssetFacts;
  diff: SnapshotDiff | null;
}
