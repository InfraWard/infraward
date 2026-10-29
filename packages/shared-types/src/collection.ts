// Contratos de la recolección de servidores (DESIGN §8).

import type { InventoryTrigger } from './inventory.js';
import type { ProxyFacts, ProxyRoute } from './service-paths.js';

/**
 * Roles que asigna la detección. Al recoger se sustituyen solo estos: los roles que no estén en
 * la lista (puestos a mano) se conservan.
 */
export const DETECTED_ROLES = ['proxmox-node', 'plesk', 'docker-host'] as const;
export type DetectedRole = (typeof DETECTED_ROLES)[number];

export interface CollectedOs {
  family: string | null;
  distribution: string | null;
  version: string | null;
  kernel: string | null;
  arch: string | null;
}

export interface CollectedHardware {
  vendor: string | null;
  product: string | null;
  /** UUID del sistema según DMI (`dmidecode -t system`). */
  uuid: string | null;
  serial: string | null;
  virtualization: string | null;
  processor: string | null;
  cpus: number | null;
  cores: number | null;
  vcpus: number | null;
  memoryMb: number | null;
  swapMb: number | null;
}

export interface CollectedMount {
  mount: string;
  device: string;
  fstype: string;
  sizeBytes: number | null;
  availableBytes: number | null;
}

export interface CollectedInterface {
  name: string;
  mac: string | null;
  active: boolean | null;
  ipv4: string[];
  ipv6: string[];
}

export interface CollectedNetwork {
  hostname: string | null;
  fqdn: string | null;
  defaultIpv4: string | null;
  interfaces: CollectedInterface[];
}

export interface CollectedPackage {
  name: string;
  version: string;
  arch: string | null;
  /** `dpkg`, `rpm`, `apk`… */
  manager: string | null;
}

export interface CollectedService {
  name: string;
  state: string;
  status: string | null;
}

export interface CollectedPort {
  proto: 'tcp' | 'udp';
  address: string;
  port: number;
  process: string | null;
  pid: number | null;
}

/**
 * Desde dónde se llega a un puerto: `all` = todas las interfaces (0.0.0.0, ::, *), `address` =
 * una IP concreta que no es de loopback, `local` = solo loopback (127.x, ::1).
 */
export type PortExposure = 'all' | 'address' | 'local';

/** Exposición de una dirección de escucha (sin dirección = local). */
export function portExposure(address: string | null | undefined): PortExposure {
  if (!address) return 'local';
  if (['0.0.0.0', '::', '[::]', '*'].includes(address)) return 'all';
  return address.startsWith('127.') ||
    address === '::1' ||
    address === 'localhost'
    ? 'local'
    : 'address';
}

export interface CollectedDetection {
  /** Salida de `pveversion` si es un nodo Proxmox. */
  proxmox: string | null;
  /** Salida de `plesk version` (primera línea) si es un servidor Plesk. */
  plesk: string | null;
  /** Versión del demonio de Docker si `docker info` responde. */
  docker: string | null;
}

/** Datos de la propia recolección. */
export interface CollectionMeta {
  collectedAt: string;
  /** `pct`: recogido desde el nodo Proxmox, sin SSH en el CT (no hay sudoers propio). */
  via: CollectionVia;
  /** Versión de `/etc/infraward/sudoers-version` (null si no hay: alta manual). */
  sudoersVersion: number | null;
  sudoersOutdated: boolean;
  /**
   * Notas informativas de lo que no se ve con este sudoers sin estar desactualizado (tabla
   * `SUDOERS_CAPABILITIES`, efecto `note`), p. ej. volúmenes y redes sin uso.
   */
  sudoersNotes?: string[];
  /**
   * CA SSH en la que confía el servidor (modo CA): versión de `/etc/infraward/ssh-ca-version` y
   * huellas de `/etc/ssh/infraward/trusted_user_ca_keys`. null si no está configurada.
   */
  sshCa: SshCaTrust | null;
  /**
   * El machine-id también es de otros assets con host keys distintas (VM, CT o plantilla
   * clonados): se recoge con la clave `<machine-id>+<huella>` (§8). null si no.
   */
  machineIdClone?: MachineIdClone | null;
  /** Avisos de recolección parcial (sudo denegado, comando ausente…). */
  warnings: string[];
}

/** Servidor cuyo machine-id comparten otros (clones). */
export interface MachineIdClone {
  machineId: string;
  sharedWith: { id: string; name: string }[];
}

/** Lo que el servidor tiene instalado de la CA SSH (lo lee el worker, sin sudo). */
export interface SshCaTrust {
  version: number | null;
  /** Huellas `SHA256:…` de las claves de CA confiables. */
  trusted: string[];
}

/**
 * Versión del fichero de CAs y de la configuración de sshd que instala el script de alta en
 * modo CA. Si cambia lo que se instala (no las claves), sube; las claves se comparan aparte.
 */
export const SSH_CA_CONFIG_VERSION = 1;

/**
 * ¿Hay que volver a ejecutar el script? Si la versión instalada es antigua o el conjunto de
 * claves confiables no es exactamente el vigente en el proveedor (falta la nueva durante una
 * rotación, o sigue la retirada).
 */
export function sshCaOutdated(
  installed: SshCaTrust | null | undefined,
  current: readonly string[],
): boolean {
  if (!installed || current.length === 0) return false;
  if ((installed.version ?? 0) < SSH_CA_CONFIG_VERSION) return true;
  const have = new Set(installed.trusted);
  return have.size !== current.length || current.some((fp) => !have.has(fp));
}

/** `facts` de un servidor tras recogerlo (asset y snapshot). */
export interface CollectedFacts {
  machineId: string | null;
  os: CollectedOs;
  hardware: CollectedHardware;
  mounts: CollectedMount[];
  network: CollectedNetwork;
  packages: CollectedPackage[];
  services: CollectedService[];
  ports: CollectedPort[];
  detected: CollectedDetection;
  infraward: CollectionMeta;
  /**
   * Rutas del nginx del sistema (QoL-5b; solo nombres y destinos, filtradas en el servidor).
   * Ausente si no hay nginx; null si no se pudo leer (sudoers anterior a la v5).
   */
  proxy?: ProxyFacts | null;
  /**
   * Procesos en marcha o en escucha con los paquetes de su ejecutable y sus librerías (sudoers
   * v6, sesión 19; calculado en el servidor). Ausente o null sin la v6.
   */
  processes?: CollectedProcess[] | null;
  /**
   * Autenticación de sshd según `sshd -T` (sudoers v7, QoL-7; filtrado en el servidor). Ausente
   * o null sin la v7 o si el servidor no tiene sshd.
   */
  sshd?: SshdAuthFacts | null;
}

/** Lo único que se lee de la configuración efectiva de sshd (para un usuario `root`). */
export interface SshdAuthFacts {
  /** `yes`, `prohibit-password`, `forced-commands-only` o `no` (`without-password` = prohibit). */
  permitRootLogin: string;
  passwordAuthentication: boolean;
  /** Teclado interactivo (con PAM, también pide la contraseña). */
  kbdInteractiveAuthentication: boolean;
}

/**
 * Riesgo de la configuración de sshd: `root` = PermitRootLogin yes (root entra por SSH, con
 * clave o contraseña); `password` = se admiten contraseñas; `rootPassword` = las dos (la
 * contraseña de root de la caja fuerte sirve también por SSH, no solo en consola).
 */
export interface SshdAuthRisk {
  rootLogin: boolean;
  passwordLogin: boolean;
  rootPassword: boolean;
}

export function sshdAuthRisk(
  sshd: SshdAuthFacts | null | undefined,
): SshdAuthRisk | null {
  if (!sshd) return null;
  const rootLogin = sshd.permitRootLogin === 'yes';
  const passwordLogin =
    sshd.passwordAuthentication || sshd.kbdInteractiveAuthentication;
  if (!rootLogin && !passwordLogin) return null;
  return { rootLogin, passwordLogin, rootPassword: rootLogin && passwordLogin };
}

export type SshdRiskLevel = 'root-password' | 'root' | 'password';

/** Resumen del riesgo para el árbol y el panel (null si no hay). */
export function sshdRiskLevel(
  sshd: SshdAuthFacts | null | undefined,
): SshdRiskLevel | null {
  const risk = sshdAuthRisk(sshd);
  if (!risk) return null;
  return risk.rootPassword ? 'root-password' : risk.rootLogin ? 'root' : 'password';
}

/** Un proceso y los paquetes que usa (nunca su entorno ni su línea de órdenes). */
export interface CollectedProcess {
  pid: number;
  /** Nombre del proceso (`comm`), el mismo que `ports[].process`. */
  name: string;
  /** Unidad de systemd que lo lanzó, si es el MainPID de un servicio. */
  unit: string | null;
  /** Paquete del ejecutable (null si no es de ningún paquete: binario suelto). */
  exePackage: string | null;
  /** Paquetes de las librerías que tiene cargadas (sin el del ejecutable). */
  libPackages: string[];
}

export interface AssetCollectJobData {
  assetId: string;
  /** Qué lanzó la cadena (por defecto, `manual`); viaja a los jobs que encadena. */
  trigger?: InventoryTrigger;
}

export interface AssetCollectJobResult {
  assetId: string;
  /** null si no se guardó snapshot (servidor duplicado, o sin cambios: `unchanged`). */
  snapshotId: string | null;
  /** Los facts no cambiaron respecto al último snapshot: no se ha creado otro. */
  unchanged?: boolean;
  /**
   * Asset no retirado que ya tiene el machine-id de este servidor: no se ha guardado nada y el
   * asset queda marcado como duplicado.
   */
  duplicateOf: { id: string; name: string } | null;
  roles: string[];
  /** Huella de la host key usada (con `via: 'pct'`, la del nodo). */
  hostKeyFingerprint: string;
  sudoersVersion: number | null;
  via: CollectionVia;
  /** Descubrimiento encolado tras la recolección (rol con descubridor), si lo hay. */
  discoveryJobId: string | null;
  /** SBOM del servidor o CT (`host.scan`) encolado tras la recolección, si lo hay. */
  hostScanJobId: string | null;
  warnings: string[];
}

// --- Descubrimiento (DESIGN §8: descubridores como plugins) ---

/** Roles que activan un descubridor de hijos. La API solo encola `asset.discover` para estos. */
export const DISCOVERABLE_ROLES = [
  'proxmox-node',
  'docker-host',
  'plesk',
] as const;
export type DiscoverableRole = (typeof DISCOVERABLE_ROLES)[number];

/** Cómo se ha recogido un asset: por SSH directo o desde el nodo con `pct exec`. */
export type CollectionVia = 'ssh' | 'pct';

export interface ProxmoxInterface {
  name: string;
  mac: string | null;
  ipv4: string[];
  ipv6: string[];
}

/** Datos de un CT o VM según Proxmox; van en `facts.proxmox` del hijo. */
export interface ProxmoxGuestFacts {
  vmid: number;
  kind: 'lxc' | 'qemu';
  /** Nodo en el que está ahora. */
  node: string;
  /** Nombre del clúster (null en un nodo sin clúster). */
  cluster: string | null;
  /** `running`, `stopped`… */
  status: string;
  template: boolean;
  cpus: number | null;
  maxMemBytes: number | null;
  maxDiskBytes: number | null;
  uptime: number | null;
  tags: string[];
  /**
   * Configuración del guest sin contraseñas, claves, tokens ni notas (`cipassword`, `sshkeys`,
   * `description`…). null si no se pudo leer.
   */
  config: Record<string, string | number> | null;
  /** Interfaces reales de los CT en marcha (null si no se pudieron leer). */
  interfaces: ProxmoxInterface[] | null;
  discoveredAt: string;
}

/** Puerto publicado de un contenedor (`0.0.0.0:8080->80/tcp`). */
export interface DockerPortBinding {
  containerPort: number;
  proto: 'tcp' | 'udp' | 'sctp';
  /** null si no está publicado en el host (solo expuesto). */
  hostIp: string | null;
  hostPort: number | null;
}

/**
 * Datos de un contenedor según Docker; van en `facts.docker` del hijo. Solo lo necesario:
 * nunca el entorno (`Config.Env`), que suele llevar secretos, ni las etiquetas.
 */
export interface DockerContainerFacts {
  id: string;
  name: string;
  /** Referencia con la que se creó (`nginx:1.25`). */
  image: string;
  /**
   * Identidad de la imagen (`sha256:…`): lo que de verdad corre. Con el almacén clásico es el
   * digest del config; con el de containerd (Docker ≥ 29 por defecto), el del índice o manifiesto.
   */
  imageId: string;
  repoDigests: string[];
  repoTags: string[];
  /** `linux/amd64` (null si no se pudo leer la imagen). */
  platform: string | null;
  /** Tamaño de la imagen en el host (null si no se pudo leer). */
  imageSizeBytes: number | null;
  /** `running`, `exited`, `created`, `paused`… */
  state: string;
  /** Puertos expuestos y publicados (con el contenedor parado, los configurados). */
  ports: DockerPortBinding[];
  composeProject: string | null;
  /** Servicio de compose (`com.docker.compose.service`): su nombre en la red del proyecto. */
  composeService?: string | null;
  createdAt: string | null;
  startedAt: string | null;
  /**
   * Montajes (sesión 14; ausente en facts anteriores). Los volúmenes con nombre son además assets
   * `volume` enlazados con `mounts`.
   */
  mounts?: DockerMount[];
  /** Redes a las que está conectado (sesión 14). Cada una es un asset `network` (`attached_to`). */
  networks?: DockerContainerNetwork[];
  /**
   * Rutas que declara con etiquetas de Traefik o Caddy (QoL-5b): solo las claves de una lista
   * blanca salen del servidor (`rule`, `service`, `loadbalancer.server.port`, `reverse_proxy`).
   */
  proxyRoutes?: ProxyRoute[];
  /** Configuración de nginx o NPM leída con `docker exec … nginx -T`, filtrada en el servidor. */
  proxy?: ProxyFacts | null;
  discoveredAt: string;
}

/** Montaje de un contenedor. Nunca las opciones del driver (pueden llevar credenciales). */
export interface DockerMount {
  /** `volume`, `bind`, `tmpfs`, `npipe`, `cluster`. */
  type: string;
  /** Nombre del volumen (solo `volume`). */
  name: string | null;
  /** Ruta en el host (solo `bind`). */
  source: string | null;
  destination: string;
  readOnly: boolean;
}

export interface DockerContainerNetwork {
  name: string;
  ipv4: string | null;
  ipv6: string | null;
  /** Alias en esa red (QoL-5b; el servicio de compose, el id corto…). */
  aliases?: string[];
}

/** Volumen de Docker; va en `facts.docker` del asset `volume`. Nunca `Options` ni `Labels`. */
export interface DockerVolumeFacts {
  name: string;
  driver: string;
  scope: string | null;
  mountpoint: string | null;
  createdAt: string | null;
  discoveredAt: string;
}

export interface DockerNetworkSubnet {
  subnet: string;
  gateway: string | null;
}

/** Red de Docker; va en `facts.docker` del asset `network`. Nunca `Options` ni `Labels`. */
export interface DockerNetworkFacts {
  id: string;
  name: string;
  driver: string;
  scope: string | null;
  internal: boolean;
  subnets: DockerNetworkSubnet[];
  createdAt: string | null;
  discoveredAt: string;
}

// --- Plesk (DESIGN §8): en `facts.plesk` (y `facts.certificate`). Nunca contraseñas. ---

export interface PleskSubscriptionFacts {
  /** Dominio principal (el nombre de la suscripción). */
  name: string;
  /** Estado de Plesk: 0 = activa; otro valor = suspendida o deshabilitada. */
  status: number;
  active: boolean;
  /** Login del propietario en Plesk (cliente o revendedor). */
  owner: string | null;
  createdAt: string | null;
  discoveredAt: string;
}

export const PLESK_DOMAIN_KINDS = [
  'subscription',
  'addon',
  'subdomain',
  'alias',
] as const;
export type PleskDomainKind = (typeof PLESK_DOMAIN_KINDS)[number];

export interface PleskDomainFacts {
  name: string;
  kind: PleskDomainKind;
  /** `vrt_hst` (hosting), `std_fwd`/`frm_fwd` (redirección), `none`. */
  hostingType: string | null;
  status: number;
  active: boolean;
  subscription: string;
  /** Dominio padre (subdominios y alias). */
  parent: string | null;
  createdAt: string | null;
  discoveredAt: string;
}

export interface PleskDatabaseFacts {
  name: string;
  /** `mysql`, `postgresql`, `mssql`. */
  engine: string;
  /** Servidor de bases de datos (`localhost:3306`). */
  server: string | null;
  domain: string;
  discoveredAt: string;
}

/** Certificado TLS (parte pública); va en `facts.certificate`. Nunca la clave privada ni el CSR. */
export interface CertificateFacts {
  /** Nombre en el repositorio de Plesk. */
  name: string;
  subject: string | null;
  /** Nombres alternativos (`DNS:…`, `IP Address:…`). */
  subjectAltNames: string[];
  issuer: string | null;
  notBefore: string | null;
  notAfter: string | null;
  /** SHA-256 del certificado (`AA:BB:…`). */
  fingerprint256: string | null;
  selfSigned: boolean;
  letsEncrypt: boolean;
  /** Dominios que lo usan. */
  usedBy: string[];
  /** Dónde está: repositorio de un dominio o el del servidor (`admin`). */
  repository: string;
  discoveredAt: string;
}

/**
 * Id de deduplicación de `asset.discover` en la cola `discovery`. Tiene que ser distinto del de
 * `asset.collect` (el id del asset): el descubrimiento se encola mientras la recolección del
 * mismo asset sigue en curso.
 */
export function discoveryDeduplicationId(assetId: string): string {
  return `discover:${assetId}`;
}

export interface AssetDiscoverJobData {
  assetId: string;
  trigger?: InventoryTrigger;
}

export interface AssetDiscoverJobResult {
  assetId: string;
  /** Roles cuyos descubridores se ejecutaron (p. ej. `proxmox-node`, `docker-host`). */
  discoverers: string[];
  created: number;
  updated: number;
  /** Hijos que estaban en otro nodo (migración) y ahora cuelgan de este. */
  reparented: number;
  /** Claves naturales renombradas (nodo que se unió a un clúster). */
  renamed: number;
  missing: number;
  reactivated: number;
  /** Desaparecidos que llevan `RECONCILE_RETIRE_AFTER` descubrimientos sin verse: retirados. */
  retired?: number;
  /** Recolecciones encoladas (CT en marcha). */
  collectQueued: number;
  /** Escaneos de imágenes encolados (imágenes aún sin escanear). */
  scanQueued: number;
  /** Ids de las recolecciones encoladas (o de las que ya estaban en cola). */
  collectJobIds: string[];
  /** Ids de los escaneos encolados (o de los que ya estaban en cola). */
  scanJobIds: string[];
  /** false si el listado no se completó: entonces no se marca nada como `missing`. */
  complete: boolean;
  warnings: string[];
}
