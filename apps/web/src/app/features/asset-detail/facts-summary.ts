import {
  DOMAIN_PROVIDERS,
  portExposure,
  type PortExposure,
  byCodeUnit,
  type SshdAuthFacts,
  type AssetFacts,
  type CollectedFacts,
  type CollectedPackage,
  type CollectedPort,
  type CollectedService,
  type CertificateFacts,
  type CollectionMeta,
  type ConnectorFacts,
  type DnsRecordFacts,
  type DnsTlsFacts,
  type RegistrationFacts,
  type ZoneFacts,
  type DockerContainerFacts,
  type DockerContainerNetwork,
  type DockerMount,
  type DockerNetworkFacts,
  type DockerVolumeFacts,
  type MachineIdClone,
  type ProxmoxGuestFacts,
} from '@infraward/shared-types';

export interface SummaryItem {
  label: string;
  value: string;
}

/** Facts de una imagen (`facts.image`, los registra el escaneo). */
interface ImageFacts {
  imageId?: string;
  platform?: string | null;
  repoTags?: string[];
}

type Facts = Partial<CollectedFacts> & {
  proxmox?: Partial<ProxmoxGuestFacts>;
  docker?: Partial<DockerContainerFacts>;
  image?: ImageFacts;
};

/** Lista de pares etiqueta/valor: lo que no esté (o tenga un tipo inesperado) no sale. */
class Items {
  readonly list: SummaryItem[] = [];
  add(label: string, value: unknown): void {
    const t = text(value);
    if (t) this.list.push({ label, value: t });
  }
}

/**
 * Sistema: SO, CPU y memoria (los de la recolección o, en un CT/VM, los que asigna Proxmox) y el
 * software detectado. Los facts son JSONB libre: todo se lee de forma defensiva.
 */
export function systemItems(facts: AssetFacts): SummaryItem[] {
  const f = facts as Facts;
  const items = new Items();
  if (isPresent(f.os)) {
    items.add(
      'Sistema',
      join(' ', [f.os.distribution, f.os.version]) || f.os.family,
    );
    items.add('Kernel', join(' · ', [f.os.kernel, f.os.arch]));
  }
  if (isPresent(f.hardware)) {
    const hw = f.hardware;
    const cpus = hw.vcpus ?? hw.cpus;
    items.add(
      'CPU',
      join(' · ', [
        typeof cpus === 'number' ? `${cpus} vCPU` : null,
        hw.processor,
      ]),
    );
    if (typeof hw.memoryMb === 'number')
      items.add('Memoria', formatMb(hw.memoryMb));
    items.add('Virtualización', hw.virtualization);
    items.add('Fabricante', join(' · ', [hw.vendor, hw.product]));
  }
  if (isPresent(f.proxmox)) {
    const px = f.proxmox;
    items.add(
      'Proxmox',
      join(' ', [
        px.kind === 'lxc' ? 'CT' : px.kind === 'qemu' ? 'VM' : null,
        px.vmid,
      ]) + (text(px.node) ? ` en ${px.node}` : ''),
    );
    items.add(
      'Recursos asignados',
      join(' · ', [
        typeof px.cpus === 'number' ? `${px.cpus} vCPU` : null,
        typeof px.maxMemBytes === 'number'
          ? `${formatBytes(px.maxMemBytes)} RAM`
          : null,
        typeof px.maxDiskBytes === 'number'
          ? `${formatBytes(px.maxDiskBytes)} disco`
          : null,
      ]),
    );
    if (typeof px.uptime === 'number' && px.uptime > 0)
      items.add('En marcha desde hace', formatDuration(px.uptime));
  }
  if (isPresent(f.detected)) {
    items.add(
      'Software detectado',
      join(' · ', [f.detected.proxmox, f.detected.docker, f.detected.plesk]),
    );
  }
  return items.list;
}

/** Red: hostname, IP por defecto e interfaces con IPv4 (sin loopback ni las virtuales de Docker). */
export function networkItems(facts: AssetFacts): SummaryItem[] {
  const f = facts as Facts;
  const items = new Items();
  if (isPresent(f.network)) {
    items.add('Hostname', f.network.fqdn || f.network.hostname);
    items.add('IPv4 por defecto', f.network.defaultIpv4);
    items.add('Interfaces', interfacesText(f.network.interfaces));
  } else if (isPresent(f.proxmox)) {
    items.add('Interfaces', interfacesText(f.proxmox.interfaces));
  }
  return items.list;
}

/** Contenedor: imagen, estado, puertos y compose (y, en Podman, pod, unidad y usuario rootless). */
export function containerItems(facts: AssetFacts): SummaryItem[] {
  const d = (facts as Facts).docker;
  const items = new Items();
  if (!isPresent(d)) return items.list;
  const podman = d.engine === 'podman';
  items.add('Imagen', d.image);
  items.add(podman ? 'Estado en Podman' : 'Estado en Docker', d.state);
  items.add('Puertos', Array.isArray(d.ports) ? dockerPorts(d.ports) : null);
  items.add('Compose', d.composeProject);
  if (podman) {
    items.add('Pod', d.pod);
    items.add('Unidad de systemd', d.systemdUnit);
    items.add('Usuario (rootless)', d.rootlessUser);
  }
  items.add('Plataforma', d.platform);
  items.add('Arrancado', formatDate(d.startedAt));
  return items.list;
}

/** Imagen: tags, image ID y plataforma. */
export function imageItems(facts: AssetFacts): SummaryItem[] {
  const i = (facts as Facts).image;
  const items = new Items();
  if (!isPresent(i)) return items.list;
  items.add('Tags', Array.isArray(i.repoTags) ? i.repoTags.join(', ') : null);
  items.add('Image ID', i.imageId);
  items.add('Plataforma', i.platform);
  return items.list;
}

/** Montajes de un contenedor (sesión 14; los facts anteriores no los tienen). */
export function containerMounts(facts: AssetFacts): DockerMount[] {
  const d = (facts as Facts).docker;
  return isPresent(d) ? arrayOf<DockerMount>(d.mounts) : [];
}

/** Redes de un contenedor con sus IP. */
export function containerNetworks(facts: AssetFacts): DockerContainerNetwork[] {
  const d = (facts as Facts).docker;
  return isPresent(d) ? arrayOf<DockerContainerNetwork>(d.networks) : [];
}

/** Volumen de Docker (`facts.docker` de un asset `volume`). */
export function volumeItems(facts: AssetFacts): SummaryItem[] {
  const v = facts['docker'] as Partial<DockerVolumeFacts> | undefined;
  const items = new Items();
  if (!isPresent(v)) return items.list;
  items.add('Driver', v.driver);
  items.add('Ámbito', v.scope);
  items.add('Punto de montaje', v.mountpoint);
  items.add('Usuario (rootless)', v.rootlessUser);
  items.add('Creado', formatDate(v.createdAt));
  return items.list;
}

/** Red de Docker (`facts.docker` de un asset `network`). */
export function dockerNetworkItems(facts: AssetFacts): SummaryItem[] {
  const n = facts['docker'] as Partial<DockerNetworkFacts> | undefined;
  const items = new Items();
  if (!isPresent(n)) return items.list;
  items.add('Driver', n.driver);
  items.add('Ámbito', n.scope);
  items.add('Interna', n.internal ? 'sí (sin salida al exterior)' : null);
  items.add('Usuario (rootless)', n.rootlessUser);
  items.add(
    'Subredes',
    arrayOf<{ subnet?: string; gateway?: string | null }>(n.subnets)
      .map((s) => (s.gateway ? `${s.subnet} (gw ${s.gateway})` : s.subnet))
      .join(', '),
  );
  items.add('Creada', formatDate(n.createdAt));
  return items.list;
}

const PLESK_DOMAIN_KIND_LABELS: Record<string, string> = {
  subscription: 'Principal de la suscripción',
  addon: 'Dominio adicional',
  subdomain: 'Subdominio',
  alias: 'Alias',
};

const PLESK_HOSTING_LABELS: Record<string, string> = {
  vrt_hst: 'Hosting web',
  std_fwd: 'Redirección',
  frm_fwd: 'Redirección con marco',
  none: 'Sin hosting',
};

/** Suscripción, dominio o base de datos de Plesk (`facts.plesk`). Nunca contraseñas. */
export function pleskItems(facts: AssetFacts): SummaryItem[] {
  const p = facts['plesk'] as Record<string, unknown> | undefined;
  const items = new Items();
  if (!isPresent(p)) return items.list;
  if (typeof p['kind'] === 'string')
    items.add('Tipo', PLESK_DOMAIN_KIND_LABELS[p['kind']] ?? p['kind']);
  if (typeof p['hostingType'] === 'string')
    items.add(
      'Hosting',
      PLESK_HOSTING_LABELS[p['hostingType']] ?? p['hostingType'],
    );
  if (typeof p['active'] === 'boolean')
    items.add(
      'Estado en Plesk',
      p['active']
        ? 'Activo'
        : `Suspendido o deshabilitado (${String(p['status'])})`,
    );
  items.add('Suscripción', p['subscription']);
  items.add('Dominio padre', p['parent']);
  items.add('Propietario', p['owner']);
  items.add('Motor', p['engine']);
  items.add('Servidor', p['server']);
  items.add('Dominio', p['domain']);
  items.add('Alta', formatDate(p['createdAt']));
  return items.list;
}

/** Certificado TLS (`facts.certificate`): nunca la clave privada. */
export function certificateItems(facts: AssetFacts): SummaryItem[] {
  const c = facts['certificate'] as Partial<CertificateFacts> | undefined;
  const items = new Items();
  if (!isPresent(c)) return items.list;
  items.add('Sujeto', c.subject);
  items.add(
    'Nombres',
    Array.isArray(c.subjectAltNames) ? c.subjectAltNames.join(', ') : null,
  );
  items.add('Emisor', c.issuer);
  items.add('Válido desde', formatDate(c.notBefore));
  items.add('Válido hasta', formatDate(c.notAfter));
  items.add(
    'Tipo',
    c.letsEncrypt ? "Let's Encrypt" : c.selfSigned ? 'Autofirmado' : null,
  );
  items.add('Lo usan', Array.isArray(c.usedBy) ? c.usedBy.join(', ') : null);
  items.add(
    c.repository === 'tls' ? 'Origen' : 'Repositorio',
    c.repository === 'admin'
      ? 'Del servidor'
      : c.repository === 'tls'
        ? 'Leído en el 443 de sus registros DNS'
        : c.repository,
  );
  items.add('SHA-256', c.fingerprint256);
  return items.list;
}

/** Conector de dominios (`facts.connector`): nunca el token. */
export function connectorItems(facts: AssetFacts): SummaryItem[] {
  const c = facts['connector'] as Partial<ConnectorFacts> | undefined;
  const items = new Items();
  if (!isPresent(c)) return items.list;
  items.add('Proveedor', c.kind ? (DOMAIN_PROVIDERS[c.kind]?.label ?? c.kind) : null);
  const v = c.verify;
  if (v) {
    items.add('Token', v.ok ? `válido (${v.tokenStatus ?? 'activo'})` : `no válido: ${v.error}`);
    items.add('Cuentas', v.accounts?.join(', '));
    items.add('Probado', formatDate(v.checkedAt));
    items.add('Caduca el token', formatDate(v.tokenExpiresAt));
  }
  const s = c.lastSync;
  if (s) {
    items.add('Última sincronización', `${formatDate(s.at)}${s.complete ? '' : ' (parcial)'}`);
    items.add('Zonas y registros', `${s.zones} · ${s.records}`);
  }
  return items.list;
}

const RDAP_STATUS_LABELS: Record<string, string> = {
  'client transfer prohibited': 'transferencia bloqueada',
  'client delete prohibited': 'borrado bloqueado',
  'client update prohibited': 'cambios bloqueados',
  active: 'activo',
};

/** Dominio de un conector: la zona (`facts.zone`) y su registro por RDAP (`facts.registration`). */
export function zoneItems(facts: AssetFacts): SummaryItem[] {
  const z = facts['zone'] as Partial<ZoneFacts> | undefined;
  const r = facts['registration'] as Partial<RegistrationFacts> | undefined;
  const items = new Items();
  if (isPresent(r)) {
    if (r.state === 'unsupported')
      items.add('Caducidad', 'sin RDAP para este TLD (no se puede consultar)');
    else if (r.state === 'error') items.add('Caducidad', `RDAP: ${r.error}`);
    else items.add('Caduca el', formatDate(r.expiresAt));
    items.add('Registrador', r.registrar);
    items.add('Registrado el', formatDate(r.registeredAt));
    items.add(
      'Estados',
      r.statuses?.map((st) => RDAP_STATUS_LABELS[st] ?? st).join(', '),
    );
    items.add('Consultado (RDAP)', formatDate(r.checkedAt));
  }
  if (isPresent(z)) {
    items.add(
      'Proveedor DNS',
      z.provider ? (DOMAIN_PROVIDERS[z.provider]?.label ?? z.provider) : null,
    );
    items.add(
      'Estado en el proveedor',
      `${z.status ?? '—'}${z.paused ? ' (en pausa)' : ''}`,
    );
    items.add('Nameservers', z.nameServers?.join(', '));
    items.add('Plan', z.plan);
    items.add('Cuenta', z.account);
  }
  return items.list;
}

/** Registro DNS (`facts.dns`) y la lectura de su 443 (`facts.tls`). */
export function dnsRecordItems(facts: AssetFacts): SummaryItem[] {
  const d = facts['dns'] as Partial<DnsRecordFacts> | undefined;
  const t = facts['tls'] as Partial<DnsTlsFacts> | null | undefined;
  const items = new Items();
  if (!isPresent(d)) return items.list;
  items.add('Nombre', d.name);
  items.add('Tipo', d.type);
  items.add('Valor', `${d.content ?? ''}${d.truncated ? ' (cortado)' : ''}`);
  items.add('TTL', d.ttl === 1 ? 'automático' : d.ttl ? `${d.ttl} s` : null);
  items.add('Prioridad', d.priority);
  if (d.provider === 'cloudflare')
    items.add('Proxy de Cloudflare', d.proxied ? 'sí (el público ve el borde de Cloudflare)' : 'no');
  if (isPresent(t)) {
    if (t.status === 'ok')
      items.add(
        'TLS en el 443',
        [
          t.authorized ? 'cadena válida' : `cadena no válida (${t.authorizationError})`,
          t.hostnameMatch === false ? 'el certificado no cubre el nombre' : null,
        ]
          .filter(Boolean)
          .join(' · '),
      );
    else if (t.status === 'error') items.add('TLS en el 443', t.error);
    items.add('Leído', formatDate(t.checkedAt));
  }
  return items.list;
}

/** Recolección: cuándo y cómo. */
export function collectionItems(facts: AssetFacts): SummaryItem[] {
  const meta = (facts as Facts).infraward;
  const items = new Items();
  if (!isPresent(meta)) return items.list;
  items.add('Última recolección', formatDate(meta.collectedAt));
  items.add('Vía', meta.via === 'pct' ? 'pct exec (desde el nodo)' : meta.via);
  return items.list;
}

/**
 * Servicios del sistema base que no dicen nada del papel del servidor (y los `pve-container@`,
 * que ya salen como hijos). Se comparan sin el sufijo `.service`.
 */
export const NOISE_SERVICES: readonly (string | RegExp)[] = [
  /^systemd-/,
  /^(console-|container-|serial-)?getty(@|$)/,
  /^user@/,
  /^user-runtime-dir@/,
  /^pve-container@/,
  /^lxc-monitord$/,
  /^pve-lxc-syscalld$/,
  'apparmor',
  'cron',
  'dbus',
  'dm-event',
  'ksmtuned',
  'lxcfs',
  'nfs-blkmap',
  'procps',
  'qmeventd',
  'rrdcached',
  'pvefw-logger',
  'watchdog-mux',
  'wtmpdb-update-boot',
  'polkit',
  'rsyslog',
  'unattended-upgrades',
  'networking',
  'chrony',
  'irqbalance',
];

export interface ServiceSummary {
  /** En marcha y relevantes, sin `.service` ni duplicados (SysV + systemd). */
  relevant: string[];
  /** Cuántos en marcha se han ocultado por ser del sistema base. */
  hidden: number;
}

export function runningServices(
  services: readonly CollectedService[],
): ServiceSummary {
  const names = new Set(
    services
      .filter((s) => s.state === 'running' && typeof s.name === 'string')
      .map((s) => s.name.replace(/\.service$/, '')),
  );
  const relevant = [...names].filter(
    (n) =>
      !NOISE_SERVICES.some((p) =>
        typeof p === 'string' ? p === n : p.test(n),
      ),
  );
  relevant.sort(byCodeUnit);
  return { relevant, hidden: names.size - relevant.length };
}

export type { PortExposure };
const EXPOSURE_RANK: Record<PortExposure, number> = {
  all: 0,
  address: 1,
  local: 2,
};

export interface ListeningPort {
  port: number;
  proto: string;
  process: string | null;
  addresses: string[];
  /** La más abierta de sus direcciones. */
  exposure: PortExposure;
  /** Solo escucha en loopback (127.x, ::1). */
  localOnly: boolean;
}

/**
 * Puertos en escucha agrupados por puerto, protocolo y proceso (IPv4 e IPv6 juntos): primero los
 * expuestos en todas las interfaces, luego los de una IP concreta y al final los locales.
 */
export function listeningPorts(
  ports: readonly CollectedPort[],
): ListeningPort[] {
  const byKey = new Map<string, ListeningPort>();
  for (const p of ports) {
    if (typeof p.port !== 'number') continue;
    const key = `${p.port}/${p.proto}/${p.process ?? ''}`;
    const entry = byKey.get(key) ?? {
      port: p.port,
      proto: p.proto,
      process: p.process ?? null,
      addresses: [],
      exposure: 'local',
      localOnly: true,
    };
    if (p.address && !entry.addresses.includes(p.address))
      entry.addresses.push(p.address);
    const exposure = portExposure(p.address);
    if (EXPOSURE_RANK[exposure] < EXPOSURE_RANK[entry.exposure])
      entry.exposure = exposure;
    entry.localOnly = entry.exposure === 'local';
    byKey.set(key, entry);
  }
  return [...byKey.values()].sort(
    (a, b) =>
      EXPOSURE_RANK[a.exposure] - EXPOSURE_RANK[b.exposure] ||
      a.port - b.port ||
      a.proto.localeCompare(b.proto),
  );
}

function interfacesText(value: unknown): string | null {
  if (!Array.isArray(value)) return null;
  const parts = value.filter(isObject).flatMap((i) => {
    const name = text(i['name']);
    const ips = Array.isArray(i['ipv4'])
      ? i['ipv4'].map(text).filter(Boolean)
      : [];
    if (!name || !ips.length || /^(lo|docker\d*|br-|veth)/.test(name))
      return [];
    return [`${name} ${ips.join(', ')}`];
  });
  return parts.length ? parts.join(' · ') : null;
}

function dockerPorts(ports: unknown[]): string | null {
  const seen = new Set<string>();
  for (const p of ports.filter(isObject)) {
    seen.add(
      typeof p['hostPort'] === 'number'
        ? `${p['hostPort']}→${p['containerPort']}/${p['proto']}`
        : `${p['containerPort']}/${p['proto']}`,
    );
  }
  return seen.size ? [...seen].join(', ') : null;
}

/** `facts.sshd` validado (JSON libre; sudoers v7) o null. */
export function sshdFacts(facts: AssetFacts): SshdAuthFacts | null {
  const v = facts['sshd'];
  if (
    !isObject(v) ||
    typeof v['permitRootLogin'] !== 'string' ||
    typeof v['passwordAuthentication'] !== 'boolean' ||
    typeof v['kbdInteractiveAuthentication'] !== 'boolean'
  )
    return null;
  return {
    permitRootLogin: v['permitRootLogin'],
    passwordAuthentication: v['passwordAuthentication'],
    kbdInteractiveAuthentication: v['kbdInteractiveAuthentication'],
  };
}

/** Metadatos de la última recolección (avisos, sudoers) si los hay. */
export function collectionMeta(facts: AssetFacts): CollectionMeta | null {
  const meta = facts['infraward'];
  if (!isObject(meta)) return null;
  return {
    ...(meta as unknown as CollectionMeta),
    sudoersOutdated: meta['sudoersOutdated'] === true,
    warnings: Array.isArray(meta['warnings'])
      ? meta['warnings'].filter((w): w is string => typeof w === 'string')
      : [],
    machineIdClone: machineIdClone(meta['machineIdClone']),
    sudoersNotes: Array.isArray(meta['sudoersNotes'])
      ? meta['sudoersNotes'].filter((n): n is string => typeof n === 'string')
      : [],
  };
}

/** `facts.infraward.machineIdClone` validado (JSON libre). */
function machineIdClone(value: unknown): MachineIdClone | null {
  if (!isObject(value) || typeof value['machineId'] !== 'string') return null;
  const shared = Array.isArray(value['sharedWith']) ? value['sharedWith'] : [];
  return {
    machineId: value['machineId'],
    sharedWith: shared.filter(
      (s): s is { id: string; name: string } =>
        isObject(s) &&
        typeof s['id'] === 'string' &&
        typeof s['name'] === 'string',
    ),
  };
}

export function factsPackages(facts: AssetFacts): CollectedPackage[] {
  return arrayOf<CollectedPackage>(facts['packages']);
}

export function factsServices(facts: AssetFacts): CollectedService[] {
  return arrayOf<CollectedService>(facts['services']);
}

export function factsPorts(facts: AssetFacts): CollectedPort[] {
  return arrayOf<CollectedPort>(facts['ports']);
}

function arrayOf<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value.filter(isObject) as T[]) : [];
}

/** Como `isObject`, pero conserva el tipo esperado del fact (que puede no cumplirse: JSONB libre). */
function isPresent<T>(value: T | null | undefined): value is T {
  return isObject(value);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'string' && value.trim()) return value.trim();
  return null;
}

function join(sep: string, parts: unknown[]): string {
  return parts.map(text).filter(Boolean).join(sep);
}

function formatMb(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GiB` : `${mb} MiB`;
}

function formatBytes(bytes: number): string {
  return formatMb(Math.round(bytes / 1024 / 1024));
}

function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3600);
  if (days) return `${days} d ${hours} h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours ? `${hours} h ${minutes} min` : `${minutes} min`;
}

function formatDate(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? null
    : date.toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'medium' });
}
