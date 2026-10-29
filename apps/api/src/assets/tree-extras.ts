import { dnsWarningSql, scanEnabledSql } from '@infraward/domain';
import {
  sshCaOutdated,
  sshdRiskLevel,
  type AssetRuntimeState,
  type AssetType,
  type DnsCheckLevel,
  type SshAuthMode,
  type SshCaTrust,
  type SshdAuthFacts,
  type SshdRiskLevel,
} from '@infraward/shared-types';

/**
 * Lo que el árbol necesita de los facts y la conexión, leído con rutas de JSONB concretas (nunca
 * los facts completos ni las credenciales). Todo es JSON libre: se valida aquí.
 */
export interface TreeExtrasRow {
  type: AssetType;
  connection_host: unknown;
  connection_port: unknown;
  default_ipv4: unknown;
  docker_state: unknown;
  docker_ports: unknown;
  proxmox_status: unknown;
  proxmox_interfaces: unknown;
  proxmox_net0: unknown;
  sudoers_outdated: unknown;
  collection_warnings: unknown;
  duplicate_of_id: string | null;
  machine_id_clone: unknown;
  certificate_not_after: unknown;
  registration_expires_at: unknown;
  dns_warning: unknown;
  ssh_auth: SshAuthMode;
  ssh_ca: unknown;
  sshd: unknown;
  scan_enabled: boolean;
}

export const TREE_EXTRAS_SELECT = `
  a.connection->'host' AS connection_host,
  a.connection->'port' AS connection_port,
  a.facts->'network'->'defaultIpv4' AS default_ipv4,
  a.facts->'docker'->'state' AS docker_state,
  a.facts->'docker'->'ports' AS docker_ports,
  a.facts->'proxmox'->'status' AS proxmox_status,
  a.facts->'proxmox'->'interfaces' AS proxmox_interfaces,
  a.facts->'proxmox'->'config'->'net0' AS proxmox_net0,
  a.facts->'infraward'->'sudoersOutdated' AS sudoers_outdated,
  a.duplicate_of_id,
  a.facts->'infraward'->'machineIdClone' AS machine_id_clone,
  a.facts->'certificate'->'notAfter' AS certificate_not_after,
  a.facts->'registration'->'expiresAt' AS registration_expires_at,
  (SELECT c.level FROM dns_record_checks c
    WHERE c.asset_id = a.id AND ${dnsWarningSql('c')}) AS dns_warning,
  a.ssh_auth,
  a.facts->'infraward'->'sshCa' AS ssh_ca,
  a.facts->'sshd' AS sshd,
  ${scanEnabledSql('a')} AS scan_enabled,
  CASE WHEN jsonb_typeof(a.facts->'infraward'->'warnings') = 'array'
       THEN jsonb_array_length(a.facts->'infraward'->'warnings') END AS collection_warnings`;

export interface TreeExtras {
  address: string | null;
  ips: string[];
  runtimeState: AssetRuntimeState | null;
  runtimeDetail: string | null;
  sudoersOutdated: boolean;
  collectionWarnings: number;
  duplicateOf: string | null;
  machineIdClone: boolean;
  expiresAt: string | null;
  dnsWarning: DnsCheckLevel | null;
  sshCaOutdated: boolean;
  sshdRisk: SshdRiskLevel | null;
  scanDisabled: boolean;
}

/**
 * `caFingerprints`: huellas de las CA vigentes en el proveedor (vacío = sin referencia: no se
 * avisa de CA desactualizada).
 */
export function treeExtras(
  row: TreeExtrasRow,
  caFingerprints: readonly string[] = [],
): TreeExtras {
  const detail = str(row.docker_state) ?? str(row.proxmox_status);
  const warnings = Number(row.collection_warnings);
  return {
    address: treeAddress(row),
    ips: treeIps(row),
    runtimeState: detail ? runtimeState(detail) : null,
    runtimeDetail: detail,
    sudoersOutdated: row.sudoers_outdated === true,
    collectionWarnings:
      Number.isInteger(warnings) && warnings > 0 ? warnings : 0,
    duplicateOf: row.duplicate_of_id ?? null,
    machineIdClone: isObject(row.machine_id_clone),
    expiresAt:
      row.type === 'certificate'
        ? isoDate(row.certificate_not_after)
        : row.type === 'domain'
          ? isoDate(row.registration_expires_at)
          : null,
    dnsWarning:
      row.dns_warning === 'high' || row.dns_warning === 'info'
        ? row.dns_warning
        : null,
    sshCaOutdated:
      row.ssh_auth === 'ca_certificate' &&
      sshCaOutdated(sshCaTrust(row.ssh_ca), caFingerprints),
    sshdRisk: sshdRiskLevel(sshdFacts(row.sshd)),
    scanDisabled: row.scan_enabled === false,
  };
}

/** `facts.sshd` validado (JSON libre). */
export function sshdFacts(value: unknown): SshdAuthFacts | null {
  if (!value || typeof value !== 'object') return null;
  const v = value as Record<string, unknown>;
  if (
    typeof v.permitRootLogin !== 'string' ||
    typeof v.passwordAuthentication !== 'boolean' ||
    typeof v.kbdInteractiveAuthentication !== 'boolean'
  )
    return null;
  return {
    permitRootLogin: v.permitRootLogin,
    passwordAuthentication: v.passwordAuthentication,
    kbdInteractiveAuthentication: v.kbdInteractiveAuthentication,
  };
}

/** `facts.infraward.sshCa` validado (JSON libre). */
export function sshCaTrust(value: unknown): SshCaTrust | null {
  if (!value || typeof value !== 'object') return null;
  const { version, trusted } = value as Record<string, unknown>;
  return {
    version: typeof version === 'number' ? version : null,
    trusted: Array.isArray(trusted)
      ? trusted.filter((t): t is string => typeof t === 'string')
      : [],
  };
}

/** Estado de Docker (`running`, `exited`, `created`…) o de Proxmox (`running`, `stopped`…). */
export function runtimeState(state: string): AssetRuntimeState {
  switch (state.toLowerCase()) {
    case 'running':
      return 'running';
    case 'paused':
    case 'suspended':
      return 'paused';
    // `created`: el contenedor existe pero nunca arrancó (o se recreó sin arrancar).
    case 'stopped':
    case 'exited':
    case 'created':
    case 'dead':
      return 'stopped';
    default:
      return 'other';
  }
}

/**
 * Cómo se llega al asset: puertos publicados de un contenedor, host de conexión de un servidor
 * enrolado (con el puerto si no es el 22, y su IPv4 si es otra) o la IPv4 del equipo.
 */
export function treeAddress(row: TreeExtrasRow): string | null {
  if (row.type === 'image') return null;
  if (row.type === 'container') return dockerPorts(row.docker_ports);
  const host = str(row.connection_host);
  if (host) {
    const port = row.connection_port;
    const target =
      typeof port === 'number' && port !== 22 ? `${host}:${port}` : host;
    // Tras un NAT o un túnel, la IP propia distingue servidores con la misma conexión.
    const own = str(row.default_ipv4);
    return own && own !== host ? `${target} · ${own}` : target;
  }
  return (
    str(row.default_ipv4) ??
    interfaceIpv4(row.proxmox_interfaces) ??
    staticIpv4(row.proxmox_net0)
  );
}

/**
 * IPs para la búsqueda `ip:` (DESIGN §15): el host de conexión si es una IP, la IPv4 por defecto,
 * las de las interfaces reales de Proxmox y la fija de `net0`.
 */
export function treeIps(row: TreeExtrasRow): string[] {
  if (row.type === 'image') return [];
  const host = str(row.connection_host);
  const ips = [
    host && isIp(host) ? host : null,
    str(row.default_ipv4),
    ...interfaceIpv4s(row.proxmox_interfaces),
    staticIpv4(row.proxmox_net0),
  ];
  return [...new Set(ips.filter((ip): ip is string => !!ip))];
}

function isIp(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^[0-9a-f:]+$/i.test(host);
}

/** `8080→80/tcp, 53/udp`: IPv4 e IPv6 del mismo puerto salen una vez; los solo expuestos, sin host. */
function dockerPorts(value: unknown): string | null {
  if (!Array.isArray(value)) return null;
  const seen = new Set<string>();
  for (const p of value) {
    if (!isObject(p) || typeof p['containerPort'] !== 'number') continue;
    const proto = str(p['proto']) ?? 'tcp';
    const host = p['hostPort'];
    seen.add(
      typeof host === 'number'
        ? `${host}→${p['containerPort']}/${proto}`
        : `${p['containerPort']}/${proto}`,
    );
  }
  // Los publicados antes que los solo expuestos.
  const list = [...seen].sort(
    (a, b) => Number(!a.includes('→')) - Number(!b.includes('→')),
  );
  return list.length ? list.join(', ') : null;
}

const VIRTUAL_IFACE =
  /^(lo|docker\d*|br-|veth|virbr|cni|flannel|cali|tailscale|wg)/;

/** Primera IPv4 de una interfaz real del CT (sin loopback, puentes de Docker ni veth). */
function interfaceIpv4(value: unknown): string | null {
  return interfaceIpv4s(value)[0] ?? null;
}

/** Las IPv4 de las interfaces reales del CT, en orden. */
function interfaceIpv4s(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const found: string[] = [];
  for (const iface of value) {
    if (!isObject(iface) || VIRTUAL_IFACE.test(str(iface['name']) ?? ''))
      continue;
    const ips = Array.isArray(iface['ipv4']) ? iface['ipv4'] : [];
    for (const ip of ips) {
      const addr = str(ip)?.split('/')[0];
      if (addr && !addr.startsWith('127.')) found.push(addr);
    }
  }
  return found;
}

/** IP fija de `net0` (`…,ip=192.168.1.5/24,…`); `dhcp` no dice nada. */
function staticIpv4(value: unknown): string | null {
  const match = /(?:^|,)ip=(\d{1,3}(?:\.\d{1,3}){3})(?:\/\d+)?(?:,|$)/.exec(
    str(value) ?? '',
  );
  return match?.[1] ?? null;
}

function isoDate(value: unknown): string | null {
  const text = str(value);
  if (!text) return null;
  const t = Date.parse(text);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
