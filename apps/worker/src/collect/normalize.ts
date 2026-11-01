import {
  byCodeUnit,
  DETECTED_ROLES,
  requiredSudoersVersion,
  sudoersGaps,
  type CollectedFacts,
  type CollectedHardware,
  type CollectedInterface,
  type CollectedMount,
  type CollectedPackage,
  type CollectedPort,
  type CollectedService,
  type CollectionVia,
  type DetectedRole,
  type CollectedProcess,
  type SshdAuthFacts,
  type ProxyFacts,
  type SshCaTrust,
  type PodmanRootlessUser,
} from '@infraward/shared-types';
import {
  isSudoDenial,
  parsePodmanUsers,
  podmanRootlessWarnings,
  parseSshdAuth,
  parseNginxRoutes,
  parseProcessPackages,
} from '@infraward/connectors';
import { sshPublicKeyFingerprint } from '@infraward/secrets';

/** Resultado de un comando `sudo -n …` del playbook (registro de un bucle de Ansible). */
export interface RawSudoResult {
  item: { key: string };
  rc?: number;
  stdout?: string;
  stderr?: string;
  skipped?: boolean;
}

/** JSON que escribe `ansible/collect/collect.yml` en el tmpfs del job. */
export interface RawCollection {
  facts: Record<string, unknown>;
  packages: Record<string, RawPackage[]> | null;
  packagesError?: string | null;
  /** Primera línea: gestor (`dpkg`, `rpm`, `apk`); resto, un paquete por línea. */
  nativePackages?: string[] | null;
  services: Record<string, RawService> | null;
  servicesError?: string | null;
  /** `<binario>=<ruta>` de los binarios presentes. */
  which: string[];
  sudo: RawSudoResult[];
  /** `netstat -tulpn` si no hay `ss` (BusyBox o net-tools). */
  netstat?: { rc: number; stdout: string; stderr: string } | null;
  /** `# <tabla>` + contenido de `/proc/net/{tcp,tcp6,udp,udp6}` si no hay `ss` ni `netstat`. */
  procNet?: string | null;
  sudoersVersion: string;
  /** Contenido de /etc/ssh/infraward/trusted_user_ca_keys ('' si no existe: modo estático). */
  sshCaKeys?: string;
  /** `pct` si se recogió un CT desde su nodo (versiones anteriores del playbook: ausente). */
  via?: CollectionVia;
}

interface RawPackage {
  name: string;
  version: string;
  release?: string;
  epoch?: number | string | null;
  arch?: string;
  source?: string;
}

interface RawService {
  name: string;
  state: string;
  status?: string;
}

const MAX_WARNING = 200;

/** Convierte la salida bruta del playbook en los `facts` normalizados de un servidor. */
export function normalizeCollection(
  raw: RawCollection,
  now: Date = new Date(),
): CollectedFacts {
  const warnings: string[] = [];
  const via: CollectionVia = raw.via === 'pct' ? 'pct' : 'ssh';
  const f = raw.facts ?? {};
  const present = new Set(
    (raw.which ?? []).map((l) => l.split('=')[0]).filter(Boolean),
  );
  const sudo = new Map((raw.sudo ?? []).map((r) => [r.item?.key, r]));

  // Comandos con sudo: un fallo no aborta la recolección, se anota.
  const ok = (key: string): string | null => {
    const r = sudo.get(key);
    if (!r || r.skipped || r.rc === undefined) return null;
    if (r.rc === 0) return r.stdout ?? '';
    const stderr = (r.stderr ?? '').trim();
    if (isSudoDenial(stderr, r.rc)) {
      warnings.push(
        `sudo denegado para '${key}': alta manual o sudoers desactualizado`,
      );
    } else if (key !== 'docker' && key !== 'podman') {
      warnings.push(
        `'${key}' falló (código ${r.rc})${stderr ? `: ${clip(firstLine(stderr))}` : ''}`,
      );
    }
    return null;
  };

  const pveversion = ok('pveversion');
  const pleskVersion = ok('plesk');
  const dockerVersion = ok('docker');
  const podmanVersion = ok('podman');
  const ssOutput = ok('ss');
  const dmidecode = ok('dmidecode');

  // Con podman-docker, `docker` es Podman y `docker info` no tiene `ServerVersion`: no es un
  // demonio caído, lo inventaría el descubridor de Podman.
  if (present.has('docker') && dockerVersion === null && !present.has('podman'))
    warnings.push('docker está instalado pero el demonio no responde');
  if (present.has('podman') && podmanVersion === null && !podmanDenied(sudo.get('podman')))
    warnings.push('podman está instalado pero no responde (podman info)');
  const podmanUsers = podmanRootless(sudo.get('podman_users'));
  if (podmanUsers) warnings.push(...podmanRootlessWarnings({ detected: podmanUsers }));
  const ports = collectPorts(raw, present, ssOutput, warnings);

  const sudoersVersion = /^\d{1,6}$/.test((raw.sudoersVersion ?? '').trim())
    ? Number(raw.sudoersVersion.trim())
    : null;
  // Un CT recogido con `pct exec` no tiene sudoers propio: se entra como root desde el nodo.
  // Si está desactualizado depende de los roles del asset: lo decide `checkSudoers`.
  if (via === 'ssh' && sudoersVersion === null)
    warnings.push(
      'sin sudoers de InfraWard (alta manual): la recolección es parcial',
    );

  const packages = normalizePackages(raw);
  if (!packages)
    warnings.push(
      `no se pudo obtener la lista de paquetes${raw.packagesError ? `: ${clip(raw.packagesError)}` : ''}`,
    );
  const services = normalizeServices(raw.services);
  if (!services)
    warnings.push('no se pudo obtener la lista de servicios (¿sin systemd?)');

  return {
    machineId: str(f.machine_id),
    os: {
      family: str(f.os_family),
      distribution: str(f.distribution),
      version: str(f.distribution_version),
      kernel: str(f.kernel),
      arch: str(f.architecture),
    },
    hardware: normalizeHardware(f, dmidecode),
    mounts: normalizeMounts(f.mounts),
    network: {
      hostname: str(f.hostname),
      fqdn: str(f.fqdn),
      defaultIpv4: str(record(f.default_ipv4)?.address),
      interfaces: normalizeInterfaces(f),
    },
    packages: packages ?? [],
    services: services ?? [],
    ports,
    detected: {
      // DESIGN §8: basta con que exista pveversion / plesk; Docker tiene que responder.
      proxmox: present.has('pveversion')
        ? firstLine(pveversion ?? '') || 'desconocida'
        : null,
      plesk: present.has('plesk')
        ? firstLine(pleskVersion ?? '') || 'desconocida'
        : null,
      docker: dockerVersion?.trim() ? firstLine(dockerVersion) : null,
      // Podman no tiene demonio: basta con que esté. Sin la v8 (no se puede preguntar la
      // versión) también, para que el aviso del sudoers diga que hay que actualizarlo.
      podman: present.has('podman')
        ? firstLine(podmanVersion ?? '') || 'desconocida'
        : null,
      ...(present.has('podman') && podmanUsers ? { podmanUsers } : {}),
    },
    infraward: {
      collectedAt: now.toISOString(),
      via,
      sudoersVersion,
      sudoersOutdated: false,
      sshCa: via === 'ssh' ? parseSshCaKeys(raw.sshCaKeys ?? '') : null,
      warnings,
    },
    ...nginxProxy(sudo.get('nginx'), now),
    ...processPackages(sudo.get('processes')),
    ...sshdAuth(sudo.get('sshd')),
  };
}

/** ¿Rechazó sudo (o el ayudante, sudoers anterior a la v8) `podman info`? */
function podmanDenied(r: RawSudoResult | undefined): boolean {
  return !!r && !r.skipped && r.rc !== undefined && isSudoDenial((r.stderr ?? '').trim(), r.rc);
}

/**
 * Usuarios con Podman rootless detectados (sudoers v8): habilitados o no, con sus señales. Sin la
 * v8 (denegado) no se sabe: lo dice el aviso del sudoers (null).
 */
function podmanRootless(r: RawSudoResult | undefined): PodmanRootlessUser[] | null {
  if (!r || r.skipped || r.rc !== 0) return null;
  return parsePodmanUsers(r.stdout ?? '').detected;
}

/**
 * Autenticación efectiva de sshd (sudoers v7, QoL-7), ya filtrada en el servidor. Como la v6, no
 * cuenta como recolección parcial: sin ella lo dice la nota del sudoers. null si no se pudo leer
 * (sudoers anterior, sin sshd o salida que no se entiende): entonces no se avisa.
 */
function sshdAuth(r: RawSudoResult | undefined): { sshd?: SshdAuthFacts | null } {
  if (!r || r.skipped || r.rc === undefined) return {};
  return { sshd: r.rc === 0 ? parseSshdAuth(r.stdout ?? '') : null };
}

/**
 * Paquetes de los procesos en marcha (sudoers v6), ya calculados en el servidor. Como la v5, no
 * cuenta como recolección parcial: sin ella lo dice la nota y la prioridad lo indica.
 */
function processPackages(
  r: RawSudoResult | undefined,
): { processes?: CollectedProcess[] | null } {
  if (!r || r.skipped || r.rc === undefined) return {};
  return { processes: r.rc === 0 ? parseProcessPackages(r.stdout ?? '') : null };
}

/**
 * Rutas del nginx del sistema (QoL-5b), ya filtradas en el servidor. No cuenta como recolección
 * parcial: sin la v5 lo dice la nota del sudoers y el camino del dominio se corta ahí.
 */
function nginxProxy(
  r: RawSudoResult | undefined,
  now: Date,
): { proxy?: ProxyFacts | null } {
  if (!r || r.skipped || r.rc === undefined) return {};
  return { proxy: r.rc === 0 ? parseNginxRoutes(r.stdout ?? '', 'nginx', now) : null };
}

/**
 * Avisos y notas del sudoers según los roles del asset (detectados o puestos a mano), todo desde
 * la tabla `SUDOERS_CAPABILITIES` (DESIGN §14): «sudoers desactualizado» si falta alguna
 * capacidad `outdated` (un servidor sin Docker con la v1 está al día) y notas informativas por
 * las `note`. Solo en servidores con el sudoers de InfraWard (ni CT por pct exec ni altas
 * manuales). Idempotente (no repite el aviso).
 */
export function checkSudoers(facts: CollectedFacts, roles: string[]): void {
  const meta = facts.infraward;
  const applies = meta.via === 'ssh' && meta.sudoersVersion !== null;
  const gaps = applies
    ? sudoersGaps(roles, meta.sudoersVersion)
    : { outdated: [], notes: [] };
  meta.sudoersOutdated = gaps.outdated.length > 0;
  meta.sudoersNotes = gaps.notes;
  meta.warnings = meta.warnings.filter(
    (w) => !w.startsWith('sudoers desactualizado'),
  );
  if (meta.sudoersOutdated) {
    meta.warnings.push(
      `sudoers desactualizado (v${meta.sudoersVersion}, hace falta v${requiredSudoersVersion(roles)}): genera un comando de actualización`,
    );
  }
}

/** Roles detectados (§8) a partir de los facts normalizados. */
export function detectRoles(facts: CollectedFacts): DetectedRole[] {
  const roles: DetectedRole[] = [];
  if (facts.detected.proxmox) roles.push('proxmox-node');
  if (facts.detected.plesk) roles.push('plesk');
  if (facts.detected.docker) roles.push('docker-host');
  if (facts.detected.podman) roles.push('podman-host');
  return roles;
}

/**
 * Sustituye los roles detectados por los nuevos y conserva los puestos a mano (los que no
 * están en `DETECTED_ROLES`).
 */
export function mergeRoles(current: string[], detected: string[]): string[] {
  const managed = new Set<string>(DETECTED_ROLES);
  const manual = current.filter((r) => !managed.has(r));
  return [...new Set([...manual, ...detected])].sort(byCodeUnit);
}

/**
 * Puertos en escucha: `ss` y, si no está (BusyBox), `netstat -tulpn` o, en último caso,
 * `/proc/net` (sin proceso). Los fallbacks se anotan en los avisos.
 */
function collectPorts(
  raw: RawCollection,
  present: Set<string>,
  ssOutput: string | null,
  warnings: string[],
): CollectedPort[] {
  if (ssOutput !== null) return parseSs(ssOutput);
  if (present.has('ss')) return [];
  if (raw.netstat?.rc === 0) {
    warnings.push("sin 'ss': puertos leídos con netstat");
    return parseNetstat(raw.netstat.stdout);
  }
  if (raw.procNet?.trim()) {
    warnings.push(
      "sin 'ss' ni 'netstat': puertos leídos de /proc/net, sin proceso",
    );
    return parseProcNet(raw.procNet);
  }
  warnings.push(
    "sin 'ss' ni 'netstat': no se pueden listar los puertos en escucha",
  );
  return [];
}

/**
 * `ss -Htulpn`: `<proto> <estado> <recv-q> <send-q> <local> <peer> [users:((…))]`.
 * Direcciones: `0.0.0.0:22`, `[::]:22`, `*:22`, `127.0.0.53%lo:53`, `[fe80::1%eth0]:123`.
 */
export function parseSs(output: string): CollectedPort[] {
  const ports: CollectedPort[] = [];
  for (const line of output.split('\n')) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 5) continue;
    const proto = cols[0];
    if (proto !== 'tcp' && proto !== 'udp') continue;
    const local = splitHostPort(cols[4]);
    if (!local) continue;
    const users = /users:\(\("((?:[^"\\]|\\.)*)",pid=(\d+)/.exec(line);
    ports.push({
      proto,
      ...local,
      process: users ? users[1].slice(0, 128) : null,
      pid: users ? Number(users[2]) : null,
    });
  }
  return sortPorts(ports);
}

/**
 * `netstat -tulpn` de BusyBox o net-tools:
 * `<proto> <recv-q> <send-q> <local> <remota> [estado] <pid>/<programa>|-`.
 * TCP solo en `LISTEN`; UDP sin estado (con estado es un socket conectado, no escucha).
 * Direcciones: `0.0.0.0:22`, `:::9999`, `::1:25`.
 */
export function parseNetstat(output: string): CollectedPort[] {
  const ports: CollectedPort[] = [];
  for (const line of output.split('\n')) {
    const cols = line.trim().split(/\s+/);
    const proto = /^(tcp|udp)6?$/.exec(cols[0] ?? '')?.[1] as
      CollectedPort['proto'] | undefined;
    if (!proto || cols.length < 5) continue;
    let rest: string[];
    if (proto === 'tcp') {
      if (cols[5] !== 'LISTEN') continue;
      rest = cols.slice(6);
    } else {
      if (cols[5] && !/^(\d+\/|-$)/.test(cols[5])) continue;
      rest = cols.slice(5);
    }
    const local = splitHostPort(cols[3]);
    if (!local) continue;
    const owner = /^(\d+)\/(.+)$/.exec(rest.join(' '));
    ports.push({
      proto,
      ...local,
      process: owner ? owner[2].slice(0, 128) : null,
      pid: owner ? Number(owner[1]) : null,
    });
  }
  return sortPorts(ports);
}

/**
 * Tablas de `/proc/net` precedidas por `# tcp`, `# tcp6`, `# udp`, `# udp6`. Direcciones en
 * hexadecimal con el orden de bytes del kernel (palabras de 32 bits en little-endian). TCP en
 * escucha = estado `0A`; UDP «en escucha» = `07` (sin conectar) con el remoto a 0.
 */
export function parseProcNet(output: string): CollectedPort[] {
  const ports: CollectedPort[] = [];
  let table: string | null = null;
  for (const line of output.split('\n')) {
    const header = /^# (tcp6?|udp6?)$/.exec(line.trim());
    if (header) {
      table = header[1];
      continue;
    }
    const cols = line.trim().split(/\s+/);
    if (!table || !/^\d+:$/.test(cols[0] ?? '') || cols.length < 4) continue;
    const proto = table.startsWith('tcp') ? 'tcp' : 'udp';
    const [localHex, remoteHex, state] = [cols[1], cols[2], cols[3]];
    if (
      proto === 'tcp'
        ? state !== '0A'
        : state !== '07' || !remoteHex.endsWith(':0000')
    )
      continue;
    const m = /^([0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):([0-9A-Fa-f]{4})$/.exec(
      localHex,
    );
    if (!m) continue;
    ports.push({
      proto,
      address: hexAddress(m[1]),
      port: Number.parseInt(m[2], 16),
      process: null,
      pid: null,
    });
  }
  return sortPorts(ports);
}

/** `ADDR` de /proc/net: cada palabra de 32 bits está en little-endian. */
function hexAddress(hex: string): string {
  const bytes = (hex.match(/.{8}/g) ?? []).flatMap((word) =>
    (word.match(/../g) ?? []).reverse().map((b) => Number.parseInt(b, 16)),
  );
  if (bytes.length === 4) return bytes.join('.');
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i] << 8) | bytes[i + 1]);
  return formatIpv6(groups);
}

/** IPv6 en forma comprimida (RFC 5952): la racha más larga de ceros (≥ 2) se cambia por `::`. */
function formatIpv6(groups: number[]): string {
  let best = { start: -1, length: 0 };
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > best.length && j - i >= 2) best = { start: i, length: j - i };
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best.start < 0) return hex.join(':');
  const head = hex.slice(0, best.start).join(':');
  const tail = hex.slice(best.start + best.length).join(':');
  return `${head}::${tail}`;
}

function splitHostPort(
  local: string,
): Pick<CollectedPort, 'address' | 'port'> | null {
  const sep = local.lastIndexOf(':');
  if (sep <= 0) return null;
  const port = Number(local.slice(sep + 1));
  if (!Number.isInteger(port) || port < 0 || port > 65535) return null;
  return {
    address: local
      .slice(0, sep)
      .replace(/^\[(.*)\]$/, '$1')
      .replace(/%.*$/, ''),
    port,
  };
}

/** Ordena y quita duplicados (`proto|dirección|puerto`). */
function sortPorts(ports: CollectedPort[]): CollectedPort[] {
  const seen = new Set<string>();
  return ports
    .filter((p) => {
      const key = `${p.proto}|${p.address}|${p.port}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort(
      (a, b) =>
        a.port - b.port || cmp(a.proto, b.proto) || cmp(a.address, b.address),
    );
}

function normalizePackages(raw: RawCollection): CollectedPackage[] | null {
  if (raw.packages && typeof raw.packages === 'object') {
    const list: CollectedPackage[] = [];
    for (const [name, versions] of Object.entries(raw.packages)) {
      for (const p of Array.isArray(versions) ? versions : []) {
        const epoch =
          p.epoch !== undefined && p.epoch !== null && String(p.epoch) !== ''
            ? `${p.epoch}:`
            : '';
        const release = p.release ? `-${p.release}` : '';
        list.push({
          name: p.name ?? name,
          version: `${epoch}${p.version ?? ''}${release}`,
          arch: str(p.arch),
          manager: str(p.source),
        });
      }
    }
    return sortPackages(list);
  }
  const lines = raw.nativePackages ?? [];
  const manager = lines[0]?.trim();
  if (!manager || lines.length < 2) return null;
  const list: CollectedPackage[] = [];
  for (const line of lines.slice(1)) {
    if (manager === 'apk') {
      const m = /^(.+)-([^-]+-r\d+)$/.exec(line.trim());
      if (m) list.push({ name: m[1], version: m[2], arch: null, manager });
      continue;
    }
    const [name, version, arch, status] = line.split('\t');
    if (!name || !version) continue;
    // dpkg: solo los instalados (`ii`); `rc` = desinstalado con configuración.
    if (status !== undefined && !status.startsWith('i')) continue;
    list.push({
      name,
      // rpm sin epoch: `0:` sobra.
      version: manager === 'rpm' ? version.replace(/^0:/, '') : version,
      arch: str(arch),
      manager,
    });
  }
  return sortPackages(list);
}

function sortPackages(list: CollectedPackage[]): CollectedPackage[] {
  return list.sort(
    (a, b) => cmp(a.name, b.name) || cmp(a.arch ?? '', b.arch ?? ''),
  );
}

function normalizeServices(
  services: Record<string, RawService> | null,
): CollectedService[] | null {
  if (!services || typeof services !== 'object') return null;
  return Object.values(services)
    .filter((s) => s && typeof s.name === 'string')
    .map((s) => ({
      name: s.name,
      state: String(s.state ?? 'unknown'),
      status: str(s.status),
    }))
    .sort((a, b) => cmp(a.name, b.name));
}

function normalizeHardware(
  f: Record<string, unknown>,
  dmidecode: string | null,
): CollectedHardware {
  const dmi = parseDmidecodeSystem(dmidecode ?? '');
  const count = num(f.processor_count);
  const coresPerSocket = num(f.processor_cores);
  return {
    vendor: dmi.Manufacturer ?? str(f.system_vendor),
    product: dmi['Product Name'] ?? str(f.product_name),
    uuid: dmi.UUID ?? str(f.product_uuid),
    serial: dmi['Serial Number'] ?? str(f.product_serial),
    virtualization:
      str(f.virtualization_role) === 'guest'
        ? str(f.virtualization_type)
        : null,
    processor: processorModel(f.processor),
    cpus: count,
    cores:
      count !== null && coresPerSocket !== null ? count * coresPerSocket : null,
    vcpus: num(f.processor_vcpus),
    memoryMb: num(f.memtotal_mb),
    swapMb: num(f.swaptotal_mb),
  };
}

/** Campos de «System Information» de `dmidecode -t system` (sin valores de relleno). */
export function parseDmidecodeSystem(output: string): Record<string, string> {
  const fields: Record<string, string> = {};
  let inSystem = false;
  for (const line of output.split('\n')) {
    if (!line.startsWith('\t')) {
      inSystem = line.trim() === 'System Information';
      continue;
    }
    if (!inSystem) continue;
    const m = /^\t([^:\t]+):\s*(.*)$/.exec(line);
    const value = m ? str(m[2]) : null;
    if (m && value) fields[m[1].trim()] = value;
  }
  return fields;
}

/** `ansible_processor` es una lista plana (`["0", "GenuineIntel", "Intel(R) …", …]`). */
function processorModel(value: unknown): string | null {
  if (!Array.isArray(value)) return null;
  const names = value.filter(
    (v): v is string => typeof v === 'string' && !/^\d+$/.test(v),
  );
  const model = [...names].sort((a, b) => b.length - a.length)[0];
  return str(model);
}

function normalizeMounts(value: unknown): CollectedMount[] {
  if (!Array.isArray(value)) return [];
  return value
    .map(record)
    .filter((m): m is Record<string, unknown> => !!m && !!str(m.mount))
    .map((m) => ({
      mount: str(m.mount)!,
      device: str(m.device) ?? '',
      fstype: str(m.fstype) ?? '',
      sizeBytes: num(m.size_total),
      availableBytes: num(m.size_available),
    }))
    .sort((a, b) => cmp(a.mount, b.mount));
}

function normalizeInterfaces(f: Record<string, unknown>): CollectedInterface[] {
  const names = Array.isArray(f.interfaces) ? f.interfaces : [];
  const result: CollectedInterface[] = [];
  for (const name of names) {
    if (typeof name !== 'string' || name === 'lo') continue;
    // Ansible guarda cada interfaz como fact con `-`, `:` y `.` cambiados por `_`.
    const data = record(f[name.replace(/[-:.]/g, '_')]);
    if (!data) continue;
    const v4 = [record(data.ipv4), ...list(data.ipv4_secondaries)]
      .filter((a): a is Record<string, unknown> => !!a && !!str(a.address))
      .map((a) => withPrefix(a));
    const v6 = list(data.ipv6)
      .filter((a): a is Record<string, unknown> => !!a && !!str(a.address))
      .map((a) => withPrefix(a));
    result.push({
      name,
      mac: str(data.macaddress),
      active: typeof data.active === 'boolean' ? data.active : null,
      ipv4: v4,
      ipv6: v6,
    });
  }
  return result.sort((a, b) => cmp(a.name, b.name));
}

function withPrefix(a: Record<string, unknown>): string {
  const prefix = str(a.prefix);
  return prefix ? `${str(a.address)}/${prefix}` : str(a.address)!;
}

function list(value: unknown): (Record<string, unknown> | null)[] {
  return Array.isArray(value) ? value.map(record) : [];
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** Texto útil o null (Ansible usa `NA` y dmidecode textos de relleno cuando no hay dato). */
function str(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const v = value.trim();
  if (
    !v ||
    /^(NA|N\/A|None|Not Specified|Not Present|To Be Filled By O\.E\.M\.|Default string)$/i.test(
      v,
    )
  )
    return null;
  return v.slice(0, 512);
}

function num(value: unknown): number | null {
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
}

function firstLine(text: string): string {
  return text.trim().split('\n')[0]?.trim() ?? '';
}

function clip(text: string): string {
  return text.length > MAX_WARNING ? `${text.slice(0, MAX_WARNING)}…` : text;
}

/** Orden ordinal: estable entre máquinas (no depende del locale). */
function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Fichero de CAs confiables que instala el script en modo CA: versión (cabecera
 * `# infraward-ssh-ca-version: <n>`) y huellas de las claves. null si no hay fichero.
 */
export function parseSshCaKeys(text: string): SshCaTrust | null {
  if (!text.trim()) return null;
  const version = /^# infraward-ssh-ca-version: (\d{1,6})$/m.exec(text);
  const trusted: string[] = [];
  for (const line of text.split('\n').map((l) => l.trim())) {
    if (!line || line.startsWith('#')) continue;
    try {
      trusted.push(sshPublicKeyFingerprint(line));
    } catch {
      // Línea que no es una clave: no cuenta como CA confiable.
    }
  }
  return { version: version ? Number(version[1]) : null, trusted };
}
