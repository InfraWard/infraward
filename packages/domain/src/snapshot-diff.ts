import type {
  AssetFacts,
  SnapshotChange,
  SnapshotChangeSummary,
  SnapshotDiff,
} from '@infraward/shared-types';

/**
 * Rutas de los facts que cambian solas, sin que cambie nada del asset (DESIGN §10): no cuentan
 * como cambio ni salen en el diff. `*` = cualquier elemento de una lista o clave de un objeto.
 * Un test exige que cada una exista en los facts de ejemplo de su tipo.
 */
export const VOLATILE_FACT_PATHS: readonly { path: string; why: string }[] = [
  { path: 'infraward.collectedAt', why: 'fecha de cada recolección' },
  { path: 'mounts.*.availableBytes', why: 'espacio libre: cambia con el uso' },
  { path: 'ports.*.pid', why: 'el PID cambia al reiniciar el proceso' },
  { path: 'processes.*.pid', why: 'el PID cambia al reiniciar el proceso (los paquetes sí cuentan)' },
  { path: 'proxmox.uptime', why: 'tiempo en marcha' },
  { path: 'proxy.readAt', why: 'fecha de cada lectura de nginx (las rutas sí cuentan)' },
  {
    path: 'docker.proxy.readAt',
    why: 'fecha de cada lectura del nginx del contenedor (las rutas sí cuentan)',
  },
  { path: 'proxmox.discoveredAt', why: 'fecha de cada descubrimiento' },
  {
    path: 'proxmox.config.lock',
    why: 'candado temporal de Proxmox (copias, migraciones)',
  },
  { path: 'docker.discoveredAt', why: 'fecha de cada descubrimiento' },
  {
    path: 'docker.startedAt',
    why: 'cambia en cada reinicio (el estado sí cuenta)',
  },
  { path: 'plesk.discoveredAt', why: 'fecha de cada descubrimiento' },
  { path: 'certificate.discoveredAt', why: 'fecha de cada descubrimiento' },
  { path: 'zone.discoveredAt', why: 'fecha de cada sincronización del conector' },
  { path: 'dns.discoveredAt', why: 'fecha de cada sincronización del conector' },
  {
    path: 'registration.checkedAt',
    why: 'fecha de la última consulta RDAP (el resultado sí cuenta)',
  },
  {
    path: 'tls.checkedAt',
    why: 'fecha de la última lectura del 443 (el resultado sí cuenta)',
  },
  {
    path: 'connector.verify.checkedAt',
    why: 'fecha de la última prueba del token (el resultado sí cuenta)',
  },
  { path: 'connector.lastSync.at', why: 'fecha de cada sincronización' },
];

/** Interfaces virtuales que crea Docker: `veth…` (una por contenedor), `docker0` y `br-<id>`. */
const DOCKER_INTERFACE = /^(veth[0-9a-f]+|docker0|br-[0-9a-f]{12})$/;

/**
 * Servicios de systemd que se activan bajo demanda por D-Bus (la propia recolección los despierta
 * al leer la hora, el hostname o el idioma) y se paran solos al rato.
 */
const ON_DEMAND_SERVICE =
  /^(systemd-(timedated|hostnamed|localed)|dbus-org\.freedesktop\.(timedate1|hostname1|locale1))\.service$/;

/**
 * Elementos de listas que no cuentan (se quitan antes de comparar), con su porqué. Un test exige
 * que cada lista exista en los facts de ejemplo y que el elemento se ignore.
 */
export const VOLATILE_LIST_ITEMS: readonly {
  path: string;
  match: (item: Record<string, unknown>) => boolean;
  why: string;
}[] = [
  {
    path: 'network.interfaces',
    match: (i) => DOCKER_INTERFACE.test(String(i.name)),
    why: 'interfaces de Docker: cambian de nombre y MAC al reiniciar contenedores (las redes de Docker ya son assets)',
  },
  {
    path: 'proxmox.interfaces',
    match: (i) => DOCKER_INTERFACE.test(String(i.name)),
    why: 'interfaces de Docker dentro del CT, igual que en la recolección',
  },
  {
    path: 'services',
    match: (s) => ON_DEMAND_SERVICE.test(String(s.name)),
    why: 'servicios de systemd bajo demanda (timedated, hostnamed, localed): se encienden y apagan solos',
  },
];

/**
 * Listas de objetos que se comparan por clave (no por posición): así un paquete actualizado sale
 * como `packages[openssl:amd64].version` y no como media lista cambiada. Las listas de valores
 * simples se comparan como conjuntos.
 */
const KEYED_LISTS: readonly { path: string; key: (item: Item) => string }[] = [
  { path: 'packages', key: (p) => `${p.name}${p.arch ? `:${p.arch}` : ''}` },
  { path: 'services', key: (s) => String(s.name) },
  { path: 'ports', key: (p) => `${p.proto} ${p.address}:${p.port}` },
  {
    path: 'processes',
    key: (p) => `${p.name}|${p.unit ?? ''}|${p.exePackage ?? ''}`,
  },
  { path: 'mounts', key: (m) => String(m.mount) },
  { path: 'network.interfaces', key: (i) => String(i.name) },
  { path: 'proxmox.interfaces', key: (i) => String(i.name) },
  {
    path: 'docker.ports',
    key: (p) =>
      `${p.hostIp ?? ''}:${p.hostPort ?? ''}->${p.containerPort}/${p.proto}`,
  },
  { path: 'docker.mounts', key: (m) => String(m.destination) },
  { path: 'docker.networks', key: (n) => String(n.name) },
  { path: 'docker.subnets', key: (n) => String(n.subnet) },
  { path: 'infraward.machineIdClone.sharedWith', key: (s) => String(s.id) },
];

/** Tope de cambios guardados por snapshot (el resumen cuenta todos). */
export const MAX_SNAPSHOT_CHANGES = 2000;

type Item = Record<string, unknown>;

/** Snapshot comparable: facts y roles. */
export interface SnapshotState {
  facts: AssetFacts;
  roles: readonly string[];
}

const volatile = VOLATILE_FACT_PATHS.map((v) => v.path.split('.'));

/** `pattern` de una ruta genérica (`mounts.*.availableBytes`) contra una concreta. */
function matches(pattern: readonly string[], path: readonly string[]): boolean {
  return (
    pattern.length === path.length &&
    pattern.every((p, i) => p === '*' || p === path[i])
  );
}

function isVolatile(path: readonly string[]): boolean {
  return volatile.some((v) => matches(v, path));
}

function isObject(value: unknown): value is Item {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Ruta genérica (sin claves de lista) para buscar en `KEYED_LISTS`. */
function keyedList(path: readonly string[]) {
  const joined = path.join('.');
  return KEYED_LISTS.find((k) => k.path === joined);
}

/** Facts sin lo volátil, para comparar y para el diff. */
export function stripVolatile(facts: AssetFacts): AssetFacts {
  return strip(facts, []) as AssetFacts;
}

function strip(value: unknown, path: string[]): unknown {
  if (Array.isArray(value)) {
    const joined = path.join('.');
    const skip = VOLATILE_LIST_ITEMS.filter((v) => v.path === joined);
    return value
      .filter((v) => !(isObject(v) && skip.some((s) => s.match(v))))
      .map((v) => strip(v, [...path, '*']));
  }
  if (!isObject(value)) return value;
  const out: Item = {};
  for (const [k, v] of Object.entries(value)) {
    const next = [...path, k];
    if (isVolatile(next)) continue;
    out[k] = strip(v, next);
  }
  return out;
}

/**
 * Cambios reales de `prev` a `next` (DESIGN §10). Sin cambios ⇒ `changes` vacío: no se guarda
 * snapshot. Las rutas usan las claves concretas (`packages[openssl:amd64].version`) y el resumen
 * agrupa por sección de primer nivel.
 */
export function diffSnapshots(
  prev: SnapshotState,
  next: SnapshotState,
): SnapshotDiff {
  const all: SnapshotChange[] = [];
  diffSet('roles', [...prev.roles].sort(), [...next.roles].sort(), all);
  diffValue(stripVolatile(prev.facts), stripVolatile(next.facts), [], '', all);
  const summary = new Map<string, SnapshotChangeSummary>();
  for (const c of all) {
    const section = c.path.split(/[.[]/)[0];
    const s = summary.get(section) ?? {
      section,
      added: 0,
      removed: 0,
      changed: 0,
    };
    s[c.kind]++;
    summary.set(section, s);
  }
  return {
    changes: all.slice(0, MAX_SNAPSHOT_CHANGES),
    summary: [...summary.values()],
    truncated: all.length > MAX_SNAPSHOT_CHANGES,
  };
}

/** ¿Hay algún cambio real? */
export function hasChanges(prev: SnapshotState, next: SnapshotState): boolean {
  return diffSnapshots(prev, next).summary.length > 0;
}

function join(display: string, key: string): string {
  return display ? `${display}.${key}` : key;
}

function diffValue(
  before: unknown,
  after: unknown,
  path: string[],
  display: string,
  out: SnapshotChange[],
): void {
  if (before === undefined && after === undefined) return;
  if (before === undefined) {
    out.push({ path: display, kind: 'added', after });
    return;
  }
  if (after === undefined) {
    out.push({ path: display, kind: 'removed', before });
    return;
  }
  if (isObject(before) && isObject(after)) {
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    for (const k of [...keys].sort())
      diffValue(before[k], after[k], [...path, k], join(display, k), out);
    return;
  }
  if (Array.isArray(before) && Array.isArray(after)) {
    diffList(before, after, path, display, out);
    return;
  }
  if (!equal(before, after))
    out.push({ path: display, kind: 'changed', before, after });
}

function diffList(
  before: unknown[],
  after: unknown[],
  path: string[],
  display: string,
  out: SnapshotChange[],
): void {
  const simple = (list: unknown[]) =>
    list.every((v) => !isObject(v) && !Array.isArray(v));
  if (simple(before) && simple(after)) {
    diffSet(display, before, after, out);
    return;
  }
  const keyed = keyedList(path);
  if (!keyed || !before.every(isObject) || !after.every(isObject)) {
    if (!equal(before, after))
      out.push({ path: display, kind: 'changed', before, after });
    return;
  }
  const a = byKey(before as Item[], keyed.key);
  const b = byKey(after as Item[], keyed.key);
  const keys = new Set([...a.keys(), ...b.keys()]);
  for (const k of [...keys].sort())
    diffValue(a.get(k), b.get(k), [...path, '*'], `${display}[${k}]`, out);
}

/** Por clave; una clave repetida (dos versiones del mismo paquete) se distingue con `#n`. */
function byKey(items: Item[], key: (item: Item) => string): Map<string, Item> {
  const map = new Map<string, Item>();
  for (const item of items) {
    const base = key(item);
    let k = base;
    for (let n = 2; map.has(k); n++) k = `${base}#${n}`;
    map.set(k, item);
  }
  return map;
}

/** Listas de valores simples como conjuntos: un elemento por cambio. */
function diffSet(
  display: string,
  before: readonly unknown[],
  after: readonly unknown[],
  out: SnapshotChange[],
): void {
  const a = new Set(before.map((v) => JSON.stringify(v)));
  const b = new Set(after.map((v) => JSON.stringify(v)));
  for (const v of [...a].sort())
    if (!b.has(v))
      out.push({ path: display, kind: 'removed', before: JSON.parse(v) });
  for (const v of [...b].sort())
    if (!a.has(v))
      out.push({ path: display, kind: 'added', after: JSON.parse(v) });
}

function equal(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  return JSON.stringify(a) === JSON.stringify(b);
}
