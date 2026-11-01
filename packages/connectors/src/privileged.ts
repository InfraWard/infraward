import {
  CONTAINER_FORMAT,
  IMAGE_FORMAT,
  NETWORK_FORMAT,
  VOLUME_FORMAT,
} from './docker/formats.js';
import { PLESK_QUERIES } from './plesk/queries.js';
import {
  PODMAN_CONTAINER_FORMAT,
  PODMAN_IMAGE_FORMAT,
  PODMAN_NETWORK_FORMAT,
  PODMAN_POD_FORMAT,
  PODMAN_VOLUME_FORMAT,
} from './podman/formats.js';
import { PODMAN_USERS_SCRIPT } from './podman/podman-users.js';
import { PROCESS_PACKAGES_SCRIPT } from './processes/process-packages.js';
import { SSHD_AUTH_SCRIPT } from './sshd/sshd-auth.js';
import { NGINX_DUMP, NGINX_ROUTES_SCRIPT } from './proxies/nginx-filter.js';

/**
 * Ayudante de root que instala el script de alta (sudoers v4, DESIGN §7). El sudoers permite
 * SOLO este binario; él admite una lista cerrada de consultas, valida cada argumento y ejecuta el
 * comando real sin shell en medio. Así vale igual con sudo clásico y con sudo-rs (Ubuntu ≥ 25.10),
 * que no admite comodines, espacios ni expresiones regulares en los argumentos del sudoers.
 *
 * Esta tabla es la fuente de verdad: el ayudante de `ansible/enroll/enroll.sh.tmpl` tiene que
 * hacer exactamente lo mismo (un test de la API lo ejecuta con binarios falsos y compara).
 */
export const INFRAWARD_QUERY_HELPER =
  '/usr/local/libexec/infraward/infraward-query';
/** Ayudante de Plesk del sudoers v3: el script de alta y la baja lo borran. */
export const LEGACY_PLESK_QUERY_HELPER =
  '/usr/local/libexec/infraward/plesk-query';
/** Código de salida del ayudante cuando rechaza una consulta o un argumento. */
export const QUERY_REJECTED_EXIT = 64;

/** Máximo de ids o nombres por llamada a `docker inspect` (el conector trocea; con Podman, sin contar el ámbito). */
export const MAX_INSPECT_ARGS = 256;

/** Validaciones de argumentos (las mismas expresiones en el ayudante). */
export const QUERY_ARG = {
  /** Nombre de nodo de Proxmox. */
  node: /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/,
  /** vmid de Proxmox (100 a 999999999). */
  vmid: /^[1-9]\d{2,8}$/,
  guestKind: /^(?:lxc|qemu)$/,
  containerId: /^[0-9a-f]{64}$/,
  imageId: /^sha256:[0-9a-f]{64}$/,
  /** Nombres de volumen y de red de Docker (sin `-` inicial: no cuelan opciones). */
  dockerName: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$/,
  /**
   * Ámbito de Podman (v8): `root` (rootful) o el uid de un usuario rootless. El ayudante exige
   * además que el uid sea de un usuario de `/etc/infraward/podman-users`.
   */
  podmanScope: /^(?:root|[1-9][0-9]{0,9})$/,
} as const;

/** Socket de Podman de un usuario rootless (`systemctl --user enable --now podman.socket`). */
export function podmanUserSocket(uid: string): string {
  return `/run/user/${uid}/podman/podman.sock`;
}

/**
 * `sh -c PODMAN_AS_USER_SCRIPT sh <uid> <comando…>`: el comando como el usuario de ese uid
 * (`runuser`, con sus grupos). El ayudante lleva el mismo texto (un test compara los comandos).
 */
export const PODMAN_AS_USER_SCRIPT =
  'u=$(id -nu "$1") || exit 125; shift; exec runuser -u "$u" -- "$@"';

/**
 * `podman` en un ámbito: como root, el propio CLI (Podman no tiene demonio: ve el almacén de
 * root); de un usuario rootless, el CLI en modo remoto contra el socket de ese usuario y
 * **ejecutado como ese usuario**: el socket y lo que responde son suyos, así que el cliente no
 * corre como root (un enlace al socket de root o un servidor falso no le dan nada que no tenga).
 */
export function podmanArgv(scope: string, ...args: string[]): string[] {
  return scope === 'root'
    ? ['podman', ...args]
    : [
        'sh',
        '-c',
        PODMAN_AS_USER_SCRIPT,
        'sh',
        scope,
        'env',
        `XDG_RUNTIME_DIR=/run/user/${scope}`,
        'podman',
        '--remote',
        '--url',
        `unix://${podmanUserSocket(scope)}`,
        ...args,
      ];
}

const PVESH_GET = ['pvesh', 'get'];
/** `sh -c <filtro> sh <comando…>`: el filtro de nginx corre en el servidor (v5). */
const nginxRoutes = (...command: string[]) => [
  'sh',
  '-c',
  NGINX_ROUTES_SCRIPT,
  'sh',
  ...command,
];
const PVESH_JSON = ['--output-format', 'json'];
const pleskDb = (q: keyof typeof PLESK_QUERIES) => [
  'plesk',
  'db',
  '-B',
  '-N',
  '-r',
  '-e',
  PLESK_QUERIES[q],
];

interface QuerySpec {
  /** Argumentos: mínimo y máximo. */
  arity: readonly [number, number];
  /** Expresión de cada posición; la última se repite para el resto. null = sin validar. */
  args: readonly (RegExp | null)[];
  /** Comando real con los argumentos ya validados. */
  argv: (args: readonly string[]) => string[];
}

const fixed = (...argv: string[]): QuerySpec => ({
  arity: [0, 0],
  args: [],
  argv: () => argv,
});
const many = (prefix: string[], pattern: RegExp): QuerySpec => ({
  arity: [1, MAX_INSPECT_ARGS],
  args: [pattern],
  argv: (args) => [...prefix, ...args],
});
/** Consulta de Podman (v8): el ámbito y nada más. */
const podman = (...args: string[]): QuerySpec => ({
  arity: [1, 1],
  args: [QUERY_ARG.podmanScope],
  argv: ([scope]) => podmanArgv(scope, ...args),
});
/** Consulta de Podman con el ámbito y de 1 a `MAX_INSPECT_ARGS` ids o nombres. */
const podmanMany = (args: string[], pattern: RegExp): QuerySpec => ({
  arity: [2, MAX_INSPECT_ARGS + 1],
  args: [QUERY_ARG.podmanScope, pattern],
  argv: ([scope, ...rest]) => podmanArgv(scope, ...args, ...rest),
});

/**
 * Lista CERRADA de consultas del ayudante. Solo lectura, salvo `pct-exec` (root dentro de un CT
 * del nodo, para recogerlo con Ansible: el ayudante valida el vmid, no el comando).
 */
export const PRIVILEGED_QUERIES = {
  'dmidecode-system': fixed('dmidecode', '-t', 'system'),
  ss: fixed('ss', '-Htulpn'),
  pveversion: fixed('pveversion'),
  'pve-cluster-status': fixed(...PVESH_GET, '/cluster/status', ...PVESH_JSON),
  'pve-cluster-resources': fixed(
    ...PVESH_GET,
    '/cluster/resources',
    '--type',
    'vm',
    ...PVESH_JSON,
  ),
  'pve-guest-config': {
    arity: [3, 3],
    args: [QUERY_ARG.guestKind, QUERY_ARG.node, QUERY_ARG.vmid],
    argv: ([kind, node, vmid]) => [
      ...PVESH_GET,
      `/nodes/${node}/${kind}/${vmid}/config`,
      ...PVESH_JSON,
    ],
  },
  'pve-lxc-interfaces': {
    arity: [2, 2],
    args: [QUERY_ARG.node, QUERY_ARG.vmid],
    argv: ([node, vmid]) => [
      ...PVESH_GET,
      `/nodes/${node}/lxc/${vmid}/interfaces`,
      ...PVESH_JSON,
    ],
  },
  'pct-exec': {
    arity: [2, Number.MAX_SAFE_INTEGER],
    args: [QUERY_ARG.vmid, null],
    argv: ([vmid, ...command]) => ['pct', 'exec', vmid, '--', ...command],
  },
  'docker-version': fixed('docker', 'info', '--format', '{{.ServerVersion}}'),
  'docker-ps': fixed('docker', 'ps', '-a', '-q', '--no-trunc'),
  'docker-inspect-containers': many(
    ['docker', 'inspect', '--format', CONTAINER_FORMAT],
    QUERY_ARG.containerId,
  ),
  'docker-images': fixed('docker', 'images', '-q', '--no-trunc'),
  'docker-image-inspect': many(
    ['docker', 'image', 'inspect', '--format', IMAGE_FORMAT],
    QUERY_ARG.imageId,
  ),
  'docker-volumes': fixed('docker', 'volume', 'ls', '-q'),
  'docker-volume-inspect': many(
    ['docker', 'inspect', '--type', 'volume', '--format', VOLUME_FORMAT],
    QUERY_ARG.dockerName,
  ),
  'docker-networks': fixed('docker', 'network', 'ls', '--format', '{{.Name}}'),
  'docker-network-inspect': many(
    ['docker', 'inspect', '--type', 'network', '--format', NETWORK_FORMAT],
    QUERY_ARG.dockerName,
  ),
  'docker-save': {
    arity: [1, 1],
    args: [QUERY_ARG.imageId],
    argv: ([id]) => ['docker', 'save', id],
  },
  // v8: Podman. El ámbito (`root` o el uid de un usuario rootless de la lista) va siempre primero.
  'podman-version': fixed('podman', 'info', '--format', '{{.Version.Version}}'),
  'podman-users': fixed('sh', '-c', PODMAN_USERS_SCRIPT, 'sh'),
  'podman-ps': podman('ps', '-a', '-q', '--no-trunc'),
  'podman-inspect-containers': podmanMany(
    ['container', 'inspect', '--format', PODMAN_CONTAINER_FORMAT],
    QUERY_ARG.containerId,
  ),
  'podman-pods': podman('pod', 'ps', '--no-trunc', '--format', PODMAN_POD_FORMAT),
  'podman-images': podman('images', '-q', '--no-trunc'),
  'podman-image-inspect': podmanMany(
    ['image', 'inspect', '--format', PODMAN_IMAGE_FORMAT],
    QUERY_ARG.imageId,
  ),
  'podman-volumes': podman('volume', 'ls', '-q'),
  'podman-volume-inspect': podmanMany(
    ['volume', 'inspect', '--format', PODMAN_VOLUME_FORMAT],
    QUERY_ARG.dockerName,
  ),
  'podman-networks': podman('network', 'ls', '--format', '{{.Name}}'),
  'podman-network-inspect': podmanMany(
    ['network', 'inspect', '--format', PODMAN_NETWORK_FORMAT],
    QUERY_ARG.dockerName,
  ),
  'podman-save': {
    arity: [2, 2],
    args: [QUERY_ARG.podmanScope, QUERY_ARG.imageId],
    // A la salida estándar, como `docker save` (docker-archive: lo que lee Trivy).
    argv: ([scope, id]) =>
      podmanArgv(scope, 'save', '--format', 'docker-archive', id),
  },
  'podman-nginx-routes': {
    arity: [2, 2],
    args: [QUERY_ARG.podmanScope, QUERY_ARG.containerId],
    argv: ([scope, id]) =>
      nginxRoutes(...podmanArgv(scope, 'exec', id), ...NGINX_DUMP),
  },
  // v5 (QoL-5b): rutas de nginx/NPM filtradas en el servidor (solo nombres y destinos).
  'nginx-routes': { ...fixed(), argv: () => nginxRoutes(...NGINX_DUMP) },
  'docker-nginx-routes': {
    arity: [1, 1],
    args: [QUERY_ARG.containerId],
    argv: ([id]) => nginxRoutes('docker', 'exec', id, ...NGINX_DUMP),
  },
  // v6 (sesión 19): paquetes de los procesos en marcha, calculados en el servidor.
  'process-packages': fixed('sh', '-c', PROCESS_PACKAGES_SCRIPT, 'sh'),
  // v7 (QoL-7): autenticación efectiva de sshd (`sshd -T`), filtrada en el servidor.
  'sshd-auth': fixed('sh', '-c', SSHD_AUTH_SCRIPT, 'sh'),
  'plesk-version': fixed('plesk', 'version'),
  'plesk-domains': { ...fixed(), argv: () => pleskDb('domains') },
  'plesk-aliases': { ...fixed(), argv: () => pleskDb('aliases') },
  'plesk-databases': { ...fixed(), argv: () => pleskDb('databases') },
  'plesk-certificates': { ...fixed(), argv: () => pleskDb('certificates') },
} as const satisfies Record<string, QuerySpec>;
export type PrivilegedQueryName = keyof typeof PRIVILEGED_QUERIES;

/** Una consulta al ayudante: nombre y argumentos (se validan antes de ejecutar nada). */
export interface PrivilegedQuery {
  name: PrivilegedQueryName;
  args?: readonly string[];
}

export class QueryRejectedError extends Error {}

/** Valida una consulta como el ayudante; lanza `QueryRejectedError` si no la admitiría. */
export function validateQuery(query: PrivilegedQuery): string[] {
  const spec = (PRIVILEGED_QUERIES as Record<string, QuerySpec>)[query.name];
  if (!spec || !Object.hasOwn(PRIVILEGED_QUERIES, query.name))
    throw new QueryRejectedError(`consulta desconocida: ${query.name}`);
  const args = [...(query.args ?? [])];
  const [min, max] = spec.arity;
  if (args.length < min || args.length > max)
    throw new QueryRejectedError(
      `${query.name}: número de argumentos no válido`,
    );
  args.forEach((arg, i) => {
    const pattern = spec.args[Math.min(i, spec.args.length - 1)];
    if (pattern && !pattern.test(arg))
      throw new QueryRejectedError(
        `${query.name}: argumento ${i + 1} no válido`,
      );
  });
  return args;
}

/** Comando real de una consulta (lo que ejecuta el ayudante como root). */
export function expandQuery(query: PrivilegedQuery): string[] {
  const args = validateQuery(query);
  return (PRIVILEGED_QUERIES[query.name] as QuerySpec).argv(args);
}

/** argv para el servidor: `<ayudante> <consulta> <args…>` (con `sudo -n` delante). */
export function helperArgv(query: PrivilegedQuery): string[] {
  return [INFRAWARD_QUERY_HELPER, query.name, ...validateQuery(query)];
}

/** Trocea una lista de ids o nombres para `docker inspect` (máx. `MAX_INSPECT_ARGS`). */
export function chunks<T>(items: readonly T[], size = MAX_INSPECT_ARGS): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size)
    out.push(items.slice(i, i + size));
  return out;
}

/**
 * ¿Rechazó sudo (clásico o sudo-rs) o el ayudante el comando? Pasa con un sudoers anterior a la
 * v4 (sin el ayudante) o con un alta manual: el resultado es parcial, no un fallo del servidor.
 */
export function isSudoDenial(stderr: string, code?: number | null): boolean {
  return (
    code === QUERY_REJECTED_EXIT ||
    /password is required|interactive authentication is required|not allowed to execute|may not run|not in the sudoers|infraward-query: rechazado|I'm sorry .* can't do that/i.test(
      stderr,
    )
  );
}
