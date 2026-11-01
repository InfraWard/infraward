import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NGINX_ROUTES_SCRIPT } from '@infraward/connectors';

/** Guest de `/cluster/resources`. */
export interface FakeGuest {
  type: 'lxc' | 'qemu';
  vmid: number;
  node: string;
  name: string;
  status: string;
  template?: number;
  /** El CT tiene Docker (lo verá la recolección por pct exec). */
  docker?: boolean;
  /** Contenedores del Docker del CT (los lista el descubridor por pct exec). */
  containers?: FakeContainer[];
  /** Volúmenes, redes e imágenes sin contenedores del Docker del CT (sesión 14). */
  volumes?: string[];
  networks?: string[];
  extraImages?: FakeImage[];
  /** sudo deniega `docker volume ls` y `network ls`. */
  denyUnusedListing?: boolean;
  /** Memoria (MiB) y núcleos de su configuración (512 y 1 por defecto). */
  memory?: number;
  cores?: number;
}

/** Imagen presente en el host sin contenedores. */
export interface FakeImage {
  image: string;
  imageId: string;
  size?: number;
}

/** Docker de un servidor (no CT): lo descubre el descubridor por SSH con `sudo -n docker`. */
export type FakeDockerHost = Pick<
  FakeGuest,
  'containers' | 'volumes' | 'networks' | 'extraImages' | 'denyUnusedListing'
>;

export interface FakePodmanHost {
  /** Salida de la consulta `podman-users` (`P uid lista socket storage linger contenedores usuario`). */
  users: string;
  /** Imágenes que `podman save` de root no encuentra (se sacan del almacén rootless). */
  rootMissing?: string[];
}

/**
 * `docker-archive` de verdad (manifest, config y una capa) para una imagen del almacén rootless:
 * el worker comprueba que el config tiene el sha256 del image ID y cada capa el de su
 * `rootfs.diff_ids` (DESIGN §9), así que el image ID es el sha256 de este config. `seed` lo hace
 * distinto para cada imagen.
 */
function dockerArchive(seed: string): { imageId: string; tar: Buffer } {
  const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
  const layer = Buffer.from(`capa de ${seed}\n`);
  const config = Buffer.from(
    JSON.stringify({
      architecture: 'amd64',
      os: 'linux',
      config: { Labels: { 'infraward.test': seed } },
      rootfs: { type: 'layers', diff_ids: [`sha256:${sha(layer)}`] },
    }),
  );
  const configName = `${sha(config)}.json`;
  const manifest = Buffer.from(
    JSON.stringify([{ Config: configName, RepoTags: null, Layers: ['capa/layer.tar'] }]),
  );
  return {
    imageId: `sha256:${sha(config)}`,
    tar: tarOf([
      ['manifest.json', manifest],
      [configName, config],
      ['capa/layer.tar', layer],
    ]),
  };
}

/** Tar ustar mínimo (ficheros regulares, nombres cortos). */
function tarOf(files: [string, Buffer][]): Buffer {
  const blocks: Buffer[] = [];
  for (const [name, data] of files) {
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, 'utf8');
    header.write('0000644\0', 100, 'ascii');
    header.write('0000000\0', 108, 'ascii');
    header.write('0000000\0', 116, 'ascii');
    header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
    header.write('00000000000\0', 136, 'ascii');
    header.write('        ', 148, 'ascii');
    header.write('0', 156, 'ascii');
    header.write('ustar\0', 257, 'ascii');
    header.write('00', 263, 'ascii');
    let sum = 0;
    for (const byte of header) sum += byte;
    header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
    blocks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

const RAW_PODMAN_FIXTURES: Record<string, string> = Object.fromEntries(
  [
    'ps.txt', 'inspect.jsonl', 'pods.jsonl', 'images.txt', 'image-inspect.jsonl', 'volume-ls.txt',
    'volume-inspect.jsonl', 'network-ls.txt', 'network-inspect.jsonl', 'rootless-ps.txt',
    'rootless-inspect.jsonl', 'rootless-images.txt', 'rootless-image-inspect.jsonl',
    'rootless-volume-ls.txt', 'rootless-volume-inspect.jsonl', 'rootless-network-ls.txt',
    'rootless-network-inspect.jsonl',
  ].map((f) => [
    f,
    readFileSync(
      new URL(`../../../../packages/connectors/src/podman/fixtures/${f}`, import.meta.url),
      'utf8',
    ),
  ]),
);

/**
 * Las imágenes del almacén rootless (alpine en los fixtures) llevan, en lugar de su image ID real,
 * el de un `docker-archive` válido: el `podman save` falso de un usuario lo devuelve y la
 * verificación del worker lo acepta. Las de root siguen con el tar falso (no se verifican).
 */
const ROOTLESS_ARCHIVES = new Map(
  RAW_PODMAN_FIXTURES['rootless-images.txt']!
    .split('\n')
    .filter(Boolean)
    .map((id) => [id, dockerArchive(id)] as const),
);

/** Image ID con el que sale en los fixtures simulados una imagen de los de verdad. */
export function podmanImageId(original: string): string {
  return ROOTLESS_ARCHIVES.get(original)?.imageId ?? original;
}

/** Salidas reales de Podman 5.4.2 (las de los tests del descubridor), con esos image IDs. */
const PODMAN_FIXTURES = Object.fromEntries(
  Object.entries(RAW_PODMAN_FIXTURES).map(([file, text]) => [
    file,
    [...ROOTLESS_ARCHIVES].reduce(
      (t, [original, { imageId }]) =>
        t.replaceAll(original.slice(7), imageId.slice(7)),
      text,
    ),
  ]),
);

/** El tar de cada imagen rootless (base64), por su image ID simulado. */
const PODMAN_ARCHIVES = Object.fromEntries(
  [...ROOTLESS_ARCHIVES.values()].map((a) => [a.imageId, a.tar.toString('base64')]),
);

/** Base de datos de Plesk simulada: filas de cada consulta fija de `plesk db`. */
export interface FakePlesk {
  domains: object[];
  aliases: object[];
  databases: object[];
  certificates: object[];
  /** Consulta que falla (como un esquema distinto de `psa`). */
  fail?: 'domains' | 'aliases' | 'databases' | 'certificates';
}

/** Contenedor de Docker dentro de un CT simulado. */
export interface FakeContainer {
  name: string;
  image: string;
  /** `sha256:` + 64 hex. */
  imageId: string;
  state: string;
  /** Puertos publicados: `80/tcp` → puerto del host. */
  published?: Record<string, number>;
  /** Variable de entorno que nunca debe salir del servidor (la plantilla no la pide). */
  env?: string;
  /** Tamaño de la imagen según `docker image inspect` (1000 por defecto). */
  imageSize?: number;
  /** Volúmenes con nombre que monta (en `/data/<nombre>`). */
  mounts?: string[];
  /** Redes a las que está conectado (por defecto, `bridge`). */
  networks?: string[];
  /** IPv4 en sus redes (172.18.0.2 por defecto). */
  ip?: string;
  /** Servicio de compose (alias en sus redes). */
  composeService?: string;
  /**
   * Etiquetas: el simulado las devuelve TODAS como `proxyLabels` (peor caso: como si la plantilla
   * no filtrara); el descubridor solo puede quedarse con las de su lista blanca.
   */
  labels?: Record<string, string>;
  /** `nginx -T` del contenedor (nginx o NPM): lo filtra el filtro real del ayudante. */
  nginx?: string;
}

/** Vulnerabilidad que el Trivy falso encuentra en una imagen. */
export interface FakeVuln {
  id: string;
  pkg: string;
  version: string;
  fixed?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  /** CVSS v3 de NVD (sin él, Trivy no da CVSS). */
  cvss?: number;
  /** `Status` de Trivy (por defecto `fixed` con versión corregida y `affected` sin ella). */
  status?: string;
}

export interface FakePveState {
  node: string;
  cluster: string | null;
  machineId: string;
  /** machine-id que devuelven todos los CT (clones de una plantilla). */
  ctMachineId: string;
  guests: FakeGuest[];
  /** `pvesh get /cluster/resources` falla (nodo caído a medias). */
  failResources?: boolean;
  /** `docker ps` falla en los CT (demonio caído). */
  failDocker?: boolean;
  /** Versión del sudoers que ve la verificación del alta (4 por defecto). */
  sudoersVersion?: number;
  /** Vulnerabilidades por image ID que devuelve el Trivy falso. */
  vulns?: Record<string, FakeVuln[]>;
  /**
   * Qué detecta la recolección del servidor (no de los CT): por defecto un nodo Proxmox. Con
   * `plesk` responde a las consultas `plesk-*` del ayudante y con `docker`, a las `docker-*`.
   */
  nodeRoles?: ('proxmox' | 'plesk' | 'docker' | 'podman')[];
  /**
   * Podman del servidor (con `nodeRoles` `podman`): responde a las consultas `podman-*` con las
   * salidas reales de `packages/connectors/src/podman/fixtures` (root y, por el uid 1000, las
   * `rootless-*`); los demás uids no tienen socket.
   */
  hostPodman?: FakePodmanHost;
  /** Docker del propio servidor (con `nodeRoles` `docker`). */
  hostDocker?: FakeDockerHost;
  /** IPv4 por defecto del servidor (facts de la recolección). */
  ip?: string;
  /** Líneas de `ss -Htulpn` del servidor (por defecto, sshd en el 22). */
  ss?: string[];
  /** `nginx -T` del servidor: la recolección lo pasa por el filtro que le da el worker. */
  hostNginx?: string;
  plesk?: FakePlesk;
  /** Versión del sudoers que ve la recolección del servidor (4 por defecto). */
  collectSudoersVersion?: number;
  /**
   * Salida del script de procesos (sudoers v6) en el servidor: `P<TAB>pid<TAB>nombre<TAB>unidad
   * <TAB>paquete<TAB>librerías`. Sin ella (o con una versión menor), la consulta se deniega.
   */
  processes?: string;
  /**
   * Salida de `sshd -T` del servidor (sudoers v7): la recolección la pasa por el filtro que le da
   * el worker (`infraward_sshd_filter`) con un `sshd` falso. Con una versión menor, se deniega.
   */
  sshdConfig?: string;
  /**
   * Paquetes dpkg del servidor y de cada CT (por vmid) que lee el SBOM con `cat` (por defecto,
   * bash y openssl). Con `null`, el sistema no tiene BD de paquetes.
   */
  packages?: Record<string, FakePackage[] | null>;
  /**
   * Vulnerabilidades que el Trivy falso encuentra al evaluar el SBOM de un servidor o CT (por
   * paquete y versión). Las de las imágenes van en `vulns`.
   */
  hostVulns?: FakeVuln[];
}

/** Paquete instalado (dpkg) en un servidor o CT simulado. */
export interface FakePackage {
  name: string;
  version: string;
}

export interface FakePve {
  /** Directorio con `ssh` y `ssh-keyscan` falsos (va delante en el PATH del worker). */
  binDir: string;
  /** `ansible-playbook` falso (ANSIBLE_PLAYBOOK_BIN). */
  ansibleBin: string;
  /** Huella de la host key que devuelve el `ssh-keyscan` falso. */
  fingerprint: string;
  setState(state: FakePveState): void;
  /** Comandos que recibió el `ssh` falso (lo que se ejecutaría en el nodo). */
  sshCommands(): string[];
  /** Análisis de imágenes del Trivy falso (generación del SBOM desde el tar). */
  trivyScans(): string[][];
  /** Generaciones de SBOM de servidores y CT (`trivy rootfs`). */
  trivyRootfs(): string[][];
  /** Evaluaciones de SBOMs (`trivy sbom`). */
  trivyEvaluations(): string[][];
  /** Descargas de la base de datos del Trivy falso. */
  trivyDownloads(): string[][];
  /** Directorios de la caché de Trivy y de trabajo del escaneo del worker. */
  trivyCacheDir: string;
  scanDir: string;
  /** Entorno del worker para usar este nodo simulado (ssh, Ansible y Trivy falsos). */
  workerEnv(): Record<string, string>;
  /** Ejecuciones de Ansible: inventario y variables extra. */
  ansibleRuns(): {
    host: Record<string, unknown>;
    vars: Record<string, unknown>;
  }[];
}

/**
 * Nodo Proxmox simulado para los e2e: el worker real ejecuta estos binarios en lugar de `ssh`,
 * `ssh-keyscan` y `ansible-playbook`, y responde con el estado JSON que fija el test. Así se
 * prueban la reconciliación contra PostgreSQL, el encadenado de jobs y los argumentos exactos
 * que se mandarían al nodo (consultas al ayudante de root).
 */
export function createFakePve(): FakePve {
  const dir = mkdtempSync(join(tmpdir(), 'infraward-fake-pve-'));
  const stateFile = join(dir, 'state.json');
  const sshLog = join(dir, 'ssh.log');
  const ansibleLog = join(dir, 'ansible.log');
  const keyType = 'ssh-ed25519';
  const blob = Buffer.concat([
    u32(keyType.length),
    Buffer.from(keyType),
    u32(32),
    randomBytes(32),
  ]).toString('base64');
  const fingerprint = `SHA256:${createHash('sha256')
    .update(Buffer.from(blob, 'base64'))
    .digest('base64')
    .replace(/=+$/, '')}`;

  const shebang = `#!${process.execPath}\n`;
  const prelude = `const fs = require('node:fs');
const state = JSON.parse(fs.readFileSync(${JSON.stringify(stateFile)}, 'utf8'));
`;
  script(
    join(dir, 'ssh-keyscan'),
    `${shebang}const host = process.argv.at(-1);
process.stdout.write(host + ' ${keyType} ${blob}\\n');
`,
  );
  script(
    join(dir, 'ssh'),
    `${shebang}${prelude}
const crypto = require('node:crypto');
const hex = (v) => crypto.createHash('sha256').update(v).digest('hex');
// Docker de un CT o del propio servidor: responde como \`docker ps\`, \`inspect --format\`,
// \`images\`, \`image inspect\`, \`volume ls\`, \`network ls\` e \`inspect --type volume|network\` con
// los campos que piden las plantillas del descubridor (no las evalúa) y \`save\` con un tar falso.
// Añade \`options\` con un secreto que el descubridor nunca debe guardar.
function docker(target, rest) {
  const containers = (target && target.containers) || [];
  const extra = (target && target.extraImages) || [];
  const done = (out) => { process.stdout.write(out); process.exit(0); };
  const denied = () => { process.stderr.write('sudo: a password is required\\n'); process.exit(1); };
  const names = (s) => s.slice(s.lastIndexOf("' ") + 2).split(' ').filter(Boolean).map((n) => n.replace(/^'|'$/g, ''));
  const images = [...containers.map((c) => ({ image: c.image, imageId: c.imageId, size: c.imageSize })), ...extra];
  if (rest === 'ps -a -q --no-trunc') {
    if (state.failDocker) { process.stderr.write('Cannot connect to the Docker daemon\\n'); process.exit(1); }
    done(containers.map((c) => hex(c.name) + '\\n').join(''));
  }
  if (rest === 'images -q --no-trunc') done([...new Set(images.map((i) => i.imageId))].map((i) => i + '\\n').join(''));
  if (rest === 'volume ls -q') { if (target.denyUnusedListing) denied(); done((target.volumes || []).map((v) => v + '\\n').join('')); }
  if (rest === "network ls --format '{{.Name}}'") { if (target.denyUnusedListing) denied(); done((target.networks || []).map((n) => n + '\\n').join('')); }
  if (/^inspect --type volume --format '/.test(rest)) {
    done(names(rest).filter((n) => (target.volumes || []).includes(n)).map((n) => JSON.stringify({
      name: n, driver: 'local', scope: 'local', mountpoint: '/var/lib/docker/volumes/' + n + '/_data',
      createdAt: '2026-10-11T00:31:11Z', options: { o: 'addr=nas,password=centinela-volumen' } }) + '\\n').join(''));
  }
  if (/^inspect --type network --format '/.test(rest)) {
    done(names(rest).filter((n) => (target.networks || []).includes(n)).map((n, i) => JSON.stringify({
      id: hex('net-' + n), name: n, driver: n === 'host' ? 'host' : 'bridge', scope: 'local', internal: false,
      createdAt: '2026-10-11T00:31:11Z', subnets: [{ subnet: '172.' + (18 + i) + '.0.0/16', gateway: '172.' + (18 + i) + '.0.1' }, null] }) + '\\n').join(''));
  }
  if (/^inspect --format '/.test(rest)) {
    const ids = rest.match(/[0-9a-f]{64}/g) || [];
    done(ids.map((id) => containers.find((c) => hex(c.name) === id)).filter(Boolean).map((c) => JSON.stringify({
      id: hex(c.name), name: '/' + c.name, image: c.image, imageId: c.imageId, state: c.state,
      createdAt: '2026-10-09T22:11:05.376783787Z', startedAt: c.state === 'running' ? '2026-10-09T22:11:05.474135078Z' : '0001-01-01T00:00:00Z',
      ports: c.state === 'running' ? Object.fromEntries(Object.entries(c.published || {}).map(([k, p]) => [k, [{ HostIp: '0.0.0.0', HostPort: String(p) }]])) : {},
      bindings: Object.fromEntries(Object.entries(c.published || {}).map(([k, p]) => [k, [{ HostIp: '', HostPort: String(p) }]])),
      composeProject: null,
      composeService: c.composeService || null,
      proxyLabels: [...Object.entries(c.labels || {}), null],
      mounts: [...(c.mounts || []).map((v) => ({ type: 'volume', name: v, source: '/var/lib/docker/volumes/' + v + '/_data', destination: '/data/' + v, rw: true })), null],
      networks: [...(c.networks || ['bridge']).map((n) => ({ name: n, ipv4: c.state === 'running' ? (c.ip || '172.18.0.2') : '', ipv6: '',
        aliases: c.composeService ? [c.composeService] : null })), null] }) + '\\n').join(''));
  }
  if (/^image inspect --format '/.test(rest)) {
    const ids = rest.match(/sha256:[0-9a-f]{64}/g) || [];
    done(ids.map((id) => images.find((x) => x.imageId === id)).filter(Boolean).map((c) => JSON.stringify({
      id: c.imageId, repoDigests: [c.image.split(':')[0] + '@' + c.imageId], repoTags: [c.image], os: 'linux', architecture: 'amd64', size: c.size || 1000 })
    ).map((l) => l + '\\n').join(''));
  }
  const save = /^save (sha256:[0-9a-f]{64})$/.exec(rest);
  if (save && images.some((c) => c.imageId === save[1])) {
    done(JSON.stringify({ fakeImage: save[1], pad: 'x'.repeat(4096) }));
  }
  process.stderr.write('docker: comando no permitido: ' + rest + '\\n'); process.exit(1);
}
// Plesk: la consulta \`plesk-<nombre>\` del ayudante → filas JSON del estado (con campos de más, como
// una contraseña, que el descubridor no debe guardar).
function plesk(key) {
  if (!state.plesk || !['domains', 'aliases', 'databases', 'certificates'].includes(key)) { process.stderr.write('infraward-query: rechazado: consulta no permitida: plesk-' + key + '\\n'); process.exit(64); }
  if (state.plesk.fail === key) { process.stderr.write("ERROR 1054 (42S22) at line 1: Unknown column 'x'\\n"); process.exit(1); }
  process.stdout.write(state.plesk[key].map((r) => JSON.stringify({ ...r, passwd: 'centinela-plesk' }) + '\\n').join(''));
  process.exit(0);
}
// Podman del servidor: salidas reales (fixtures) por ámbito; root o el uid 1000 (alice).
function podman(query, qargs) {
  const FIX = ${JSON.stringify(PODMAN_FIXTURES)};
  const ARCHIVES = ${JSON.stringify(PODMAN_ARCHIVES)};
  const done = (out) => { process.stdout.write(out); process.exit(0); };
  const p = state.hostPodman || { users: '' };
  if (query === 'podman-version') done('5.4.2\\n');
  if (query === 'podman-users') done(p.users);
  const [scope, ...rest] = qargs;
  if (scope !== 'root' && scope !== '1000') {
    process.stderr.write('Error: unable to connect to Podman socket: dial unix /run/user/' + scope + '/podman/podman.sock: connect: no such file or directory\\n');
    process.exit(125);
  }
  const f = (name) => FIX[(scope === 'root' ? '' : 'rootless-') + name] || '';
  const lines = (name) => f(name).split('\\n').filter(Boolean);
  const pick = (name, key) => done(lines(name).filter((l) => rest.includes(JSON.parse(l)[key])).map((l) => l + '\\n').join(''));
  if (query === 'podman-ps') done(f('ps.txt'));
  if (query === 'podman-pods') done(scope === 'root' ? FIX['pods.jsonl'] : '');
  if (query === 'podman-images') done(f('images.txt'));
  if (query === 'podman-volumes') done(f('volume-ls.txt'));
  if (query === 'podman-networks') done(f('network-ls.txt'));
  if (query === 'podman-inspect-containers') pick('inspect.jsonl', 'id');
  if (query === 'podman-image-inspect') pick('image-inspect.jsonl', 'id');
  if (query === 'podman-volume-inspect') pick('volume-inspect.jsonl', 'name');
  if (query === 'podman-network-inspect') pick('network-inspect.jsonl', 'name');
  if (query === 'podman-save') {
    const id = rest[0];
    if (lines('images.txt').includes(id) && !(scope === 'root' && (p.rootMissing || []).includes(id))) {
      // De un usuario, un docker-archive de verdad (el worker lo verifica); de root, el tar falso.
      if (scope !== 'root' && ARCHIVES[id]) done(Buffer.from(ARCHIVES[id], 'base64'));
      done(JSON.stringify({ fakeImage: id, pad: 'x'.repeat(4096) }));
    }
    process.stderr.write('Error: ' + id + ': image not known\\n'); process.exit(125);
  }
  if (query === 'podman-nginx-routes') { process.stderr.write('infraward: nginx -T falló (127)\\n'); process.exit(3); }
  process.stderr.write('infraward-query: rechazado: consulta no simulada: ' + query + '\\n'); process.exit(64);
}
// Sistema de ficheros de un servidor o CT para el SBOM: solo lo que lee con \`ls\`/\`cat\` (sin sudo).
function files(key) {
  const pkgs = (state.packages || {})[key];
  const list = pkgs === undefined ? [{ name: 'bash', version: '5.2.37-2' }, { name: 'openssl', version: '3.5.1-1' }] : pkgs;
  const out = { '/etc/os-release': 'ID=debian\\nVERSION_ID="13"\\n', '/etc/shadow': 'root:centinela-shadow' };
  if (list) out['/var/lib/dpkg/status'] = list.map((p) => 'Package: ' + p.name + '\\nStatus: install ok installed\\nVersion: ' + p.version + '\\n').join('\\n');
  return out;
}
function readOnly(key, argv) {
  const fsys = files(key);
  if (argv[0] === 'ls' && argv[1] === '-1d' && argv[2] === '--') {
    const paths = argv.slice(3);
    const found = paths.filter((p) => p in fsys);
    process.stdout.write(found.map((p) => p + '\\n').join(''));
    process.exit(found.length < paths.length ? 2 : 0);
  }
  if (argv[0] === 'cat' && argv[1] === '--' && argv.length === 3) {
    if (!(argv[2] in fsys)) { process.stderr.write('cat: ' + argv[2] + ': No such file or directory\\n'); process.exit(1); }
    process.stdout.write(fsys[argv[2]]); process.exit(0);
  }
}
const args = process.argv.slice(2);
// Maestro del job (\`-N -f\`) y su control (\`-O check|exit\`): no ejecutan nada en el nodo.
if (args.includes('-N') || args.includes('-O')) process.exit(0);
const command = args.slice(args.indexOf('--') + 2).join(' ');
fs.appendFileSync(${JSON.stringify(sshLog)}, command + '\\n');
// Sonda de la verificación del alta: uid del usuario, versión del sudoers y del acceso de
// administración instalados (línea vacía si no lo tiene).
if (command.startsWith('id -u; cat /etc/infraward/sudoers-version 2>/dev/null')) {
  process.stdout.write('994\\n' + (state.sudoersVersion || 4) + '\\n' + (state.adminAccessVersion || '') + '\\n');
  process.exit(0);
}
// Todo lo que necesita root llega como \`sudo -n <ayudante> <consulta> <args…>\` (sudoers v4),
// entrecomillado como lo hace el worker (\`shellQuote\`).
const HELPER = 'sudo -n /usr/local/libexec/infraward/infraward-query ';
const split = (line) => {
  const out = [];
  for (const m of line.matchAll(/'((?:[^']|'\\\\'')*)'|(\\S+)/g))
    out.push(m[1] !== undefined ? m[1].replace(/'\\\\''/g, "'") : m[2]);
  return out;
};
// Sin sudo: la lectura de las BDs de paquetes del propio servidor (SBOM).
if (!command.startsWith('sudo ')) readOnly('node', split(command));
if (!command.startsWith(HELPER)) { process.stderr.write('sudo: a password is required\\n'); process.exit(1); }
const tokens = split(command.slice(HELPER.length));
const quote = (a) => (/^[A-Za-z0-9_./=:,@+-]+$/.test(a) ? a : "'" + a.replace(/'/g, "'\\\\''") + "'");
const [query, ...qargs] = tokens;
// Consultas de Docker en el formato de subcomando que entiende docker() (las plantillas no se evalúan).
const dockerRest = {
  'docker-ps': () => 'ps -a -q --no-trunc',
  'docker-images': () => 'images -q --no-trunc',
  'docker-volumes': () => 'volume ls -q',
  'docker-networks': () => "network ls --format '{{.Name}}'",
  'docker-inspect-containers': (a) => "inspect --format 'F' " + a.join(' '),
  'docker-image-inspect': (a) => "image inspect --format 'F' " + a.join(' '),
  'docker-volume-inspect': (a) => "inspect --type volume --format 'F' " + a.join(' '),
  'docker-network-inspect': (a) => "inspect --type network --format 'F' " + a.join(' '),
  'docker-save': (a) => 'save ' + a.join(' '),
};
if (query === 'pct-exec') {
  // pct exec <vmid> -- <argv real>: dentro del CT solo se simula Docker.
  const [vmid, bin, ...rest] = qargs;
  if (bin === 'ls' || bin === 'cat') readOnly(vmid, [bin, ...rest]);
  if (bin === 'docker') docker(state.guests.find((g) => g.vmid === Number(vmid)), rest.map(quote).join(' '));
  process.stderr.write('pct exec: comando no simulado: ' + bin + '\\n'); process.exit(1);
}
// v5: \`docker exec <id> nginx -T\` con el filtro real del ayudante (sh y awk del sistema).
if (query === 'docker-nginx-routes' && (state.nodeRoles || []).includes('docker')) {
  const c = ((state.hostDocker || {}).containers || []).find((x) => hex(x.name) === qargs[0]);
  if (!c || !c.nginx) { process.stderr.write('infraward: nginx -T falló (127)\\n'); process.exit(3); }
  const conf = require('node:path').join(${JSON.stringify(dir)}, 'nginx-' + c.name + '.conf');
  fs.writeFileSync(conf, c.nginx);
  const r = require('node:child_process').spawnSync('sh', ['-c', ${JSON.stringify(NGINX_ROUTES_SCRIPT)}, 'sh', 'cat', conf], { encoding: 'utf8' });
  process.stdout.write(r.stdout); process.stderr.write(r.stderr); process.exit(r.status ?? 1);
}
if (dockerRest[query] && (state.nodeRoles || []).includes('docker')) docker(state.hostDocker || {}, dockerRest[query](qargs));
if (query.startsWith('podman-') && (state.nodeRoles || []).includes('podman')) podman(query, qargs);
if (query.startsWith('plesk-') && (state.nodeRoles || []).includes('plesk')) plesk(query.slice('plesk-'.length));
const pvesh = {
  'pve-cluster-status': () => '/cluster/status',
  'pve-cluster-resources': () => '/cluster/resources',
  'pve-guest-config': ([kind, node, vmid]) => '/nodes/' + node + '/' + kind + '/' + vmid + '/config',
  'pve-lxc-interfaces': ([node, vmid]) => '/nodes/' + node + '/lxc/' + vmid + '/interfaces',
};
if (!pvesh[query]) { process.stderr.write('infraward-query: rechazado: consulta no simulada: ' + query + '\\n'); process.exit(64); }
const path = pvesh[query](qargs);
const out = (v) => { process.stdout.write(JSON.stringify(v)); process.exit(0); };
if (path === '/cluster/status') {
  const entries = [{ type: 'node', name: state.node, local: 1, online: 1, id: 'node/' + state.node }];
  if (state.cluster) entries.unshift({ type: 'cluster', name: state.cluster, id: 'cluster', quorate: 1 });
  out(entries);
}
if (path === '/cluster/resources') {
  if (state.failResources) { process.stderr.write('ipcc_send_rec[1] failed: Connection refused\\n'); process.exit(1); }
  out(state.guests.map((g) => ({ id: g.type + '/' + g.vmid, type: g.type, vmid: g.vmid, node: g.node,
    name: g.name, status: g.status, template: g.template || 0, maxcpu: g.cores || 1, maxmem: (g.memory || 512) * 1048576, maxdisk: 8589934592, uptime: Math.floor(Date.now() / 1000) % 100000 })));
}
const cfg = /^\\/nodes\\/([^/]+)\\/(lxc|qemu)\\/(\\d+)\\/(config|interfaces)$/.exec(path);
if (cfg) {
  const g = state.guests.find((x) => x.node === cfg[1] && x.type === cfg[2] && x.vmid === Number(cfg[3]));
  if (!g) { process.stderr.write('no existe\\n'); process.exit(2); }
  if (cfg[4] === 'interfaces') out([{ name: 'lo', inet: '127.0.0.1/8' }, { name: 'eth0', hwaddr: 'bc:24:11:00:00:' + g.vmid % 100, inet: '10.0.0.' + (g.vmid % 250) + '/24' }]);
  out({ hostname: g.name, memory: g.memory || 512, cores: g.cores || 1, description: 'root: hunter2', cipassword: '$5$secreto', digest: 'abc' });
}
process.stderr.write('ruta desconocida\\n'); process.exit(2);
`,
  );
  const ansibleBin = join(dir, 'ansible-playbook');
  script(
    ansibleBin,
    `${shebang}${prelude}
const args = process.argv.slice(2);
const inventory = JSON.parse(fs.readFileSync(args[args.indexOf('-i') + 1], 'utf8'));
const vars = JSON.parse(args[args.indexOf('-e') + 1]);
const host = inventory.all.hosts.target;
fs.appendFileSync(${JSON.stringify(ansibleLog)}, JSON.stringify({ host, vars }) + '\\n');
const vmid = host.infraward_pct_vmid;
const guest = vmid && state.guests.find((g) => g.vmid === vmid);
const which = ['ss=/usr/bin/ss'];
const ssLines = !vmid && state.ss ? state.ss : ['tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))'];
const sudo = [{ item: { key: 'ss' }, rc: 0, stdout: ssLines.join('\\n') }];
// nginx del servidor: el filtro que pasa el worker (\`infraward_nginx_filter\`) sobre su \`nginx -T\`.
if (!vmid && state.hostNginx) {
  which.push('nginx=/usr/sbin/nginx');
  const conf = require('node:path').join(${JSON.stringify(dir)}, 'nginx-host.conf');
  fs.writeFileSync(conf, state.hostNginx);
  const r = require('node:child_process').spawnSync('sh', ['-c', vars.infraward_nginx_filter, 'sh', 'cat', conf], { encoding: 'utf8' });
  sudo.push({ item: { key: 'nginx' }, rc: r.status, stdout: r.stdout, stderr: r.stderr });
}
// v6: paquetes de los procesos del servidor; con un sudoers anterior, el ayudante lo rechaza.
if (!vmid && state.processes !== undefined) {
  sudo.push((state.collectSudoersVersion || 4) >= 6
    ? { item: { key: 'processes' }, rc: 0, stdout: state.processes, stderr: '' }
    : { item: { key: 'processes' }, rc: 64, stdout: '', stderr: 'infraward-query: rechazado: consulta desconocida' });
}
// v7: autenticación de sshd, con el filtro de verdad sobre un \`sshd -T\` falso.
if (!vmid && state.sshdConfig !== undefined) {
  if ((state.collectSudoersVersion || 4) >= 7) {
    const bin = require('node:path').join(${JSON.stringify(dir)}, 'sshd-bin');
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(require('node:path').join(${JSON.stringify(dir)}, 'sshd-T.txt'), state.sshdConfig);
    fs.writeFileSync(require('node:path').join(bin, 'sshd'), '#!/bin/sh\\ncat ' + require('node:path').join(${JSON.stringify(dir)}, 'sshd-T.txt') + '\\n', { mode: 0o755 });
    const r = require('node:child_process').spawnSync('sh', ['-c', vars.infraward_sshd_filter, 'sh'], { encoding: 'utf8', env: { PATH: bin + ':/usr/bin:/bin' } });
    sudo.push({ item: { key: 'sshd' }, rc: r.status, stdout: r.stdout, stderr: r.stderr });
  } else {
    sudo.push({ item: { key: 'sshd' }, rc: 64, stdout: '', stderr: 'infraward-query: rechazado: consulta desconocida' });
  }
}
const roles = state.nodeRoles || ['proxmox'];
if (!vmid && roles.includes('proxmox')) {
  which.push('pveversion=/usr/bin/pveversion');
  sudo.push({ item: { key: 'pveversion' }, rc: 0, stdout: 'pve-manager/9.2.2/abc (running kernel: 7.0.2-6-pve)' });
}
if (!vmid && roles.includes('plesk')) {
  which.push('plesk=/usr/sbin/plesk');
  sudo.push({ item: { key: 'plesk' }, rc: 0, stdout: 'Product version: Plesk Obsidian 18.0.70.2' });
}
if (!vmid && roles.includes('podman')) {
  which.push('podman=/usr/bin/podman');
  sudo.push({ item: { key: 'podman' }, rc: 0, stdout: '5.4.2' });
  sudo.push({ item: { key: 'podman_users' }, rc: 0, stdout: (state.hostPodman || {}).users || '' });
}
if (!vmid && roles.includes('docker')) {
  which.push('docker=/usr/bin/docker');
  sudo.push({ item: { key: 'docker' }, rc: 0, stdout: '28.3.1' });
}
if (guest && guest.docker) {
  which.push('docker=/usr/bin/docker');
  sudo.push({ item: { key: 'docker' }, rc: 0, stdout: '28.3.1' });
}
const raw = {
  facts: { machine_id: vmid ? state.ctMachineId : state.machineId, hostname: vmid ? guest.name : state.node,
    os_family: 'Debian', distribution: 'Debian', distribution_version: '13.5', kernel: '7.0.2-6-pve', architecture: 'x86_64',
    ...(!vmid && state.ip ? { default_ipv4: { address: state.ip } } : {}) },
  packages: null,
  nativePackages: ['dpkg', 'bash\\t5.2.37-2\\tamd64\\tii '],
  services: { 'ssh.service': { name: 'ssh.service', state: 'running', status: 'enabled' } },
  which, sudo,
  sudoersVersion: vars.infraward_via === 'pct' ? '' : String(state.collectSudoersVersion || 4),
  via: vars.infraward_via,
};
fs.writeFileSync(vars.infraward_output, JSON.stringify(raw), { mode: 0o600 });
process.stdout.write('PLAY RECAP\\n');
`,
  );

  const trivyLog = join(dir, 'trivy.log');
  const trivyCacheDir = join(dir, 'trivy-cache');
  const scanDir = join(dir, 'scan');
  script(
    join(dir, 'trivy'),
    `${shebang}${prelude}
const path = require('node:path');
const args = process.argv.slice(2);
const val = (f) => args[args.indexOf(f) + 1];
fs.appendFileSync(${JSON.stringify(trivyLog)}, JSON.stringify(args) + '\\n');
for (const [flag, kind] of [['--download-db-only', 'db'], ['--download-java-db-only', 'java-db']]) {
  if (args.includes(flag)) {
    fs.mkdirSync(path.join(val('--cache-dir'), kind), { recursive: true });
    fs.writeFileSync(path.join(val('--cache-dir'), kind, 'metadata.json'),
      JSON.stringify({ UpdatedAt: '2026-10-09T19:06:47Z', DownloadedAt: new Date().toISOString() }));
    process.exit(0);
  }
}
const out = (v) => fs.writeFileSync(val('--output'), JSON.stringify(v));
const sbom = (component, os, libs) => ({ bomFormat: 'CycloneDX', specVersion: '1.7', serialNumber: 'urn:uuid:' + crypto.randomUUID(),
  metadata: { timestamp: new Date().toISOString(), tools: { components: [{ name: 'trivy', version: '0.75.0' }] }, component },
  components: [{ 'bom-ref': crypto.randomUUID(), type: 'operating-system', name: os[0], version: os[1] },
    ...libs.map((p) => ({ 'bom-ref': 'pkg:deb/debian/' + p.name + '@' + p.version, type: 'library', name: p.name, version: p.version,
      purl: 'pkg:deb/debian/' + p.name + '@' + p.version, properties: [{ name: 'aquasecurity:trivy:PkgType', value: 'debian' }] }))],
  dependencies: [], vulnerabilities: [] });
const crypto = require('node:crypto');
// SBOM de una imagen: el tar falso de \`docker save\` lleva el image ID (y uno de verdad, el nombre del
// config, que es su digest); sus paquetes son los de sus vulnerabilidades. Con una etiqueta que
// nunca se debe guardar.
if (args[0] === 'image') {
  const raw = fs.readFileSync(val('--input'));
  const image = raw[0] === 0x7b ? JSON.parse(raw.toString('utf8')).fakeImage
    : 'sha256:' + /"Config":"([0-9a-f]{64})\\.json"/.exec(raw.toString('latin1'))[1];
  const libs = [...new Map(((state.vulns || {})[image] || []).map((v) => [v.pkg + '@' + v.version, { name: v.pkg, version: v.version }])).values()];
  out(sbom({ type: 'container', name: 'image.tar', properties: [{ name: 'aquasecurity:trivy:ImageID', value: image },
    { name: 'aquasecurity:trivy:Labels:secreto', value: 'centinela-etiqueta' }] }, ['debian', '12.5'], libs));
  process.exit(0);
}
// SBOM de un servidor o CT: los paquetes de la copia de dpkg.
if (args[0] === 'rootfs') {
  const status = path.join(args[1], 'var/lib/dpkg/status');
  const libs = fs.existsSync(status) ? fs.readFileSync(status, 'utf8').split('\\n\\n').filter(Boolean).map((b) => ({
    name: /^Package: (.*)$/m.exec(b)[1], version: /^Version: (.*)$/m.exec(b)[1] })) : [];
  const os = fs.existsSync(path.join(args[1], 'etc/os-release')) ? ['debian', '13'] : null;
  const doc = sbom({ type: 'application', name: args[1] }, os || ['x', 'y'], libs);
  if (!os) doc.components.shift();
  out(doc);
  process.exit(0);
}
// Evaluación del SBOM: lo que «sabe» la BD de Trivy (state.vulns por imagen, state.hostVulns para el
// resto) para los paquetes que tiene.
const doc = JSON.parse(fs.readFileSync(args[1], 'utf8'));
const image = ((doc.metadata.component.properties || []).find((p) => p.name === 'aquasecurity:trivy:ImageID') || {}).value;
const have = new Set(doc.components.map((c) => c.name + '@' + c.version));
const vulns = (image ? (state.vulns || {})[image] || [] : state.hostVulns || []).filter((v) => have.has(v.pkg + '@' + v.version));
out({ SchemaVersion: 2, Trivy: { Version: '0.75.0' }, Metadata: image ? { ImageID: image } : {},
  Results: [{ Target: args[1] + ' (debian 12.5)', Class: 'os-pkgs', Type: 'debian',
    Vulnerabilities: vulns.map((v) => ({ VulnerabilityID: v.id, PkgName: v.pkg, InstalledVersion: v.version,
      FixedVersion: v.fixed, Severity: v.severity, Status: v.status || (v.fixed ? 'fixed' : 'affected'), Title: v.id + ' en ' + v.pkg,
      ...(v.cvss ? { CVSS: { nvd: { V3Score: v.cvss } } } : {}) })) }] });
`,
  );
  const trivyRuns = () => lines(trivyLog).map((l) => JSON.parse(l) as string[]);

  return {
    binDir: dir,
    trivyCacheDir,
    scanDir,
    trivyScans: () => trivyRuns().filter((a) => a.includes('--input')),
    trivyRootfs: () => trivyRuns().filter((a) => a[0] === 'rootfs'),
    trivyEvaluations: () => trivyRuns().filter((a) => a[0] === 'sbom'),
    trivyDownloads: () =>
      trivyRuns().filter((a) => a.some((x) => x.startsWith('--download-'))),
    workerEnv: () => ({
      PATH: `${dir}:${process.env.PATH ?? ''}`,
      ANSIBLE_PLAYBOOK_BIN: ansibleBin,
      TRIVY_BIN: join(dir, 'trivy'),
      TRIVY_CACHE_DIR: trivyCacheDir,
      WORKER_SCAN_DIR: scanDir,
      SSH_CONNECT_TIMEOUT: '3',
    }),
    ansibleBin,
    fingerprint,
    setState: (state) => writeFileSync(stateFile, JSON.stringify(state)),
    sshCommands: () => lines(sshLog),
    ansibleRuns: () =>
      lines(ansibleLog).map(
        (l) =>
          JSON.parse(l) as {
            host: Record<string, unknown>;
            vars: Record<string, unknown>;
          },
      ),
  };
}

function script(path: string, content: string): void {
  writeFileSync(path, content);
  chmodSync(path, 0o755);
}

function lines(path: string): string[] {
  return existsSync(path)
    ? readFileSync(path, 'utf8').split('\n').filter(Boolean)
    : [];
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}
