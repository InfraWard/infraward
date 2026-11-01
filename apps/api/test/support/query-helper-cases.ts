import { execFileSync } from 'node:child_process';
import {
  PODMAN_AS_USER_SCRIPT,
  PODMAN_USERS_SCRIPT,
  SSHD_AUTH_SCRIPT,
  type PrivilegedQueryName,
} from '@infraward/connectors';

/**
 * Casos del ayudante de root (`infraward-query`, sudoers v4) que comparten el test unitario
 * (bash con binarios falsos) y el de integración (sudo y sudo-rs reales). `runuser` no está: en
 * la integración es el de verdad (el test entra con él como `inventory` y el ayudante baja con él
 * al usuario de Podman rootless); el unitario añade uno falso (`UNIT_HELPER_BINARIES`).
 */
export const HELPER_BINARIES = [
  'dmidecode',
  'ss',
  'pveversion',
  'pvesh',
  'pct',
  'docker',
  'podman',
  'plesk',
  'nginx',
  'sshd',
];

/** Los del unitario: sin root, `runuser` no puede cambiar de usuario y se finge. */
export const UNIT_HELPER_BINARIES = [...HELPER_BINARIES, 'runuser'];

/**
 * Lo que tienen que anotar los binarios falsos para una consulta: su comando real. Las de nginx
 * (v5) son `sh -c <filtro> sh <comando…>` y el sh es el de verdad (filtra en el servidor): se
 * anota el comando que envuelve (`nginx -T`, `docker exec <id> nginx -T`). `runuser`: falso en el
 * unitario (se anota él) o el de verdad en la integración (se anota el podman que lanza).
 */
export function expectedCalls(
  argv: string[],
  runuser: 'fake' | 'real' = 'fake',
): string[] | null {
  // Podman rootless (v8): `sh -c <script> sh <uid> env XDG_RUNTIME_DIR=… podman …`; el sh de
  // verdad busca el nombre del uid y lo pasa a runuser.
  if (argv[0] === 'sh' && argv[2] === PODMAN_AS_USER_SCRIPT)
    return runuser === 'fake'
      ? ['runuser', '-u', PODMAN_USER, '--', ...argv.slice(5)]
      : argv.slice(7);
  // podman-users (v8) solo lee /etc/infraward/podman-users y /proc: ningún binario falso.
  if (argv[0] === 'sh' && argv[2] === PODMAN_USERS_SCRIPT) return null;
  // sshd-auth (v7) llama a `sshd -T` para el usuario root.
  if (argv[0] === 'sh' && argv[2] === SSHD_AUTH_SCRIPT)
    return ['sshd', '-T', '-C', 'user=root,host=localhost,addr=127.0.0.1'];
  // process-packages (v6) no envuelve ningún comando: de los binarios falsos solo llama a `ss`.
  if (argv[0] === 'sh' && argv[1] === '-c' && argv.length === 4)
    return ['ss', '-Htulpn'];
  return argv[0] === 'sh' && argv[1] === '-c'
    ? expectedCalls(argv.slice(4), runuser)
    : argv;
}

/** Utilidades de verdad que usan los scripts que corren en el servidor (v5 y v6). */
export const HELPER_REAL_TOOLS = [
  'sh',
  'awk',
  'grep',
  'cut',
  'sort',
  'head',
  'sed',
  'cat',
  'readlink',
  'id',
  'tr',
];

/**
 * Usuario de Podman rootless de las pruebas: `nobody` existe en todas partes, pero no con el mismo
 * uid (65534 en Linux; 4294967294 en macOS): se pregunta. Los tests lo ponen en la lista de
 * usuarios (`/etc/infraward/podman-users` o la copia del unitario).
 */
export const PODMAN_USER = 'nobody';
export const PODMAN_UID = nobodyUid();
/** El de `nobody` en los contenedores Debian y Ubuntu de la integración. */
export const CONTAINER_PODMAN_UID = '65534';

function nobodyUid(): string {
  try {
    const uid = execFileSync('id', ['-u', PODMAN_USER], { encoding: 'utf8' }).trim();
    return /^[1-9][0-9]{0,9}$/.test(uid) ? uid : '65534';
  } catch {
    return '65534';
  }
}

/**
 * Configuración de nginx con secretos que el filtro NUNCA deja salir del servidor: cabeceras,
 * ficheros de contraseñas, claves, credenciales en la URL y variables que no son de NPM.
 */
export const NGINX_SECRET_CONFIG = `# configuration file /etc/nginx/nginx.conf:
http {
  upstream backend { server 10.0.0.5:8080 weight=2; server app:3000; }
  server {
    listen 443 ssl default_server;
    server_name app.example.com;
    ssl_certificate_key /etc/ssl/private/centinela-clave.key;
    auth_basic_user_file /etc/nginx/centinela.htpasswd;
    location / {
      proxy_set_header Authorization "Basic centinela-cabecera";
      proxy_pass http://usuario:centinela-url@127.0.0.1:8080;
    }
    location /api { proxy_pass http://backend; }
  }
  server {
    set $forward_scheme http;
    set $server "192.168.1.20";
    set $port 8096;
    set $token centinela-variable;
    listen 80;
    server_name jelly.example.com;
    location / { proxy_pass $forward_scheme://$server:$port; }
  }
}
`;

/** Ficheros de `/etc/pve`: nodo `pve` con el CT 100 y la VM 200; el CT 101 es de otro nodo. */
export const PVE_FILES = [
  'nodes/pve/lxc/100.conf',
  'nodes/pve/qemu-server/200.conf',
  'nodes/otro/lxc/101.conf',
  'lxc/100.conf',
];

export const ID = 'a'.repeat(64);
export const IMAGE = `sha256:${'b'.repeat(64)}`;

/** Ejemplo de argumentos válidos de cada consulta (todas tienen que salir aquí). */
export const SAMPLES: Record<PrivilegedQueryName, string[][]> = {
  'dmidecode-system': [[]],
  ss: [[]],
  pveversion: [[]],
  'pve-cluster-status': [[]],
  'pve-cluster-resources': [[]],
  'pve-guest-config': [
    ['lxc', 'pve', '100'],
    ['qemu', 'pve', '200'],
  ],
  'pve-lxc-interfaces': [['pve', '100']],
  'pct-exec': [
    ['100', '/bin/sh', '-c', "echo 'hola'; python3 -c 'print(1)'"],
    ['100', 'docker', 'save', IMAGE],
  ],
  'docker-version': [[]],
  'docker-ps': [[]],
  'docker-inspect-containers': [[ID, 'c'.repeat(64)]],
  'docker-images': [[]],
  'docker-image-inspect': [[IMAGE]],
  'docker-volumes': [[]],
  'docker-volume-inspect': [['datos', 'mi_vol.1-x', 'f'.repeat(64)]],
  'docker-networks': [[]],
  'docker-network-inspect': [['bridge', 'app-net']],
  'docker-save': [[IMAGE]],
  'nginx-routes': [[]],
  'docker-nginx-routes': [[ID]],
  'process-packages': [[]],
  'sshd-auth': [[]],
  'podman-version': [[]],
  'podman-users': [[]],
  'podman-ps': [['root'], [PODMAN_UID]],
  'podman-inspect-containers': [
    ['root', ID, 'c'.repeat(64)],
    [PODMAN_UID, ID],
  ],
  'podman-pods': [['root'], [PODMAN_UID]],
  'podman-images': [['root'], [PODMAN_UID]],
  'podman-image-inspect': [
    ['root', IMAGE],
    [PODMAN_UID, IMAGE],
  ],
  'podman-volumes': [['root'], [PODMAN_UID]],
  'podman-volume-inspect': [['root', 'datos', 'mi_vol.1-x']],
  'podman-networks': [['root'], [PODMAN_UID]],
  'podman-network-inspect': [
    ['root', 'podman', 'red-app'],
    [PODMAN_UID, 'podman'],
  ],
  'podman-save': [
    ['root', IMAGE],
    [PODMAN_UID, IMAGE],
  ],
  'podman-nginx-routes': [
    ['root', ID],
    [PODMAN_UID, ID],
  ],
  'plesk-version': [[]],
  'plesk-domains': [[]],
  'plesk-aliases': [[]],
  'plesk-databases': [[]],
  'plesk-certificates': [[]],
};

/** Intentos que el ayudante tiene que rechazar con 64 sin ejecutar ningún binario. */
export const ATTACKS: [string, string[]][] = [
  ['sin consulta', []],
  ['consulta desconocida', ['bash']],
  ['consulta con ruta', ['/bin/sh']],
  ['consulta con espacios', ['docker-ps ; id']],
  ['argumento de más en una fija', ['ss', '-a']],
  ['argumento de más en dmidecode', ['dmidecode-system', '-t', 'bios']],
  ['plesk con consulta libre', ['plesk-domains', 'SELECT * FROM accounts']],
  // pvesh: no se aceptan rutas, solo piezas validadas, y el guest tiene que existir.
  ['pvesh con otra ruta', ['pve-guest-config', '/access/users', 'pve', '100']],
  ['pvesh con otro tipo', ['pve-guest-config', 'storage', 'pve', '100']],
  [
    'pvesh con ../ en el nodo',
    ['pve-guest-config', 'lxc', '../../access', '100'],
  ],
  ['pvesh con / en el nodo', ['pve-guest-config', 'lxc', 'pve/../x', '100']],
  ['pvesh con ; en el vmid', ['pve-guest-config', 'lxc', 'pve', '100;id']],
  [
    'pvesh con ruta en el vmid',
    ['pve-lxc-interfaces', 'pve', '100/../../access'],
  ],
  [
    'pvesh con opción extra',
    ['pve-guest-config', 'lxc', 'pve', '100', '--output-format', 'text'],
  ],
  [
    'pvesh de un guest que no existe',
    ['pve-guest-config', 'lxc', 'pve', '999'],
  ],
  [
    'pvesh de un guest de otro nodo',
    ['pve-guest-config', 'lxc', 'otro', '100'],
  ],
  ['pvesh con vmid no numérico', ['pve-lxc-interfaces', 'pve', 'abc']],
  ['pvesh con salto de línea', ['pve-lxc-interfaces', 'pve', '100\n']],
  ['pvesh con nodo vacío', ['pve-lxc-interfaces', '', '100']],
  // docker save: solo un id a la salida estándar.
  ['docker save -o', ['docker-save', '-o', '/etc/passwd', IMAGE]],
  ['docker save --output=', ['docker-save', `--output=/etc/x`]],
  ['docker save con dos argumentos', ['docker-save', IMAGE, 'extra']],
  ['docker save con un nombre', ['docker-save', 'nginx:latest']],
  ['docker save con id corto', ['docker-save', 'sha256:abc']],
  ['docker save con id y algo más', ['docker-save', `${IMAGE} -o /tmp/x`]],
  ['docker save sin argumentos', ['docker-save']],
  // inspect: ids y nombres anclados, sin opciones.
  [
    'inspect con opción',
    ['docker-inspect-containers', '--format', '{{.Config.Env}}'],
  ],
  [
    'inspect con id y opción',
    ['docker-inspect-containers', ID, '-f', '{{.Config.Env}}'],
  ],
  ['inspect sin ids', ['docker-inspect-containers']],
  [
    'inspect de más de 256',
    ['docker-inspect-containers', ...Array<string>(257).fill(ID)],
  ],
  ['inspect de imagen con nombre', ['docker-image-inspect', 'nginx']],
  ['volumen con - inicial', ['docker-volume-inspect', '-f']],
  ['volumen con espacio', ['docker-volume-inspect', 'a b']],
  ['red con $()', ['docker-network-inspect', '$(id)']],
  ['red con acentos graves', ['docker-network-inspect', '`id`']],
  ['red con ;', ['docker-network-inspect', 'bridge;id']],
  ['red con &&', ['docker-network-inspect', 'bridge&&id']],
  ['red con |', ['docker-network-inspect', 'bridge|id']],
  ['red con salto de línea', ['docker-network-inspect', 'bridge\nid']],
  // nginx: solo el filtro fijo; en un contenedor, por su id completo.
  ['nginx-routes con argumentos', ['nginx-routes', '-c', '/tmp/x.conf']],
  ['docker-nginx-routes sin id', ['docker-nginx-routes']],
  ['docker-nginx-routes con nombre', ['docker-nginx-routes', 'nginx']],
  ['docker-nginx-routes con opción', ['docker-nginx-routes', '-u']],
  ['docker-nginx-routes con dos ids', ['docker-nginx-routes', ID, ID]],
  ['docker-nginx-routes con comando', ['docker-nginx-routes', ID, 'cat', '/etc/shadow']],
  // podman (v8): el primer argumento es el ámbito (root o el uid de un usuario de la lista).
  ['podman sin ámbito', ['podman-ps']],
  ['podman con ámbito vacío', ['podman-ps', '']],
  ['podman con uid 0', ['podman-ps', '0']],
  ['podman con uid con ceros', ['podman-ps', '0065534']],
  ['podman con ruta de socket', ['podman-ps', '/run/user/0/podman/podman.sock']],
  ['podman con url', ['podman-ps', 'unix:///run/podman/podman.sock']],
  ['podman con opción de ámbito', ['podman-ps', '--remote']],
  ['podman con argumento de más', ['podman-ps', 'root', '-a']],
  ['podman de un uid fuera de la lista', ['podman-ps', '4242']],
  ['podman inspect sin ids', ['podman-inspect-containers', 'root']],
  ['podman inspect con opción', ['podman-inspect-containers', 'root', '--format', '{{.Config.Env}}']],
  ['podman inspect sin ámbito', ['podman-inspect-containers', ID]],
  ['podman image inspect con nombre', ['podman-image-inspect', 'root', 'nginx']],
  ['podman red con ;', ['podman-network-inspect', 'root', 'podman;id']],
  ['podman save -o', ['podman-save', 'root', '-o', '/etc/passwd']],
  ['podman save con nombre', ['podman-save', 'root', 'nginx:latest']],
  ['podman save sin ámbito', ['podman-save', IMAGE]],
  ['podman save de más', ['podman-save', 'root', IMAGE, IMAGE]],
  ['podman nginx sin id', ['podman-nginx-routes', 'root']],
  ['podman nginx con comando', ['podman-nginx-routes', 'root', ID, 'cat', '/etc/shadow']],
  ['podman-users con argumentos', ['podman-users', '/etc/shadow']],
  ['podman-version con argumentos', ['podman-version', '--format', '{{.Host}}']],
  // pct-exec: el vmid se valida y el CT tiene que ser del nodo.
  ['pct-exec sin comando', ['pct-exec', '100']],
  ['pct-exec con vmid no numérico', ['pct-exec', '100;id', 'true']],
  ['pct-exec con opción en el vmid', ['pct-exec', '--help', 'true']],
  ['pct-exec de un CT de otro nodo', ['pct-exec', '101', 'true']],
  ['pct-exec de una VM', ['pct-exec', '200', 'true']],
];

/** Rechazos que solo puede decidir el nodo (miran /etc/pve), no la validación de TypeScript. */
export const NODE_ONLY_ATTACKS = new Set([
  'pvesh de un guest que no existe',
  'pvesh de un guest de otro nodo',
  'pct-exec de un CT de otro nodo',
  'pct-exec de una VM',
  'podman de un uid fuera de la lista',
]);
