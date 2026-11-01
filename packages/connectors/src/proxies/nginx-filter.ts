import {
  PROXY_MAX_HOSTS,
  PROXY_MAX_ROUTES,
  PROXY_MAX_UPSTREAMS,
  type ProxyFacts,
  type ProxyRoute,
  type ProxySource,
  type ProxyUpstream,
} from '@infraward/shared-types';

/**
 * Filtro de `nginx -T` que se ejecuta EN EL SERVIDOR (ayudante de root, sudoers v5; DESIGN §7):
 * `sh -c NGINX_ROUTES_SCRIPT sh <comando…>` ejecuta el comando (`nginx -T` o
 * `docker exec <id> nginx -T`), guarda su salida en memoria y deja pasar solo líneas normalizadas
 * con nombres y destinos. La configuración completa (cabeceras, `auth_basic_user_file`, claves,
 * credenciales en las URL…) nunca sale de la máquina.
 *
 * Salida, una línea por dato:
 * - `S <http|stream>` / `E`: empieza / acaba un bloque `server`. `nginx -T` vuelca cada `include`
 *   como un fichero aparte (después del principal): un `server` en lo alto de un fichero incluido
 *   es de `http` (así guarda NPM sus hosts en /data/nginx/proxy_host/*.conf).
 * - `L <dirección o puerto> [ssl] [default_server]`: `listen`.
 * - `N <nombres…>`: `server_name`.
 * - `@ <ruta>` / `Q`: empieza / acaba un `location`.
 * - `P <directiva> <destino>`: `proxy_pass`, `grpc_pass`, `fastcgi_pass` o `uwsgi_pass`, sin
 *   `usuario:contraseña@`.
 * - `V <$server|$port|$forward_scheme> <valor>`: variables de los hosts de Nginx Proxy Manager.
 * - `U <nombre>` / `M <host:puerto>` / `E`: un `upstream` y sus `server`.
 * Cada valor pasa por una lista blanca de caracteres; lo que no encaja se descarta.
 *
 * El ayudante (`ansible/enroll/enroll.sh.tmpl`) y el playbook lo llevan tal cual (un test lo
 * compara). Sin comillas simples dentro del awk ni `{{`, `{%` o `{#` (lo pasa Ansible).
 */
export const NGINX_ROUTES_SCRIPT = String.raw`out=$("$@" 2>/dev/null)
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "infraward: nginx -T falló ($rc)" >&2
  exit 3
fi
printf '%s\n' "$out" | awk '
function emit(s) { if (++cnt <= 20000) print s }
function words(s) { gsub(/[ \t\r]+/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return split(s, W, " ") }
function unquote(t,   f) {
  f = substr(t, 1, 1)
  if ((f == "\"" || f == SQ) && length(t) >= 2 && substr(t, length(t), 1) == f) t = substr(t, 2, length(t) - 2)
  return t
}
function safe(t) { t = unquote(t); return (t ~ /^[]\/A-Za-z0-9._:*~^$=+[-]+$/) ? t : "" }
function inside(kind,   i) { for (i = d; i > 0; i--) if (B[i] == kind) return 1; return 0 }
function blk_open(s,   n, k, v, top) {
  n = words(s); k = (n > 0) ? W[1] : ""
  d++; K[d] = k; B[d] = 0
  top = (d == 1) ? "http" : K[d - 1]
  if (k == "server" && (top == "http" || top == "stream")) { emit("S " top); B[d] = 1 }
  else if (k == "upstream" && n >= 2 && (top == "http" || top == "stream")) { v = safe(W[2]); if (v != "") { emit("U " v); B[d] = 2 } }
  else if (k == "location" && inside(1)) { v = safe(W[n]); if (v != "" && n >= 2) { emit("@ " v); B[d] = 3 } }
}
function blk_close() {
  if (d > 0) { if (B[d] == 1 || B[d] == 2) emit("E"); else if (B[d] == 3) emit("Q"); d-- }
}
function stmt(s,   n, k, i, v, o) {
  n = words(s); if (n == 0) return
  k = W[1]
  if (inside(2)) { if (k == "server" && n >= 2) { v = safe(W[2]); if (v != "") emit("M " v) } return }
  if (!inside(1)) return
  if (k == "listen" && n >= 2) {
    v = safe(W[2]); if (v == "") return
    o = "L " v
    for (i = 3; i <= n; i++) if (W[i] == "ssl" || W[i] == "default_server") o = o " " W[i]
    emit(o)
  } else if (k == "server_name") {
    o = "N"
    for (i = 2; i <= n && i <= 41; i++) { v = safe(W[i]); if (v != "") o = o " " v }
    if (o != "N") emit(o)
  } else if ((k == "proxy_pass" || k == "grpc_pass" || k == "fastcgi_pass" || k == "uwsgi_pass") && n >= 2) {
    v = unquote(W[2]); sub(/:\/\/[^\/]*@/, "://", v); v = safe(v)
    if (v != "") emit("P " k " " v)
  } else if (k == "set" && n >= 3 && (W[2] == "$server" || W[2] == "$port" || W[2] == "$forward_scheme")) {
    v = safe(W[3]); if (v != "") emit("V " W[2] " " v)
  }
}
BEGIN { SQ = sprintf("%c", 39); d = 0; buf = "" }
/^# configuration file / { d = 0; buf = ""; next }
{
  line = $0
  sub(/#.*/, "", line)
  gsub(/[{};]/, "\n&\n", line)
  n = split(line, parts, "\n")
  for (i = 1; i <= n; i++) {
    p = parts[i]
    if (p == ";") { stmt(buf); buf = "" }
    else if (p == "{") { blk_open(buf); buf = "" }
    else if (p == "}") { stmt(buf); buf = ""; blk_close() }
    else buf = buf " " p
  }
}
'
`;

/** Comando real de `nginx -T` (en el host o en un contenedor). */
export const NGINX_DUMP = ['nginx', '-T'];

const NAME = /^(?:\*\.)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*\.?$/;
const DEFAULT_PORT: Record<string, number> = {
  http: 80,
  https: 443,
  grpc: 80,
  grpcs: 443,
};

interface ServerBlock {
  ctx: 'http' | 'stream';
  listen: number[];
  ssl: boolean;
  isDefault: boolean;
  hosts: string[];
  /** Destinos de cada `location` (null = el del propio server). */
  passes: { path: string | null; target: string; directive: string }[];
  vars: Map<string, string>;
}

/**
 * Convierte la salida filtrada en rutas. `source` = `npm` si es Nginx Proxy Manager: sus hosts
 * usan `proxy_pass $forward_scheme://$server:$port`.
 */
export function parseNginxRoutes(
  output: string,
  source: ProxySource = 'nginx',
  now: Date = new Date(),
): ProxyFacts {
  const upstreams = new Map<string, ProxyUpstream[]>();
  const servers: ServerBlock[] = [];
  let server: ServerBlock | null = null;
  let upstream: { name: string; servers: ProxyUpstream[] } | null = null;
  let path: string | null = null;
  for (const raw of output.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const [tag, ...rest] = line.split(' ');
    switch (tag) {
      case 'S':
        server = {
          ctx: rest[0] === 'stream' ? 'stream' : 'http',
          listen: [],
          ssl: false,
          isDefault: false,
          hosts: [],
          passes: [],
          vars: new Map(),
        };
        path = null;
        break;
      case 'U':
        upstream = { name: rest[0] ?? '', servers: [] };
        break;
      case 'M': {
        const u = upstream && parseHostPort(rest[0] ?? '', null);
        if (u && upstream!.servers.length < PROXY_MAX_UPSTREAMS)
          upstream!.servers.push(u);
        break;
      }
      case 'E':
        if (upstream) {
          upstreams.set(upstream.name, upstream.servers);
          upstream = null;
        } else if (server) {
          servers.push(server);
          server = null;
        }
        break;
      case 'L': {
        if (!server) break;
        const port = listenPort(rest[0] ?? '');
        if (port !== null && !server.listen.includes(port))
          server.listen.push(port);
        if (rest.includes('ssl')) server.ssl = true;
        if (rest.includes('default_server')) server.isDefault = true;
        break;
      }
      case 'N':
        if (!server) break;
        for (const n of rest) {
          const name = n.toLowerCase().replace(/\.$/, '');
          if (NAME.test(name) && !server.hosts.includes(name))
            server.hosts.push(name);
        }
        break;
      case '@':
        path = rest[0] ?? null;
        break;
      case 'Q':
        path = null;
        break;
      case 'P':
        if (server && rest.length >= 2)
          server.passes.push({ path, directive: rest[0], target: rest[1] });
        break;
      case 'V':
        if (server && rest.length >= 2) server.vars.set(rest[0], rest[1]);
        break;
    }
  }

  const routes: ProxyRoute[] = [];
  let truncated = false;
  for (const s of servers) {
    // NPM: el proxy_pass está en conf.d/include/proxy.conf (otro fichero del volcado) y el
    // server solo lleva `set $server`/`$port`; se reconstruye con sus variables.
    if (!s.passes.some((p) => p.target) && s.vars.has('$server'))
      s.passes = [
        {
          path: null,
          directive: 'proxy_pass',
          target: '$forward_scheme://$server:$port',
        },
      ];
    // Un server sin proxy_pass lo sirve el propio nginx (estático, redirección).
    const passes = s.passes.length
      ? s.passes
      : [{ path: null, target: '', directive: '' }];
    for (const p of passes) {
      if (routes.length >= PROXY_MAX_ROUTES) {
        truncated = true;
        break;
      }
      routes.push({
        source,
        hosts: s.hosts.slice(0, PROXY_MAX_HOSTS),
        listen: s.listen.length ? s.listen : [s.ctx === 'http' ? 80 : 0],
        isDefault: s.isDefault,
        path: p.path,
        upstreams: p.target
          ? resolveTarget(p.directive, p.target, s.vars, upstreams)
          : [],
      });
    }
  }
  return {
    source,
    routes,
    readAt: now.toISOString(),
    ...(truncated && { truncated }),
  };
}

function resolveTarget(
  directive: string,
  target: string,
  vars: Map<string, string>,
  upstreams: Map<string, ProxyUpstream[]>,
): ProxyUpstream[] {
  // Variables de NPM (`$forward_scheme://$server:$port`); otras variables no se resuelven.
  const value = target.replace(
    /\$(server|port|forward_scheme)\b/g,
    (m, name: string) => vars.get(`$${name}`) ?? m,
  );
  if (value.startsWith('$')) return [];
  const scheme =
    /^([a-z][a-z0-9+.-]*):\/\//.exec(value)?.[1] ??
    (directive === 'fastcgi_pass'
      ? 'fastcgi'
      : directive === 'uwsgi_pass'
        ? 'uwsgi'
        : directive === 'grpc_pass'
          ? 'grpc'
          : 'tcp');
  const rest = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  if (rest.startsWith('unix:')) return [];
  // Sin la ruta ni variables detrás del puerto (`…:8096$request_uri`).
  const hostPort = rest.split('/')[0].split('$')[0];
  if (!hostPort) return [];
  const named = upstreams.get(hostPort);
  if (named)
    return named.map((u) => ({
      ...u,
      scheme,
      port: u.port ?? DEFAULT_PORT[scheme] ?? null,
    }));
  const u = parseHostPort(hostPort, scheme);
  return u ? [u] : [];
}

function parseHostPort(
  value: string,
  scheme: string | null,
): ProxyUpstream | null {
  const m = /^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9_.-]+)(?::(\d{1,5}))?$/.exec(value);
  if (!m) return null;
  const host = m[1].replace(/^\[|\]$/g, '').toLowerCase();
  const port = m[2]
    ? Number(m[2])
    : scheme
      ? (DEFAULT_PORT[scheme] ?? null)
      : null;
  if (port !== null && (port < 1 || port > 65535)) return null;
  return { scheme, host, port };
}

function listenPort(value: string): number | null {
  if (value.startsWith('unix:')) return null;
  const m = /(?:^|:)(\d{1,5})$/.exec(value);
  if (!m) return /^\[?[0-9a-fA-F:.]+\]?$/.test(value) ? 80 : null;
  const port = Number(m[1]);
  return port >= 1 && port <= 65535 ? port : null;
}
