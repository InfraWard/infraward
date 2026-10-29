import {
  PROXY_MAX_HOSTS,
  PROXY_MAX_ROUTES,
  PROXY_SELF_HOST,
  type ProxyRoute,
  type ProxyUpstream,
} from '@infraward/shared-types';

/**
 * Claves de etiquetas que se aceptan (la plantilla de `docker inspect` ya filtra en el servidor;
 * esto vuelve a filtrar por si acaso): nunca middlewares (basicauth), TLS ni nada más.
 */
const TRAEFIK_ROUTER = /^traefik\.http\.routers\.([A-Za-z0-9_-]{1,64})\.(rule|service)$/;
const TRAEFIK_SERVICE =
  /^traefik\.http\.services\.([A-Za-z0-9_-]{1,64})\.loadbalancer\.server\.port$/;
const CADDY = /^(caddy(?:_\d{1,3})?)(?:\.(reverse_proxy))?$/;
const NAME = /^(?:\*\.)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$/;

/** Pares `[clave, valor]` de la plantilla (`proxyLabels`), solo de la lista blanca. */
export function proxyLabelPairs(value: unknown): [string, string][] {
  if (!Array.isArray(value)) return [];
  const out: [string, string][] = [];
  for (const p of value) {
    if (
      !Array.isArray(p) ||
      p.length !== 2 ||
      typeof p[0] !== 'string' ||
      typeof p[1] !== 'string'
    )
      continue;
    const [k, v] = p as [string, string];
    if (
      k === 'traefik.enable' ||
      k === 'traefik.docker.network' ||
      TRAEFIK_ROUTER.test(k) ||
      TRAEFIK_SERVICE.test(k) ||
      CADDY.test(k)
    )
      out.push([k, v.slice(0, 1024)]);
    if (out.length >= 200) break;
  }
  return out;
}

/** Rutas que declara un contenedor con etiquetas de Traefik o de caddy-docker-proxy. */
export function parseProxyLabels(pairs: [string, string][]): ProxyRoute[] {
  const labels = new Map(pairs);
  const routes: ProxyRoute[] = [];
  if (labels.get('traefik.enable')?.toLowerCase() !== 'false')
    routes.push(...traefikRoutes(pairs));
  routes.push(...caddyRoutes(pairs));
  return routes.slice(0, PROXY_MAX_ROUTES);
}

function traefikRoutes(pairs: [string, string][]): ProxyRoute[] {
  const routers = new Map<string, { rule?: string; service?: string }>();
  const services = new Map<string, number>();
  for (const [k, v] of pairs) {
    const r = TRAEFIK_ROUTER.exec(k);
    if (r) {
      const entry = routers.get(r[1]) ?? {};
      entry[r[2] as 'rule' | 'service'] = v;
      routers.set(r[1], entry);
      continue;
    }
    const s = TRAEFIK_SERVICE.exec(k);
    const port = Number(v.trim());
    if (s && Number.isInteger(port) && port > 0 && port < 65536)
      services.set(s[1], port);
  }
  const routes: ProxyRoute[] = [];
  for (const [name, router] of routers) {
    if (!router.rule) continue;
    const hosts = ruleHosts(router.rule);
    if (!hosts.length) continue;
    // Sin servicio explícito, Traefik usa el único del contenedor o uno con el nombre del router.
    const service =
      router.service ??
      (services.size === 1 ? [...services.keys()][0] : name);
    routes.push({
      source: 'traefik',
      hosts,
      listen: [],
      isDefault: false,
      path: rulePath(router.rule),
      upstreams: [
        {
          scheme: 'http',
          host: PROXY_SELF_HOST,
          port: services.get(service) ?? null,
        },
      ],
    });
  }
  return routes;
}

/** `Host(\`a.com\`) || Host(\`b.com\`, \`c.com\`)` → nombres. */
function ruleHosts(rule: string): string[] {
  const hosts: string[] = [];
  for (const m of rule.matchAll(/\bHost\(([^)]*)\)/g))
    for (const q of m[1].matchAll(/[`"']([^`"']+)[`"']/g)) {
      const name = q[1].trim().toLowerCase();
      if (NAME.test(name) && !hosts.includes(name)) hosts.push(name);
    }
  return hosts.slice(0, PROXY_MAX_HOSTS);
}

function rulePath(rule: string): string | null {
  const m = /\bPathPrefix\(\s*[`"']([^`"']+)[`"']/.exec(rule);
  return m && /^\/[A-Za-z0-9._~/-]*$/.test(m[1]) ? m[1] : null;
}

function caddyRoutes(pairs: [string, string][]): ProxyRoute[] {
  const groups = new Map<string, { sites?: string; upstream?: string }>();
  for (const [k, v] of pairs) {
    const m = CADDY.exec(k);
    if (!m) continue;
    const g = groups.get(m[1]) ?? {};
    if (m[2]) g.upstream = v;
    else g.sites = v;
    groups.set(m[1], g);
  }
  const routes: ProxyRoute[] = [];
  for (const g of groups.values()) {
    if (!g.sites || !g.upstream) continue;
    const hosts = g.sites
      .split(/[\s,]+/)
      .map((s) => s.replace(/^[a-z]+:\/\//, '').replace(/[:/].*$/, '').toLowerCase())
      .filter((s) => NAME.test(s))
      .slice(0, PROXY_MAX_HOSTS);
    if (!hosts.length) continue;
    routes.push({
      source: 'caddy',
      hosts,
      listen: [],
      isDefault: false,
      path: null,
      upstreams: caddyUpstreams(g.upstream),
    });
  }
  return routes;
}

/** `{{upstreams 8080}}`, `{{upstreams https 8443}}` (el propio contenedor) o `host:puerto`. */
function caddyUpstreams(value: string): ProxyUpstream[] {
  const self = /\{\{\s*upstreams(?:\s+(https?))?(?:\s+(\d{1,5}))?\s*\}\}/.exec(value);
  if (self)
    return [
      {
        scheme: self[1] ?? 'http',
        host: PROXY_SELF_HOST,
        port: self[2] ? Number(self[2]) : 80,
      },
    ];
  const out: ProxyUpstream[] = [];
  for (const token of value.split(/\s+/)) {
    const m =
      /^(?:(https?|h2c):\/\/)?([A-Za-z0-9_.-]+|\[[0-9a-fA-F:]+\])(?::(\d{1,5}))?$/.exec(
        token,
      );
    if (!m) continue;
    out.push({
      scheme: m[1] ?? 'http',
      host: m[2].replace(/^\[|\]$/g, '').toLowerCase(),
      port: m[3] ? Number(m[3]) : m[1] === 'https' ? 443 : 80,
    });
  }
  return out.slice(0, 10);
}

/** Imágenes de nginx (y derivadas) cuya configuración se lee con `docker exec … nginx -T`. */
const NGINX_IMAGE =
  /(?:^|\/)(?:nginx|nginx-unprivileged|openresty|nginx-proxy-manager|nginxproxymanager|swag|nginx-proxy)(?:[:@]|$)/i;
const NPM_IMAGE = /nginx-?proxy-?manager/i;

/** ¿Es un contenedor de nginx (o NPM) cuya configuración merece leerse? */
export function nginxImageKind(image: string): 'nginx' | 'npm' | null {
  if (NPM_IMAGE.test(image)) return 'npm';
  return NGINX_IMAGE.test(image) ? 'nginx' : null;
}
