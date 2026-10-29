import { describe, expect, it } from 'vitest';
import {
  PROXY_SELF_HOST,
  SERVICE_MAX_HOPS,
  type ProxyRoute,
} from '@infraward/shared-types';
import {
  hostMatches,
  resolveServicePaths,
  type ServiceAsset,
  type ServicePathInput,
  type ServiceRecord,
} from './resolve.js';

const route = (
  hosts: string[],
  host: string,
  port: number | null,
  extra: Partial<ProxyRoute> = {},
): ProxyRoute => ({
  source: 'nginx',
  hosts,
  listen: [443],
  isDefault: false,
  path: null,
  upstreams: [{ scheme: 'http', host, port }],
  ...extra,
});

const host = (id: string, ip: string, extra: Partial<ServiceAsset> = {}): ServiceAsset => ({
  id,
  name: id,
  type: 'lxc',
  parentId: null,
  ips: [ip],
  ports: [],
  ...extra,
});

const container = (
  id: string,
  parentId: string,
  docker: Partial<NonNullable<ServiceAsset['docker']>> & { image: string },
  extra: Partial<ServiceAsset> = {},
): ServiceAsset => ({
  id,
  name: id,
  type: 'container',
  parentId,
  ips: [],
  ports: null,
  docker: {
    state: 'running',
    ports: [],
    networks: [],
    composeService: null,
    proxyRoutes: [],
    ...docker,
  },
  ...extra,
});

const record = (
  id: string,
  name: string,
  content: string,
  targets: string[] = [],
  type: ServiceRecord['type'] = 'A',
): ServiceRecord => ({ id, name, type, content, targets });

const input = (over: Partial<ServicePathInput>): ServicePathInput => ({
  records: [],
  assets: [],
  natForwards: [],
  tunnels: [],
  ...over,
});

const path = (i: ServicePathInput, id = 'r1') =>
  resolveServicePaths(i).find((p) => p.recordId === id)!;
const ids = (p: ReturnType<typeof path>) => p.hops.map((h) => h.assetId);

describe('resolveServicePaths', () => {
  // CT con NPM publicado en el 443 (docker-proxy) que envía a la app por la red de Docker.
  const ct = host('ct', '192.168.1.10', {
    ports: [
      { proto: 'tcp', address: '0.0.0.0', port: 443, process: 'docker-proxy', pid: 1 },
      { proto: 'tcp', address: '0.0.0.0', port: 22, process: 'sshd', pid: 2 },
    ],
  });
  const npm = container(
    'npm',
    'ct',
    {
      image: 'jc21/nginx-proxy-manager:latest',
      ports: [{ containerPort: 443, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 443 }],
      networks: [{ name: 'proxy', ipv4: '172.18.0.2', ipv6: null }],
    },
    {
      proxy: {
        source: 'npm',
        readAt: 'x',
        routes: [
          route(['app.example.com'], '172.18.0.5', 3000, { source: 'npm' }),
          route(['other.example.com'], 'jellyfin', 8096, { source: 'npm' }),
        ],
      },
    },
  );
  const app = container('app', 'ct', {
    image: 'ghcr.io/x/app:1',
    networks: [{ name: 'proxy', ipv4: '172.18.0.5', ipv6: null }],
  });
  const jelly = container('jellyfin-1', 'ct', {
    image: 'jellyfin/jellyfin',
    composeService: 'jellyfin',
    networks: [{ name: 'proxy', ipv4: '172.18.0.6', ipv6: null }],
  });
  const nat = {
    publicIp: '203.0.113.7',
    publicPort: 443,
    proto: 'tcp' as const,
    targetAssetId: 'ct',
    targetPort: 443,
  };

  it('IP pública → reenvío NAT → docker-proxy → NPM → contenedor final (confirmado)', () => {
    const p = path(
      input({
        records: [record('r1', 'app.example.com', '203.0.113.7')],
        assets: [ct, npm, app, jelly],
        natForwards: [nat],
      }),
    );
    expect(p.status).toBe('complete');
    expect(p.cutReason).toBeNull();
    expect(p.finalAssetId).toBe('app');
    expect(p.confidence).toBe('confirmed');
    expect(p.hops.map((h) => [h.resolver, h.assetId, h.port])).toEqual([
      ['dns', null, 443],
      ['nat', 'ct', 443],
      ['docker-proxy', 'npm', 443],
      ['npm', 'app', 3000],
    ]);
    expect(p.hops[3].source).toBe(
      'npm: server_name app.example.com → 172.18.0.5:3000',
    );
  });

  it('NPM → servicio de compose por nombre', () => {
    const p = path(
      input({
        records: [record('r1', 'other.example.com', '192.168.1.10', ['ct'])],
        assets: [ct, npm, app, jelly],
      }),
    );
    expect(p.finalAssetId).toBe('jellyfin-1');
    expect(ids(p)).toEqual(['ct', 'npm', 'jellyfin-1']);
  });

  it('sin docker-proxy en ss (iptables): publicado por Docker, deducido', () => {
    const p = path(
      input({
        records: [record('r1', 'app.example.com', '192.168.1.10', ['ct'])],
        assets: [{ ...ct, ports: [] }, npm, app],
      }),
    );
    expect(p.finalAssetId).toBe('app');
    expect(p.confidence).toBe('deduced');
    expect(p.hops[1]).toMatchObject({ resolver: 'docker-proxy', confidence: 'deduced' });
  });

  it('nginx del host → 127.0.0.1:8080 publicado solo en loopback → contenedor', () => {
    const srv = host('srv', '10.0.0.4', {
      type: 'server',
      ports: [
        { proto: 'tcp', address: '0.0.0.0', port: 443, process: 'nginx', pid: 1 },
        { proto: 'tcp', address: '127.0.0.1', port: 8080, process: 'docker-proxy', pid: 2 },
      ],
      proxy: { source: 'nginx', readAt: 'x', routes: [route(['git.example.com'], '127.0.0.1', 8080)] },
    });
    const gitea = container('gitea', 'srv', {
      image: 'gitea/gitea',
      ports: [{ containerPort: 3000, proto: 'tcp', hostIp: '127.0.0.1', hostPort: 8080 }],
    });
    const p = path(
      input({
        records: [record('r1', 'git.example.com', '10.0.0.4', ['srv'])],
        assets: [srv, gitea],
      }),
    );
    expect(p.status).toBe('complete');
    expect(p.hops.map((h) => [h.resolver, h.assetId, h.port])).toEqual([
      ['dns', 'srv', 443],
      ['nginx', 'srv', 8080],
      ['docker-proxy', 'gitea', 3000],
    ]);
    expect(p.confidence).toBe('confirmed');
  });

  it('Traefik: etiqueta Host() en un contenedor vecino; sin puerto, el único expuesto (deducido)', () => {
    const t = container('traefik', 'ct', {
      image: 'traefik:v3.1',
      ports: [{ containerPort: 443, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 443 }],
    });
    const web = container('web', 'ct', {
      image: 'nginxdemos/hello',
      ports: [{ containerPort: 8000, proto: 'tcp', hostIp: null, hostPort: null }],
      proxyRoutes: [
        {
          source: 'traefik',
          hosts: ['web.example.com'],
          listen: [],
          isDefault: false,
          path: null,
          upstreams: [{ scheme: 'http', host: PROXY_SELF_HOST, port: null }],
        },
      ],
    });
    const p = path(
      input({
        records: [record('r1', 'web.example.com', '192.168.1.10', ['ct'])],
        assets: [ct, t, web],
      }),
    );
    expect(p.finalAssetId).toBe('web');
    expect(p.hops.at(-1)).toMatchObject({ resolver: 'traefik', port: 8000, confidence: 'deduced' });
    // Traefik sin etiqueta para ese nombre: corte.
    const miss = path(
      input({
        records: [record('r1', 'otro.example.com', '192.168.1.10', ['ct'])],
        assets: [ct, t, web],
      }),
    );
    expect(miss).toMatchObject({ status: 'partial', cutReason: 'no_route_for_host', finalAssetId: null });
    expect(ids(miss)).toEqual(['ct', 'traefik']);
  });

  it('túnel de Cloudflare: regla de entrada → cloudflared → contenedor por nombre', () => {
    const tunnelId = '0b1c2d3e-1111-2222-3333-444455556666';
    const cf = container('cloudflared', 'ct', {
      image: 'cloudflare/cloudflared:latest',
      networks: [{ name: 'proxy', ipv4: '172.18.0.9', ipv6: null }],
    });
    const p = path(
      input({
        records: [record('r1', 'app.example.com', `${tunnelId}.cfargotunnel.com`, [], 'CNAME')],
        assets: [ct, cf, app, jelly],
        tunnels: [
          {
            id: tunnelId,
            name: 'casa',
            status: 'healthy',
            ingress: [
              { hostname: 'app.example.com', path: null, service: 'http://jellyfin:8096' },
              { hostname: null, path: null, service: 'http_status:404' },
            ],
          },
        ],
      }),
    );
    expect(p.status).toBe('complete');
    expect(p.finalAssetId).toBe('jellyfin-1');
    expect(p.hops.map((h) => h.resolver)).toEqual(['tunnel', 'tunnel']);
    // Túnel desconocido o gestionado localmente: corte con su motivo.
    const unknown = path(
      input({
        records: [record('r1', 'app.example.com', `${tunnelId}.cfargotunnel.com`, [], 'CNAME')],
        assets: [ct, cf],
      }),
    );
    expect(unknown).toMatchObject({ status: 'none', cutReason: 'tunnel_unknown' });
    const local = path(
      input({
        records: [record('r1', 'app.example.com', `${tunnelId}.cfargotunnel.com`, [], 'CNAME')],
        assets: [ct, cf],
        tunnels: [{ id: tunnelId, name: 'casa', status: null, ingress: null }],
      }),
    );
    expect(local).toMatchObject({ status: 'partial', cutReason: 'tunnel_no_config' });
  });

  it('CNAME interno: sigue al A con el nombre original como Host', () => {
    const p = path(
      input({
        records: [
          record('r1', 'www.example.com', 'app.example.com', ['r2'], 'CNAME'),
          record('r2', 'app.example.com', '203.0.113.7'),
        ],
        assets: [
          ct,
          {
            ...npm,
            proxy: {
              ...npm.proxy!,
              routes: [route(['www.example.com'], '172.18.0.5', 3000, { source: 'npm' })],
            },
          },
          app,
        ],
        natForwards: [nat],
      }),
    );
    expect(p.finalAssetId).toBe('app');
    expect(p.hops[0]).toMatchObject({ resolver: 'dns', label: 'app.example.com' });
  });

  it('cortes: sin destino, sin nada escuchando y nginx sin leer (sudoers v4)', () => {
    expect(
      path(input({ records: [record('r1', 'x.example.com', '198.51.100.1')] })),
    ).toMatchObject({ status: 'none', cutReason: 'no_target', hops: [] });
    const quiet = path(
      input({
        records: [record('r1', 'x.example.com', '192.168.1.10', ['ct'])],
        assets: [{ ...ct, ports: [] }],
      }),
    );
    expect(quiet).toMatchObject({ status: 'partial', cutReason: 'no_listener' });
    expect(ids(quiet)).toEqual(['ct']);
    const unread = path(
      input({
        records: [record('r1', 'x.example.com', '10.0.0.4', ['srv'])],
        assets: [
          host('srv', '10.0.0.4', {
            ports: [{ proto: 'tcp', address: '0.0.0.0', port: 443, process: 'nginx', pid: 1 }],
            proxy: null,
          }),
        ],
      }),
    );
    expect(unread).toMatchObject({ status: 'partial', cutReason: 'proxy_unreadable' });
  });

  it('un proceso cualquiera en escucha es el destino final (el host o CT)', () => {
    const p = path(
      input({
        records: [record('r1', 'x.example.com', '10.0.0.4', ['srv'])],
        assets: [
          host('srv', '10.0.0.4', {
            ports: [{ proto: 'tcp', address: '0.0.0.0', port: 443, process: 'caddy', pid: 1 }],
          }),
        ],
      }),
    );
    expect(p).toMatchObject({ status: 'complete', finalAssetId: 'srv' });
    expect(p.hops.at(-1)?.label).toBe('srv:443 (caddy)');
  });

  it('detecta ciclos y respeta el tope de saltos', () => {
    // nginx que se envía a sí mismo.
    const loop = path(
      input({
        records: [record('r1', 'x.example.com', '10.0.0.4', ['srv'])],
        assets: [
          host('srv', '10.0.0.4', {
            ports: [{ proto: 'tcp', address: '0.0.0.0', port: 443, process: 'nginx', pid: 1 }],
            proxy: { source: 'nginx', readAt: 'x', routes: [route(['x.example.com'], '10.0.0.4', 443)] },
          }),
        ],
      }),
    );
    expect(loop.cutReason).toBe('cycle');
    // Una cadena de 15 nginx, cada uno al siguiente.
    const chain = Array.from({ length: 15 }, (_, i) =>
      host(`h${i}`, `10.1.0.${i + 1}`, {
        ports: [{ proto: 'tcp', address: '0.0.0.0', port: 443, process: 'nginx', pid: 1 }],
        proxy: {
          source: 'nginx',
          readAt: 'x',
          routes: [route(['x.example.com'], `10.1.0.${i + 2}`, 443)],
        },
      }),
    );
    const long = path(
      input({
        records: [record('r1', 'x.example.com', '10.1.0.1', ['h0'])],
        assets: chain,
      }),
    );
    expect(long.cutReason).toBe('max_hops');
    expect(long.hops.length).toBeLessThanOrEqual(SERVICE_MAX_HOPS + 1);
  });

  it('nginx: sin server para ese nombre, el default_server (deducido)', () => {
    const srv = host('srv', '10.0.0.4', {
      ports: [{ proto: 'tcp', address: '0.0.0.0', port: 443, process: 'nginx', pid: 1 }],
      proxy: {
        source: 'nginx',
        readAt: 'x',
        routes: [
          route(['a.example.com'], '10.0.0.4', 8001),
          route([], '10.0.0.4', 8002, { isDefault: true }),
        ],
      },
    });
    srv.ports!.push({ proto: 'tcp', address: '0.0.0.0', port: 8002, process: 'node', pid: 3 });
    const p = path(
      input({ records: [record('r1', 'b.example.com', '10.0.0.4', ['srv'])], assets: [srv] }),
    );
    expect(p.status).toBe('complete');
    expect(p.confidence).toBe('deduced');
    expect(p.hops.at(-1)?.label).toBe('srv:8002 (node)');
  });
});

it('un camino confirmado por el 80 gana al deducido del default_server del 443', () => {
  const srv: ServiceAsset = {
    id: 'srv',
    name: 'srv',
    type: 'server',
    parentId: null,
    ips: ['10.0.0.4'],
    ports: [
      { proto: 'tcp', address: '0.0.0.0', port: 443, process: 'nginx', pid: 1 },
      { proto: 'tcp', address: '0.0.0.0', port: 80, process: 'nginx', pid: 1 },
      { proto: 'tcp', address: '127.0.0.1', port: 8080, process: 'node', pid: 2 },
    ],
    proxy: {
      source: 'nginx',
      readAt: 'x',
      routes: [
        route([], '10.0.0.4', null, { isDefault: true, upstreams: [] }),
        route(['b.example.com'], '127.0.0.1', 8080, { listen: [80] }),
      ],
    },
  };
  const [p] = resolveServicePaths(
    input({ records: [record('r1', 'b.example.com', '10.0.0.4', ['srv'])], assets: [srv] }),
  );
  expect(p).toMatchObject({ status: 'complete', confidence: 'confirmed' });
  expect(p.hops.at(-1)?.label).toBe('srv:8080 (node)');
});

it('el nginx de un contenedor al que ya enrutó Traefik por el nombre: destino confirmado, sin otro eslabón', () => {
  const ct: ServiceAsset = {
    id: 'ct',
    name: 'ct',
    type: 'lxc',
    parentId: null,
    ips: ['172.20.1.193'],
    ports: [{ proto: 'tcp', address: '0.0.0.0', port: 80, process: 'docker-proxy', pid: 1 }],
  };
  const traefik: ServiceAsset = {
    id: 'traefik',
    name: 'traefik',
    type: 'container',
    parentId: 'ct',
    ips: [],
    ports: null,
    docker: {
      image: 'traefik:v3.1',
      state: 'running',
      ports: [{ containerPort: 80, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 80 }],
      networks: [],
      composeService: 'traefik',
      proxyRoutes: [],
    },
  };
  const app: ServiceAsset = {
    id: 'app',
    name: 'app',
    type: 'container',
    parentId: 'ct',
    ips: [],
    ports: null,
    // nginx:1.25 tal cual: `server_name localhost` y sin proxy_pass.
    proxy: { source: 'nginx', readAt: 'x', routes: [route(['localhost'], 'x', null, { listen: [80], upstreams: [] })] },
    docker: {
      image: 'nginx:1.25',
      state: 'running',
      ports: [{ containerPort: 80, proto: 'tcp', hostIp: null, hostPort: null }],
      networks: [],
      composeService: 'app',
      proxyRoutes: [
        {
          source: 'traefik',
          hosts: ['proxy-prueba.example.com'],
          listen: [],
          isDefault: false,
          path: null,
          upstreams: [{ scheme: 'http', host: PROXY_SELF_HOST, port: 80 }],
        },
      ],
    },
  };
  const [p] = resolveServicePaths(
    input({ records: [record('r1', 'proxy-prueba.example.com', '172.20.1.193', ['ct'])], assets: [ct, traefik, app] }),
  );
  expect(p).toMatchObject({ status: 'complete', confidence: 'confirmed', finalAssetId: 'app' });
  expect(p.hops.map((h) => h.resolver)).toEqual(['dns', 'docker-proxy', 'traefik']);
});

describe('hostMatches', () => {
  it('exacto, comodín de un nivel y .dominio de nginx', () => {
    expect(hostMatches(['a.example.com'], 'a.example.com')).toBe(true);
    expect(hostMatches(['*.example.com'], 'a.example.com')).toBe(true);
    expect(hostMatches(['*.example.com'], 'a.b.example.com')).toBe(false);
    expect(hostMatches(['.example.com'], 'a.b.example.com')).toBe(true);
    expect(hostMatches(['.example.com'], 'example.com')).toBe(true);
    expect(hostMatches(['b.example.com'], 'a.example.com')).toBe(false);
  });
});
