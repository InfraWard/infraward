import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { Asset } from '@infraward/domain';
import {
  type AssetGraph,
  type CollectedFacts,
  type Connector,
  type DockerContainerFacts,
  type DomainServicePaths,
  type EnqueueJobResponse,
  type EnrollServerResponse,
  type JobStatus,
  type NatForward,
  type Page,
  type ServedDomains,
  type ServicePathView,
  type VulnerabilityDetail,
  type VulnerabilitySummary,
} from '@infraward/shared-types';
import type { Queue } from 'bullmq';
import { Redis } from 'ioredis';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import { FakeDns, FakeDomainsApi, FakeTls } from './support/fake-domains.js';
import { createFakePve, type FakePve, type FakePveState } from './support/fake-pve.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
  waitPrioritized, WORK_QUEUES } from './support/worker.js';

const TOKEN = 'CENTINELA-tunel-0123456789abcdefghijklmnopq';
const Z1 = '5'.repeat(32);
const TUNNEL = '0b1c2d3e-1111-2222-3333-444455556666';
const rid = (n: number) => n.toString(16).padStart(32, '0');
const img = (c: string) => `sha256:${c.repeat(64)}`;
const VIEWER = { email: 'viewer-caminos@infraward.test', password: 'otra-contraseña-larga' };
const SERVER_IP = '192.168.50.10';
const PUBLIC_IP = '203.0.113.50';

/** Configuración de NPM (como la vuelca `nginx -T`), con secretos que nunca pueden salir. */
const NPM_CONF = `# configuration file /etc/nginx/nginx.conf:
http {
  server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name localhost-nginx-proxy-manager;
    return 404;
  }
  include /data/nginx/proxy_host/*.conf;
}
# configuration file /data/nginx/proxy_host/1.conf:
server {
  set $forward_scheme http;
  set $server         "app";
  set $port           3000;
  set $token          centinela-variable;
  listen 80;
  listen 443 ssl;
  server_name app.ejemplo.test nat.ejemplo.test;
  ssl_certificate_key /data/custom_ssl/centinela-clave.key;
  auth_basic_user_file /data/access/centinela.htpasswd;
  location / {
    proxy_set_header Authorization "Basic centinela-cabecera";
    include conf.d/include/proxy.conf;
  }
}
# configuration file /etc/nginx/conf.d/include/proxy.conf:
proxy_pass       $forward_scheme://$server:$port$request_uri;
`;

const HOST_NGINX = `# configuration file /etc/nginx/nginx.conf:
http {
  server {
    listen 8081;
    server_name interno.ejemplo.test;
    proxy_set_header X-Api-Key centinela-host;
    location / { proxy_pass http://usuario:centinela-url@127.0.0.1:9000; }
  }
}
`;

const STATE: FakePveState = {
  node: 'docker01',
  cluster: null,
  machineId: '9'.repeat(32),
  ctMachineId: '8'.repeat(32),
  guests: [],
  nodeRoles: ['docker'],
  collectSudoersVersion: 5,
  ip: SERVER_IP,
  ss: [
    'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))',
    'tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=11,fd=7))',
    'tcp LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("docker-proxy",pid=12,fd=7))',
    'tcp LISTEN 0 511 0.0.0.0:8081 0.0.0.0:* users:(("nginx",pid=13,fd=6))',
  ],
  hostNginx: HOST_NGINX,
  hostDocker: {
    containers: [
      {
        name: 'npm',
        image: 'jc21/nginx-proxy-manager:latest',
        imageId: img('1'),
        state: 'running',
        published: { '443/tcp': 443 },
        networks: ['proxy'],
        ip: '172.20.0.2',
        nginx: NPM_CONF,
      },
      {
        name: 'app-1',
        image: 'ghcr.io/ejemplo/app:1',
        imageId: img('2'),
        state: 'running',
        networks: ['proxy'],
        ip: '172.20.0.5',
        composeService: 'app',
        env: 'DB_PASSWORD=centinela-env',
      },
      {
        name: 'traefik',
        image: 'traefik:v3.1',
        imageId: img('3'),
        state: 'running',
        published: { '80/tcp': 80 },
        networks: ['proxy'],
        ip: '172.20.0.3',
      },
      {
        name: 'web',
        image: 'nginxdemos/hello:latest',
        imageId: img('4'),
        state: 'running',
        networks: ['proxy'],
        ip: '172.20.0.4',
        labels: {
          'traefik.enable': 'true',
          'traefik.http.routers.web.rule': 'Host(`web.ejemplo.test`)',
          'traefik.http.services.web.loadbalancer.server.port': '8080',
          'traefik.http.middlewares.auth.basicauth.users': 'admin:centinela-traefik',
          'com.example.secreto': 'centinela-etiqueta',
        },
      },
      {
        name: 'cloudflared',
        image: 'cloudflare/cloudflared:2026.9.0',
        imageId: img('5'),
        state: 'running',
        networks: ['proxy'],
        ip: '172.20.0.9',
      },
    ],
    networks: ['proxy'],
  },
  vulns: {
    [img('2')]: [
      { id: 'CVE-2026-9002', pkg: 'openssl', version: '3.0.1', fixed: '3.0.2', severity: 'CRITICAL' },
    ],
    [img('4')]: [
      { id: 'CVE-2026-9001', pkg: 'zlib', version: '1.2', fixed: '1.3', severity: 'CRITICAL' },
    ],
  },
};

/**
 * Qué servicio sirve cada dominio (QoL-5b) de punta a punta con el worker real: un servidor con
 * Docker simulado (NPM publicado en el 443, Traefik en el 80, una app y cloudflared), su nginx
 * del sistema, y un Cloudflare simulado con registros y un túnel. Rutas filtradas en el
 * servidor, caminos (NAT, NPM, Traefik, túnel), corte y destino fijado a mano, mapa, prioridad de
 * vulnerabilidades, permisos y 0 fugas de la configuración de los proxies.
 */
describe('Caminos de los dominios (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let pve: FakePve;
  const api = new FakeDomainsApi();
  const dns = new FakeDns();
  const tls = new FakeTls();
  let adminToken: string;
  let viewerToken: string;
  let server: Asset;
  let connector: Connector;
  const responses: string[] = [];

  beforeAll(async () => {
    await api.start();
    await dns.start();
    await tls.start(['app.ejemplo.test']);
    api.state = {
      token: TOKEN,
      zones: [{ id: Z1, name: 'ejemplo.test' }],
      records: [
        { id: rid(1), zoneId: Z1, name: 'app.ejemplo.test', type: 'A', content: SERVER_IP },
        { id: rid(2), zoneId: Z1, name: 'web.ejemplo.test', type: 'A', content: SERVER_IP },
        { id: rid(3), zoneId: Z1, name: 'nat.ejemplo.test', type: 'A', content: PUBLIC_IP },
        { id: rid(4), zoneId: Z1, name: 'tun.ejemplo.test', type: 'CNAME', content: `${TUNNEL}.cfargotunnel.com`, proxied: true },
        { id: rid(5), zoneId: Z1, name: 'roto.ejemplo.test', type: 'A', content: '10.99.0.9' },
      ],
      rdap: {},
      tunnels: [
        {
          id: TUNNEL,
          name: 'casa',
          status: 'healthy',
          remote_config: true,
          config: {
            ingress: [
              {
                hostname: 'tun.ejemplo.test',
                service: 'http://app:3000',
                originRequest: { httpHostHeader: 'centinela-tunel-cabecera' },
              },
              { service: 'http_status:404' },
            ],
          },
        },
      ],
    };
    dns.names.set('app.ejemplo.test', '127.0.0.1');

    await prepareEnv('e2e_service_paths');
    app = await createTestApp();
    db = app.get(DataSource);
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(app, VIEWER.email, VIEWER.password);

    pve = createFakePve();
    pve.setState(STATE);
    const res = await request('POST', '/assets/enroll', { host: '127.0.0.1', port: 22, name: 'docker01' });
    expect(res.statusCode).toBe(201);
    server = res.json<EnrollServerResponse>().asset as unknown as Asset;
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [server.id, pve.fingerprint],
    );
    worker = await startWorker({
      ...pve.workerEnv(),
      CLOUDFLARE_API_URL: `${api.url}/client/v4`,
      RDAP_BOOTSTRAP_URL: `${api.url}/rdap/dns.json`,
      DOMAINS_DNS_SERVERS: dns.server,
      DOMAINS_TLS_PORT: String(tls.port),
      DOMAINS_TLS_TIMEOUT_MS: '2000',
    });
  });

  afterAll(async () => {
    await stopWorker(worker);
    await app?.close();
    await api.stop();
    await dns.stop();
    await tls.stop();
  });

  async function request(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    payload?: object,
    token: string | null = adminToken,
  ) {
    const res = await app.inject({
      method,
      url,
      payload,
      headers: token ? authHeaders(token) : {},
    });
    responses.push(JSON.stringify(res.headers), res.body);
    return res;
  }

  const get = async <T>(url: string): Promise<T> => {
    const res = await request('GET', url);
    expect(res.statusCode, res.body).toBe(200);
    return res.json<T>();
  };

  async function finished(id: string): Promise<JobStatus> {
    let last: JobStatus | undefined;
    await waitFor(
      async () => {
        last = await get<JobStatus>(`/jobs/${id}`);
        return last.state === 'completed' || last.state === 'failed';
      },
      60_000,
      () => `job sin terminar: ${JSON.stringify(last)}\n${worker?.output.join('')}`,
    );
    expect(last!.state, JSON.stringify(last)).toBe('completed');
    return last!;
  }

  async function settle(): Promise<void> {
    for (const name of WORK_QUEUES) {
      const queue = app.get<Queue>(getQueueToken(name));
      await waitFor(
        async () => {
          const counts = await queue.getJobCounts('waiting', 'active', 'delayed', 'prioritized');
          return Object.values(counts).every((n) => n === 0);
        },
        60_000,
        () => `cola ${name} sin vaciar\n${worker?.output.join('')}`,
      );
    }
  }

  const byName = (name: string) =>
    db.getRepository(Asset).findOneByOrFail({ name });
  /** Los registros DNS se llaman «<nombre> · <tipo>». */
  const record = (name: string, type = 'A') => byName(`${name} · ${type}`);
  const pathOf = async (name: string, type?: string) =>
    get<ServicePathView>(`/assets/${(await record(name, type)).id}/service-path`);

  it('recolección y descubrimiento: rutas de nginx, NPM y Traefik, solo nombres y destinos', async () => {
    const res = await request('POST', `/assets/${server.id}/collect`);
    expect(res.statusCode).toBe(202);
    await finished(res.json<EnqueueJobResponse>().id);
    await settle();

    // nginx del sistema: filtrado en el servidor con el filtro que pasa el worker a Ansible.
    const host = await db.getRepository(Asset).findOneByOrFail({ id: server.id });
    const facts = host.facts as unknown as CollectedFacts;
    expect(facts.proxy?.routes).toEqual([
      expect.objectContaining({
        source: 'nginx',
        hosts: ['interno.ejemplo.test'],
        listen: [8081],
        upstreams: [{ scheme: 'http', host: '127.0.0.1', port: 9000 }],
      }),
    ]);
    // Solo las notas de la v6 (procesos) y la v7 (sshd): las rutas de los proxies (v5) sí se leen.
    expect(facts.infraward.sudoersNotes).toEqual([
      expect.stringContaining('requiere sudoers v6'),
      expect.stringContaining('requiere sudoers v7'),
    ]);
    expect(pve.ansibleRuns().at(-1)?.vars).toHaveProperty('infraward_nginx_filter');

    // NPM en un contenedor: `docker exec … nginx -T` por el ayudante, filtrado allí.
    const npm = (await byName('npm')).facts.docker as unknown as DockerContainerFacts;
    expect(npm.proxy?.source).toBe('npm');
    expect(npm.proxy?.routes).toContainEqual(
      expect.objectContaining({
        hosts: ['app.ejemplo.test', 'nat.ejemplo.test'],
        upstreams: [{ scheme: 'http', host: 'app', port: 3000 }],
      }),
    );
    expect(pve.sshCommands().filter((c) => c.includes('docker-nginx-routes'))).toHaveLength(1);
    // Traefik: solo las etiquetas de la lista blanca, convertidas en rutas.
    const web = (await byName('web')).facts.docker as unknown as DockerContainerFacts;
    expect(web.proxyRoutes).toEqual([
      expect.objectContaining({
        source: 'traefik',
        hosts: ['web.ejemplo.test'],
        upstreams: [{ scheme: 'http', host: '@self', port: 8080 }],
      }),
    ]);
    const app1 = (await byName('app-1')).facts.docker as unknown as DockerContainerFacts;
    expect(app1.composeService).toBe('app');
    expect(app1.networks?.[0]).toMatchObject({ name: 'proxy', aliases: ['app'] });
  });

  it('conector con túnel: caminos por NPM, Traefik y el túnel hasta el contenedor final', async () => {
    const created = await request('POST', '/connectors', {
      kind: 'cloudflare',
      name: 'Cloudflare con túnel',
      apiToken: TOKEN,
    });
    expect(created.statusCode).toBe(201);
    connector = created.json<Connector>();
    await settle();
    const tunnels = (await db.getRepository(Asset).findOneByOrFail({ id: connector.id })).facts
      .connector as { tunnels: { items: unknown[]; error: string | null } };
    expect(tunnels.tunnels.error).toBeNull();
    expect(JSON.stringify(tunnels.tunnels.items)).not.toContain('centinela');

    const app1 = await byName('app-1');
    const npm = await byName('npm');
    const appPath = await pathOf('app.ejemplo.test');
    expect(appPath).toMatchObject({ status: 'complete', confidence: 'confirmed', final: { id: app1.id } });
    expect(appPath.hops.map((h) => [h.resolver, h.asset?.name ?? null, h.port])).toEqual([
      ['dns', 'docker01', 443],
      ['docker-proxy', 'npm', 443],
      ['npm', 'app-1', 3000],
    ]);
    expect(appPath.hops[2].source).toBe(
      'npm: server_name app.ejemplo.test, nat.ejemplo.test → app:3000',
    );

    // web: el 443 solo llega al default de NPM (deducido); gana el 80 de Traefik (confirmado).
    const webPath = await pathOf('web.ejemplo.test');
    expect(webPath).toMatchObject({ status: 'complete', confidence: 'confirmed' });
    expect(webPath.final?.name).toBe('web');
    expect(webPath.hops.map((h) => h.resolver)).toEqual(['dns', 'docker-proxy', 'traefik']);

    const tunPath = await pathOf('tun.ejemplo.test', 'CNAME');
    expect(tunPath).toMatchObject({ status: 'complete', final: { id: app1.id } });
    expect(tunPath.hops[1].source).toContain('cloudflared en cloudflared');

    // Sin NAT declarado la IP pública no lleva a nada.
    expect(await pathOf('nat.ejemplo.test')).toMatchObject({ status: 'none', cutReason: 'no_target' });

    // Relaciones: «servido por» y «envía a» entre eslabones.
    const rels: { type: string; parent: string; child: string }[] = await db.query(
      `SELECT r.type::text AS type, p.name AS parent, c.name AS child FROM asset_relations r
         JOIN assets p ON p.id = r.parent_id JOIN assets c ON c.id = r.child_id
        WHERE r.type IN ('served_by', 'routes_to') ORDER BY 1, 2, 3`,
    );
    expect(rels).toEqual(
      expect.arrayContaining([
        { type: 'served_by', parent: 'app.ejemplo.test · A', child: 'app-1' },
        { type: 'served_by', parent: 'web.ejemplo.test · A', child: 'web' },
        { type: 'served_by', parent: 'tun.ejemplo.test · CNAME', child: 'app-1' },
        { type: 'routes_to', parent: 'docker01', child: 'npm' },
        { type: 'routes_to', parent: 'npm', child: 'app-1' },
        { type: 'routes_to', parent: 'traefik', child: 'web' },
      ]),
    );
    // Dominio: el camino de cada registro.
    const domain = await db.getRepository(Asset).findOneByOrFail({ name: 'ejemplo.test', type: 'domain' });
    const paths = await get<DomainServicePaths>(`/assets/${domain.id}/service-paths`);
    expect(paths.paths.map((p) => [p.record, p.status])).toEqual([
      ['app.ejemplo.test', 'complete'],
      ['nat.ejemplo.test', 'none'],
      ['roto.ejemplo.test', 'none'],
      ['tun.ejemplo.test', 'complete'],
      ['web.ejemplo.test', 'complete'],
    ]);
    // Asset: lo que sirve y lo que pasa por él.
    const served = await get<ServedDomains>(`/assets/${npm.id}/served-domains`);
    expect(served.records.map((r) => [r.record.name, r.role])).toEqual([
      ['app.ejemplo.test · A', 'via'],
    ]);
  });

  it('reenvío NAT en Ajustes: permisos, conflicto y camino desde la IP pública', async () => {
    const body = { publicIp: PUBLIC_IP, publicPort: 443, targetAssetId: server.id, targetPort: 443, description: 'Router de casa' };
    expect((await request('POST', '/settings/nat-forwards', body, viewerToken)).statusCode).toBe(403);
    expect((await request('POST', '/settings/nat-forwards', { ...body, publicIp: 'no-ip' })).statusCode).toBe(400);
    const created = await request('POST', '/settings/nat-forwards', body);
    expect(created.statusCode, created.body).toBe(201);
    expect(created.json<NatForward>()).toMatchObject({ publicIp: PUBLIC_IP, target: { name: 'docker01' } });
    expect((await request('POST', '/settings/nat-forwards', body)).statusCode).toBe(409);
    expect((await get<NatForward[]>('/settings/nat-forwards'))).toHaveLength(1);

    const nat = await pathOf('nat.ejemplo.test');
    expect(nat).toMatchObject({ status: 'complete', final: { name: 'app-1' } });
    expect(nat.hops.map((h) => [h.resolver, h.label])).toEqual([
      ['dns', `${PUBLIC_IP}:443`],
      ['nat', 'docker01:443'],
      ['docker-proxy', 'npm:443'],
      ['npm', 'app-1:3000'],
    ]);
  });

  it('cadena cortada: se fija el destino a mano y se quita', async () => {
    const roto = await record('roto.ejemplo.test');
    const app1 = await byName('app-1');
    expect(
      (await request('POST', `/assets/${roto.id}/service-path/pin`, { targetAssetId: app1.id }, viewerToken)).statusCode,
    ).toBe(403);
    // Ni un registro ni un dominio como destino.
    expect(
      (await request('POST', `/assets/${roto.id}/service-path/pin`, { targetAssetId: roto.id })).statusCode,
    ).toBe(400);
    const pinned = await request('POST', `/assets/${roto.id}/service-path/pin`, { targetAssetId: app1.id });
    expect(pinned.statusCode, pinned.body).toBe(200);
    expect(pinned.json<ServicePathView>()).toMatchObject({
      status: 'manual',
      final: { id: app1.id },
      pinned: { asset: { id: app1.id }, by: ADMIN.email },
    });
    const servedBy: unknown[] = await db.query(
      `SELECT 1 FROM asset_relations WHERE type = 'served_by' AND parent_id = $1 AND child_id = $2`,
      [roto.id, app1.id],
    );
    expect(servedBy).toHaveLength(1);
    const served = await get<ServedDomains>(`/assets/${app1.id}/served-domains`);
    expect(served.records.filter((r) => r.role === 'final').map((r) => r.record.name).sort()).toEqual([
      'app.ejemplo.test · A',
      'nat.ejemplo.test · A',
      'roto.ejemplo.test · A',
      'tun.ejemplo.test · CNAME',
    ]);

    const unpinned = await request('DELETE', `/assets/${roto.id}/service-path/pin`);
    expect(unpinned.statusCode).toBe(200);
    expect(unpinned.json<ServicePathView>()).toMatchObject({ status: 'none', pinned: null, final: null });
    expect((await request('DELETE', `/assets/${roto.id}/service-path/pin`)).statusCode).toBe(409);
    const audit = (await request('GET', '/audit?category=service')).json<{ items: { action: string }[] }>();
    expect(audit.items.map((i) => i.action).sort()).toEqual(['service.path_pinned', 'service.path_unpinned']);
  });

  it('mapa de un registro: el camino completo, aunque quede lejos del centro', async () => {
    const nat = await record('nat.ejemplo.test');
    const graph = await get<AssetGraph>(`/assets/${nat.id}/graph?depth=1`);
    const names = new Map(graph.nodes.map((n) => [n.id, n.name]));
    expect(graph.servicePath?.map((id) => names.get(id))).toEqual([
      'nat.ejemplo.test · A',
      'docker01',
      'npm',
      'app-1',
    ]);
    const edges = graph.edges.map((e) => `${names.get(e.source)}>${names.get(e.target)}:${e.type}`);
    expect(edges).toEqual(
      expect.arrayContaining([
        'docker01>npm:routes_to',
        'npm>app-1:routes_to',
        'nat.ejemplo.test · A>app-1:served_by',
      ]),
    );
  });

  it('vulnerabilidades: lo expuesto con un nombre público va antes (un motivo de su prioridad)', async () => {
    await waitPrioritized(db);
    const list = await get<Page<VulnerabilitySummary>>('/vulnerabilities?limit=50');
    const ids = list.items.map((v) => v.vulnerabilityId);
    // Los dos son CRITICAL: 9002 (app, servida por nat y tun, públicos) antes que 9001 (web, solo
    // con una IP privada).
    expect(ids.indexOf('CVE-2026-9002')).toBeLessThan(ids.indexOf('CVE-2026-9001'));
    expect(list.items.find((v) => v.vulnerabilityId === 'CVE-2026-9002')?.exposure).toMatchObject({
      publicDomains: 2,
    });
    expect(list.items.find((v) => v.vulnerabilityId === 'CVE-2026-9001')?.exposure).toBeNull();
    const only = await get<Page<VulnerabilitySummary>>('/vulnerabilities?exposure=public');
    expect(only.items.map((v) => v.vulnerabilityId)).toEqual(['CVE-2026-9002']);
    const detail = await get<VulnerabilityDetail>('/vulnerabilities/CVE-2026-9002');
    const flat = (nodes: VulnerabilityDetail['tree']): VulnerabilityDetail['tree'] =>
      nodes.flatMap((n) => [n, ...flat(n.children)]);
    expect(flat(detail.tree).find((n) => n.name === 'app-1')?.publicDomains).toEqual([
      'nat.ejemplo.test',
      'tun.ejemplo.test',
    ]);
  });

  it('0 fugas de la configuración de los proxies, del túnel y del token', async () => {
    const dump: { t: string }[] = await db.query(
      `SELECT concat_ws(' ', (SELECT string_agg(row_to_json(j)::text, ' ') FROM job_runs j),
                             (SELECT string_agg(row_to_json(a)::text, ' ') FROM audit_events a),
                             (SELECT string_agg(row_to_json(s)::text, ' ') FROM assets s),
                             (SELECT string_agg(row_to_json(s)::text, ' ') FROM snapshots s),
                             (SELECT string_agg(row_to_json(p)::text, ' ') FROM dns_service_paths p)) AS t`,
    );
    const redis = new Redis({
      host: process.env.REDIS_HOST,
      port: Number(process.env.REDIS_PORT),
      db: Number(process.env.REDIS_DB),
    });
    const values: string[] = [];
    for (const key of await redis.keys('*')) {
      const type = await redis.type(key);
      if (type === 'hash') values.push(JSON.stringify(await redis.hgetall(key)));
      else if (type === 'string') values.push((await redis.get(key)) ?? '');
      else if (type === 'list') values.push((await redis.lrange(key, 0, -1)).join(' '));
    }
    await redis.quit();
    const everything = [dump[0].t, ...responses, worker!.output.join(''), ...values].join('\n');
    for (const secret of [
      'centinela',
      'Authorization',
      'htpasswd',
      'basicauth',
      'X-Api-Key',
      'originRequest',
      TOKEN,
    ])
      expect(everything, secret).not.toContain(secret);
  });
});
