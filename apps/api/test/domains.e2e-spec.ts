import { getQueueToken } from '@nestjs/bullmq';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { Asset } from '@infraward/domain';
import {
  type AssetDomains,
  type AssetTreeSummaryNode,
  type CertificateFacts,
  type Connector,
  type ConnectorTestResponse,
  type DashboardSummary,
  type DnsRecordCheck,
  type EnqueueJobResponse,
  type JobStatus,
  type NotificationPage,
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
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker, WORK_QUEUES } from './support/worker.js';

const TOKEN = 'CENTINELA-cloudflare-0123456789abcdefghijklmn';
const BAD_TOKEN = 'token-malo-0123456789abcdefghijklmnopqrst';
const Z1 = '1'.repeat(32);
const rid = (n: number) => n.toString(16).padStart(32, '0');
const VIEWER = { email: 'viewer-dominios@infraward.test', password: 'otra-contraseña-larga' };
const OPERATOR = { email: 'operador-dominios@infraward.test', password: 'otra-contraseña-larga' };
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

/**
 * Inventario de dominios (DESIGN §13) de punta a punta con el worker real: conector de
 * Cloudflare simulado (comprueba el Bearer), RDAP simulado, un DNS por UDP y un servidor TLS
 * local. Alta y prueba del token, sincronización, enlaces `resolves_to`, «dominios que le
 * apuntan», colgantes de cada nivel y «esperado», missing → retired, proyectos y tags,
 * caducidades con avisos, permisos, baja con el borrado del token y 0 fugas.
 */
describe('Dominios (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  const api = new FakeDomainsApi();
  const dns = new FakeDns();
  const tls = new FakeTls();
  let adminToken: string;
  let viewerToken: string;
  let operatorToken: string;
  const responses: string[] = [];
  let web: Asset;
  let retiredServer: Asset;
  let connector: Connector;

  beforeAll(async () => {
    await api.start();
    await dns.start();
    await tls.start(['ejemplo.test', 'www.ejemplo.test', 'app.ejemplo.test']);
    api.state = {
      token: TOKEN,
      zones: [{ id: Z1, name: 'ejemplo.test' }],
      records: [
        // A a un servidor del inventario (por su interfaz) y a otro por su host de conexión.
        { id: rid(1), zoneId: Z1, name: 'ejemplo.test', type: 'A', content: '203.0.113.10' },
        { id: rid(2), zoneId: Z1, name: 'www.ejemplo.test', type: 'CNAME', content: 'ejemplo.test', proxied: true },
        { id: rid(3), zoneId: Z1, name: 'app.ejemplo.test', type: 'CNAME', content: 'www.ejemplo.test' },
        // Colgantes: retirado, privada desconocida, CNAME interno sin destino, takeover.
        { id: rid(4), zoneId: Z1, name: 'viejo.ejemplo.test', type: 'A', content: '10.0.0.99' },
        { id: rid(5), zoneId: Z1, name: 'lab.ejemplo.test', type: 'A', content: '10.99.99.99' },
        { id: rid(6), zoneId: Z1, name: 'roto.ejemplo.test', type: 'CNAME', content: 'nadie.ejemplo.test' },
        { id: rid(7), zoneId: Z1, name: 'blog.ejemplo.test', type: 'CNAME', content: 'viejo-blog.herokuapp.com' },
        // Informativo: IP pública que no está en el inventario.
        { id: rid(8), zoneId: Z1, name: 'saas.ejemplo.test', type: 'A', content: '198.51.100.20' },
        { id: rid(9), zoneId: Z1, name: 'ejemplo.test', type: 'MX', content: 'mail.ejemplo.test' },
      ],
      rdap: { 'ejemplo.test': inDays(200) },
    };
    for (const name of ['ejemplo.test', 'www.ejemplo.test', 'app.ejemplo.test'])
      dns.names.set(name, '127.0.0.1');

    await prepareEnv('e2e_domains');
    app = await createTestApp();
    db = app.get(DataSource);
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    await app.get(UsersService).create(OPERATOR.email, OPERATOR.password, 'operator');
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(app, VIEWER.email, VIEWER.password);
    operatorToken = await loginToken(app, OPERATOR.email, OPERATOR.password);

    const repo = db.getRepository(Asset);
    web = await repo.save(
      repo.create({
        type: 'server',
        discoveredName: 'web-1',
        status: 'active',
        facts: {
          network: {
            hostname: 'web-1',
            fqdn: null,
            defaultIpv4: '192.168.1.20',
            interfaces: [
              { name: 'eth0', mac: null, active: true, ipv4: ['203.0.113.10/24'], ipv6: [] },
              { name: 'docker0', mac: null, active: true, ipv4: ['172.17.0.1'], ipv6: [] },
            ],
          },
        },
      }),
    );
    retiredServer = await repo.save(
      repo.create({
        type: 'server',
        discoveredName: 'antiguo',
        status: 'retired',
        connection: { host: '10.0.0.99', port: 22, user: 'inventory' },
        facts: {},
      }),
    );

    worker = await startWorker({
      CLOUDFLARE_API_URL: `${api.url}/client/v4`,
      RDAP_BOOTSTRAP_URL: `${api.url}/rdap/dns.json`,
      DOMAINS_DNS_SERVERS: dns.server,
      DOMAINS_TLS_PORT: String(tls.port),
      DOMAINS_TLS_TIMEOUT_MS: '2000',
      RECONCILE_RETIRE_AFTER: '3',
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
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
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

  async function settle(): Promise<void> {
    const queues = WORK_QUEUES.map((q) => app.get<Queue>(getQueueToken(q)));
    await waitFor(
      async () => {
        for (const queue of queues) {
          const counts = await queue.getJobCounts('waiting', 'active', 'delayed', 'prioritized');
          if (Object.values(counts).some((n) => n > 0)) return false;
        }
        return true;
      },
      60_000,
      () => `colas sin terminar\n${worker?.output.join('')}`,
    );
  }

  async function sync(): Promise<JobStatus & { result?: Record<string, unknown> }> {
    const res = await request('POST', `/connectors/${connector.id}/sync`);
    expect(res.statusCode).toBe(202);
    const { id } = res.json<EnqueueJobResponse>();
    let last: JobStatus | undefined;
    await waitFor(
      async () => {
        last = (await request('GET', `/jobs/${id}`)).json<JobStatus>();
        return last.state === 'completed' || last.state === 'failed';
      },
      60_000,
      () => `sync sin terminar: ${JSON.stringify(last)}\n${worker?.output.join('')}`,
    );
    expect(last!.state, JSON.stringify(last)).toBe('completed');
    return last as JobStatus & { result?: Record<string, unknown> };
  }

  const byName = async (name: string, type?: string) =>
    db.getRepository(Asset).findOneByOrFail({ name, ...(type ? { type: type as never } : {}) });
  const check = async (name: string) =>
    (await request('GET', `/assets/${(await byName(name)).id}/dns-check`)).json<DnsRecordCheck | null>();

  it('permisos: un lector no ve ni crea conectores; un operador no los crea', async () => {
    expect((await request('GET', '/connectors', undefined, viewerToken)).statusCode).toBe(403);
    for (const token of [viewerToken, operatorToken])
      expect(
        (await request('POST', '/connectors', { kind: 'cloudflare', name: 'x', apiToken: TOKEN }, token))
          .statusCode,
      ).toBe(403);
    // Ni un token raro ni un tipo de asset `dns_provider` a mano.
    expect(
      (await request('POST', '/connectors', { kind: 'cloudflare', name: 'x', apiToken: 'corto' })).statusCode,
    ).toBe(400);
    expect(
      (await request('POST', '/assets', { type: 'dns_provider', name: 'x' })).statusCode,
    ).toBe(400);
  });

  it('alta con un token malo: se guarda, la prueba falla y no se sincroniza; con el bueno, sí', async () => {
    const created = await request('POST', '/connectors', {
      kind: 'cloudflare',
      name: 'Cloudflare de pruebas',
      apiToken: BAD_TOKEN,
    });
    expect(created.statusCode).toBe(201);
    connector = created.json<Connector>();
    expect(connector).toMatchObject({
      kind: 'cloudflare',
      hasToken: true,
      secretProvider: 'local',
      domains: 0,
      verify: { ok: false, error: 'HTTP 401 (código 1000)' },
    });
    expect(created.body).not.toContain(BAD_TOKEN);
    // El token, cifrado en local_secrets y solo como referencia en el asset.
    const asset = await db.getRepository(Asset).findOneByOrFail({ id: connector.id });
    expect(asset.credentials.apiToken).toBe(`secret://local/connectors/${connector.id}/cloudflare#apiToken`);
    const rows: { ciphertext: Buffer }[] = await db.query(
      `SELECT ciphertext FROM local_secrets WHERE path = $1`,
      [`connectors/${connector.id}/cloudflare`],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].ciphertext.toString('latin1')).not.toContain(BAD_TOKEN);

    const replaced = await request('PUT', `/connectors/${connector.id}/token`, { apiToken: TOKEN });
    expect(replaced.statusCode).toBe(200);
    expect(replaced.json<Connector>().verify).toMatchObject({
      ok: true,
      zones: 1,
      accounts: ['Cuenta de pruebas'],
    });
    const test = await request('POST', `/connectors/${connector.id}/test`);
    expect(test.json<ConnectorTestResponse>().verify?.ok).toBe(true);
  });

  it('sincroniza: cuenta → dominio → registros y certificado del 443, con RDAP', async () => {
    const job = await sync();
    expect(job.result).toMatchObject({ zones: 1, records: 9, certificates: 1, complete: true });
    const tree = (await request('GET', `/assets/${connector.id}/tree`)).json<AssetTreeSummaryNode>();
    expect(tree.type).toBe('dns_provider');
    const domain = tree.children.find((c) => c.type === 'domain')!;
    expect(domain.name).toBe('ejemplo.test');
    expect(Date.parse(domain.expiresAt!)).toBeGreaterThan(Date.now() + 199 * 86_400_000);
    expect(domain.children.filter((c) => c.type === 'dns_record')).toHaveLength(9);
    const cert = domain.children.find((c) => c.type === 'certificate')!;
    expect(cert.expiresAt).not.toBeNull();
    const certFacts = (await db.getRepository(Asset).findOneByOrFail({ id: cert.id })).facts
      .certificate as CertificateFacts;
    expect(certFacts).toMatchObject({
      fingerprint256: tls.fingerprint,
      selfSigned: true,
      repository: 'tls',
      usedBy: ['app.ejemplo.test', 'ejemplo.test', 'www.ejemplo.test'],
    });
    // Los comentarios de Cloudflare no se guardan.
    const record = await byName('www.ejemplo.test · CNAME');
    expect(JSON.stringify(record.facts)).not.toContain('nota');
    expect(record.facts.tls).toMatchObject({ status: 'ok', authorized: false, hostnameMatch: true });
  });

  it('enlaces resolves_to y «dominios que le apuntan» (directo y por CNAME)', async () => {
    const res = (await request('GET', `/assets/${web.id}/domains`)).json<AssetDomains>();
    expect(res.records.map((r) => [r.dns.name, r.dns.type, r.hops, r.via.map((v) => v.name)])).toEqual([
      ['ejemplo.test', 'A', 1, []],
      ['www.ejemplo.test', 'CNAME', 2, ['ejemplo.test · A']],
      ['app.ejemplo.test', 'CNAME', 3, ['www.ejemplo.test · CNAME', 'ejemplo.test · A']],
    ]);
    expect(res.records[0].certificate?.notAfter).not.toBeNull();
    expect(res.records[0].domain?.name).toBe('ejemplo.test');
    // En el mapa de relaciones del servidor.
    const graph = (await request('GET', `/assets/${web.id}/graph?depth=1`)).json<{
      edges: { type: string; source: string }[];
    }>();
    expect(graph.edges.some((e) => e.type === 'resolves_to')).toBe(true);
    expect(await check('ejemplo.test · A')).toMatchObject({ level: null, reason: 'linked' });
    // Relación automática: no se puede crear a mano.
    expect(
      (await request('POST', '/asset-relations', {
        parentId: (await byName('saas.ejemplo.test · A')).id,
        childId: web.id,
        type: 'resolves_to',
      })).statusCode,
    ).toBe(400);
  });

  it('colgantes: niveles, motivos, panel, notificación y filtro del árbol', async () => {
    expect(await check('viejo.ejemplo.test · A')).toMatchObject({ level: 'high', reason: 'retired_target' });
    expect(await check('lab.ejemplo.test · A')).toMatchObject({ level: 'high', reason: 'private_unknown' });
    expect(await check('roto.ejemplo.test · CNAME')).toMatchObject({ level: 'high', reason: 'cname_internal_missing' });
    expect(await check('blog.ejemplo.test · CNAME')).toMatchObject({
      level: 'high',
      reason: 'cname_nxdomain',
      takeoverService: 'Heroku',
    });
    expect(await check('saas.ejemplo.test · A')).toMatchObject({ level: 'info', reason: 'public_unknown' });
    expect(await check('ejemplo.test · MX')).toBeNull();
    // El registro a un retirado sigue enlazado con él (se ve en su ficha).
    const old = (await request('GET', `/assets/${retiredServer.id}/domains`)).json<AssetDomains>();
    expect(old.records.map((r) => r.dns.name)).toEqual(['viejo.ejemplo.test']);

    const dash = (await request('GET', '/dashboard')).json<DashboardSummary>();
    expect(dash.attention.dnsDangling.count).toBe(4);
    expect(dash.attention.dnsUnknown.count).toBe(1);
    expect(dash.expiryWarningDays).toEqual([30, 7]);
    const notes = (await request('GET', '/notifications')).json<NotificationPage>();
    const dangling = notes.items.filter((n) => n.kind === 'dns_dangling');
    expect(dangling).toHaveLength(1);
    expect(dangling[0].total).toBe(4);
    const tree = (await request('GET', `/assets/${connector.id}/tree`)).json<AssetTreeSummaryNode>();
    const warnings = tree.children[0].children
      .filter((c) => c.dnsWarning)
      .map((c) => [c.name, c.dnsWarning])
      .sort();
    expect(warnings).toEqual([
      ['blog.ejemplo.test · CNAME', 'high'],
      ['lab.ejemplo.test · A', 'high'],
      ['roto.ejemplo.test · CNAME', 'high'],
      ['saas.ejemplo.test · A', 'info'],
      ['viejo.ejemplo.test · A', 'high'],
    ]);
    // Otra sincronización no repite la notificación.
    await sync();
    const again = (await request('GET', '/notifications')).json<NotificationPage>();
    expect(again.items.filter((n) => n.kind === 'dns_dangling')).toHaveLength(1);
  });

  it('«marcar como esperado» silencia el aviso hasta que cambia el valor', async () => {
    const saas = await byName('saas.ejemplo.test · A');
    expect(
      (await request('POST', `/assets/${saas.id}/dns-check/acceptance`, undefined, viewerToken)).statusCode,
    ).toBe(403);
    const accepted = await request('POST', `/assets/${saas.id}/dns-check/acceptance`);
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json<DnsRecordCheck>().accepted?.by).toBe(ADMIN.email);
    expect((await request('GET', '/dashboard')).json<DashboardSummary>().attention.dnsUnknown.count).toBe(0);
    // Sin aviso no hay nada que aceptar.
    expect(
      (await request('POST', `/assets/${(await byName('ejemplo.test · A')).id}/dns-check/acceptance`)).statusCode,
    ).toBe(409);

    api.state.records.find((r) => r.id === rid(8))!.content = '198.51.100.21';
    await sync();
    expect(await check('saas.ejemplo.test · A')).toMatchObject({ level: 'info', accepted: null });
    expect((await request('GET', '/dashboard')).json<DashboardSummary>().attention.dnsUnknown.count).toBe(1);

    const audit = (await request('GET', '/audit?action=dns.check_accepted')).json<{ items: { targetLabel: string }[] }>();
    expect(audit.items.map((i) => i.targetLabel)).toContain('saas.ejemplo.test · A');

    // En bloque por destino: solo los informativos (un lector no puede; uno alto, nunca).
    expect((await check('saas.ejemplo.test · A'))?.sameTarget).toBe(1);
    expect(
      (await request('POST', '/dns-checks/acceptance', { target: '198.51.100.21' }, viewerToken)).statusCode,
    ).toBe(403);
    expect(
      (await request('POST', '/dns-checks/acceptance', { target: '10.99.99.99' })).statusCode,
    ).toBe(409);
    const bulk = await request('POST', '/dns-checks/acceptance', { target: '198.51.100.21' });
    expect(bulk.json()).toEqual({ accepted: 1 });
    expect((await check('saas.ejemplo.test · A'))?.accepted?.by).toBe(ADMIN.email);
  });

  it('un servidor que se retira deja colgante su registro en el siguiente tick', async () => {
    await db.getRepository(Asset).update({ id: web.id }, { status: 'retired' });
    const tick = await request('POST', '/inventory/reconcile', {});
    expect(tick.statusCode).toBe(202);
    await settle();
    expect(await check('ejemplo.test · A')).toMatchObject({ level: 'high', reason: 'retired_target' });
    await db.getRepository(Asset).update({ id: web.id }, { status: 'active' });
    await request('POST', '/inventory/reconcile', {});
    await settle();
    expect(await check('ejemplo.test · A')).toMatchObject({ level: null, reason: 'linked' });
  });

  it('proyectos y tags: el dominio entra con sus registros y los tags sobreviven', async () => {
    const domain = await byName('ejemplo.test', 'domain');
    const project = (await request('POST', '/projects', { name: 'Webs' })).json<{ id: string }>();
    expect(
      (await request('PUT', `/projects/${project.id}/members/${domain.id}`, { mode: 'include' })).statusCode,
    ).toBe(200);
    expect((await request('PATCH', `/assets/${domain.id}`, { tags: ['público'] })).statusCode).toBe(200);
    await sync();
    const record = await byName('www.ejemplo.test · CNAME');
    expect(record.effectiveProjects).toContain(project.id);
    expect((await byName('ejemplo.test', 'domain')).tags).toEqual(['público']);
    const dash = (await request('GET', `/dashboard?projectId=${project.id}`)).json<DashboardSummary>();
    expect(dash.attention.dnsDangling.count).toBe(4);
  });

  it('un registro borrado pasa a missing y, a la 3.ª sincronización, a retired', async () => {
    api.state.records = api.state.records.filter((r) => r.id !== rid(5));
    await sync();
    expect((await byName('lab.ejemplo.test · A')).status).toBe('missing');
    await sync();
    await sync();
    const lab = await byName('lab.ejemplo.test · A');
    expect([lab.status, lab.retiredAuto]).toEqual(['retired', true]);
    // Un listado incompleto (Cloudflare falla) no marca nada.
    api.state.token = 'otro-token-que-no-es-el-guardado-000000';
    const res = await request('POST', `/connectors/${connector.id}/sync`);
    const { id } = res.json<EnqueueJobResponse>();
    await waitFor(
      async () => ['failed', 'completed'].includes((await request('GET', `/jobs/${id}`)).json<JobStatus>().state),
      30_000,
      () => 'sync sin terminar',
    );
    api.state.token = TOKEN;
    expect((await request('GET', `/jobs/${id}`)).json<JobStatus>()).toMatchObject({
      state: 'failed',
      failedReason: 'No se pudo listar los dominios: HTTP 401 (código 1000)',
    });
    expect((await byName('www.ejemplo.test · CNAME')).status).toBe('active');
  });

  it('caducidades: umbrales configurables y un aviso por umbral', async () => {
    const before = (await request('GET', '/notifications?limit=100')).json<NotificationPage>()
      .items.filter((n) => n.kind === 'expiry_warning').length;
    expect((await request('PUT', '/settings/expiry-warnings', { days: [10, 10] })).statusCode).toBe(400);
    expect((await request('PUT', '/settings/expiry-warnings', { days: [400] })).statusCode).toBe(400);
    expect((await request('PUT', '/settings/expiry-warnings', { days: [60] }, viewerToken)).statusCode).toBe(403);
    const set = await request('PUT', '/settings/expiry-warnings', { days: [7, 60] });
    expect(set.json()).toEqual({ days: [60, 7] });
    // El dominio caduca en 5 días (RDAP se vuelve a consultar: el resultado anterior tiene 24 h).
    api.state.rdap['ejemplo.test'] = inDays(5);
    await db.query(
      `UPDATE assets SET facts = jsonb_set(facts, '{registration,checkedAt}', '"2020-01-01T00:00:00Z"')
        WHERE type = 'domain'`,
    );
    await sync();
    await request('POST', '/inventory/reconcile', {});
    await settle();
    const notes = (await request('GET', '/notifications?limit=100')).json<NotificationPage>();
    const expiry = notes.items.filter((n) => n.kind === 'expiry_warning');
    expect(expiry).toHaveLength(before + 1);
    // El certificado (20 días) cruza ahora el de 60; el dominio (5), el de 60 y el de 7.
    expect(expiry[0].message).toContain('ejemplo.test (dominio) caduca en 5 días');
    expect(expiry[0].total).toBe(2);
    const dash = (await request('GET', '/dashboard')).json<DashboardSummary>();
    expect([dash.attention.domainsExpiring.count, dash.attention.certificatesExpiring.count]).toEqual([1, 1]);
    // Otro tick no repite.
    await request('POST', '/inventory/reconcile', {});
    await settle();
    const again = (await request('GET', '/notifications?limit=100')).json<NotificationPage>();
    expect(again.items.filter((n) => n.kind === 'expiry_warning')).toHaveLength(before + 1);
  });

  it('baja del conector: retira su subárbol y borra el token del proveedor de secretos', async () => {
    const res = await request('DELETE', `/connectors/${connector.id}`);
    expect(res.statusCode).toBe(200);
    expect(res.json<{ revocations: { secretRemoved: boolean }[] }>().revocations[0].secretRemoved).toBe(true);
    const rows: unknown[] = await db.query(`SELECT 1 FROM local_secrets WHERE path LIKE 'connectors/%'`);
    expect(rows).toHaveLength(0);
    expect((await byName('www.ejemplo.test · CNAME')).status).toBe('retired');
    expect((await db.getRepository(Asset).findOneByOrFail({ id: connector.id })).credentials).toEqual({});
    expect((await request('GET', '/connectors')).json<Connector[]>()).toEqual([]);
    const audit = (await request('GET', '/audit?category=connector')).json<{ items: { action: string }[] }>();
    expect(new Set(audit.items.map((i) => i.action))).toEqual(
      new Set(['connector.created', 'connector.tested', 'connector.token_replaced', 'connector.sync_requested', 'connector.deleted']),
    );
  });

  it('0 fugas del token: ni en respuestas, logs del worker, job_runs, Redis ni auditoría', async () => {
    for (const secret of [TOKEN, BAD_TOKEN]) {
      expect(responses.join('\n')).not.toContain(secret);
      expect(worker!.output.join('')).not.toContain(secret);
      const dump: { t: string }[] = await db.query(
        `SELECT concat_ws(' ', (SELECT string_agg(row_to_json(j)::text, ' ') FROM job_runs j),
                               (SELECT string_agg(row_to_json(a)::text, ' ') FROM audit_events a),
                               (SELECT string_agg(row_to_json(s)::text, ' ') FROM assets s),
                               (SELECT string_agg(row_to_json(n)::text, ' ') FROM notifications n)) AS t`,
      );
      expect(dump[0].t).not.toContain(secret);
    }
    const redis = new Redis({
      host: process.env.REDIS_HOST,
      port: Number(process.env.REDIS_PORT),
      db: Number(process.env.REDIS_DB),
    });
    const keys = await redis.keys('*');
    const values: string[] = [];
    for (const key of keys) {
      const type = await redis.type(key);
      if (type === 'hash') values.push(JSON.stringify(await redis.hgetall(key)));
      else if (type === 'string') values.push((await redis.get(key)) ?? '');
      else if (type === 'list') values.push((await redis.lrange(key, 0, -1)).join(' '));
    }
    await redis.quit();
    const all = values.join('\n');
    expect(all).not.toContain(TOKEN);
    expect(all).not.toContain(BAD_TOKEN);
    // Solo se llamó a la API de Cloudflare con el Bearer (nunca en la URL).
    expect(api.requests.every((r) => !r.path.includes('CENTINELA'))).toBe(true);
  });
});
