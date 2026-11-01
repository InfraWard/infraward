import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { Snapshot as SnapshotEntity } from '@infraward/domain';
import type {
  Asset,
  AssetRelation,
  AssetRelations,
  AssetSummary,
  AssetTreeSummaryNode,
  CreateAssetRequest,
  DeleteAssetResponse,
  Page,
  Snapshot,
  SnapshotSummary,
  UserProfile,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';

const VIEWER = {
  email: 'viewer@infraward.test',
  password: 'otra-contraseña-larga',
};

describe('Inventario (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let adminToken: string;
  let viewerToken: string;

  beforeAll(async () => {
    await prepareEnv('e2e_assets');
    app = await createTestApp();
    db = app.get(DataSource);
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(app, VIEWER.email, VIEWER.password);
  });

  afterAll(async () => {
    await app?.close();
  });

  /** Petición autenticada (admin por defecto). */
  function request(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    payload?: object,
    token = adminToken,
  ) {
    return app.inject({
      method,
      url,
      payload,
      headers: authHeaders(token),
    });
  }

  async function createAsset(body: CreateAssetRequest): Promise<Asset> {
    const res = await request('POST', '/assets', body);
    expect(res.statusCode, res.body).toBe(201);
    return res.json<Asset>();
  }

  async function relate(
    parent: Asset,
    child: Asset,
    type: AssetRelation['type'] = 'contains',
  ) {
    return request('POST', '/asset-relations', {
      parentId: parent.id,
      childId: child.id,
      type,
    });
  }

  async function contains(parent: Asset, child: Asset): Promise<AssetRelation> {
    const res = await relate(parent, child);
    expect(res.statusCode, res.body).toBe(201);
    return res.json<AssetRelation>();
  }

  /** Árbol reducido a nombres para comparar la jerarquía. */
  type NameTree = { name: string; children: NameTree[] };
  const names = (node: AssetTreeSummaryNode): NameTree => ({
    name: node.name,
    children: node.children.map(names),
  });

  describe('base', () => {
    it('aplica las migraciones y el admin inicial tiene rol admin', async () => {
      expect(await db.showMigrations()).toBe(false);
      const [{ count }] = await db.query<{ count: string }[]>(
        `SELECT count(*) FROM pg_indexes WHERE indexname IN
           ('IDX_assets_facts', 'IDX_assets_tags', 'IDX_assets_roles', 'IDX_snapshots_asset_collected')`,
      );
      expect(Number(count)).toBe(4);

      const admin = await request('GET', '/auth/me');
      expect(admin.json<UserProfile>().role).toBe('admin');
      const viewer = await request('GET', '/auth/me', undefined, viewerToken);
      expect(viewer.json<UserProfile>().role).toBe('viewer');
    });

    it('exige autenticación', async () => {
      for (const url of ['/assets', '/assets/tree']) {
        const res = await app.inject({ method: 'GET', url });
        expect(res.statusCode).toBe(401);
      }
    });

    it('publica los endpoints en OpenAPI', async () => {
      const res = await app.inject({ method: 'GET', url: '/openapi.json' });
      const paths = Object.keys(res.json<{ paths: object }>().paths);
      expect(paths).toEqual(
        expect.arrayContaining([
          '/assets',
          '/assets/tree',
          '/assets/{id}',
          '/assets/{id}/tree',
          '/assets/{id}/relations',
          '/assets/{id}/ancestors',
          '/assets/{id}/snapshots',
          '/asset-relations',
          '/asset-relations/{id}',
          '/snapshots/{id}',
        ]),
      );
    });
  });

  describe('CRUD de assets', () => {
    it('crea con valores por defecto, lee, actualiza y lista', async () => {
      const created = await createAsset({ type: 'server', name: 'web01' });
      expect(created).toMatchObject({
        type: 'server',
        name: 'web01',
        status: 'pending_enrollment',
        naturalKey: null,
        roles: [],
        tags: [],
        facts: {},
      });

      const read = await request('GET', `/assets/${created.id}`);
      // La ficha añade los duplicados (en el alta no se calculan).
      expect(read.json<Asset>()).toEqual({
        ...created,
        duplicateOf: null,
        duplicates: [],
      });

      const updated = await request('PATCH', `/assets/${created.id}`, {
        status: 'active',
        naturalKey: 'machine-id:abc123',
        roles: ['docker-host'],
        tags: ['env:prod'],
        facts: { os: { family: 'Debian', version: '13' } },
      });
      expect(updated.statusCode).toBe(200);
      expect(updated.json<Asset>()).toMatchObject({
        id: created.id,
        type: 'server',
        status: 'active',
        naturalKey: 'machine-id:abc123',
        roles: ['docker-host'],
        tags: ['env:prod'],
        facts: { os: { family: 'Debian', version: '13' } },
      });

      // null quita la naturalKey
      const cleared = await request('PATCH', `/assets/${created.id}`, {
        naturalKey: null,
      });
      expect(cleared.json<Asset>().naturalKey).toBeNull();
    });

    it('valida el cuerpo y los parámetros', async () => {
      const bad = [
        { type: 'nevera', name: 'x' },
        { type: 'server', name: '' },
        { type: 'server', name: 'x', status: 'borrado' },
        // retired solo con DELETE; missing solo la reconciliación
        { type: 'server', name: 'x', status: 'retired' },
        { type: 'server', name: 'x', status: 'missing' },
        { type: 'server', name: 'x', tags: ['con espacio'] },
        { type: 'server', name: 'x', facts: ['no', 'objeto'] },
        { type: 'server', name: 'x', extra: true },
      ];
      for (const body of bad) {
        const res = await request('POST', '/assets', body);
        expect(res.statusCode, JSON.stringify(body)).toBe(400);
      }
      const asset = await createAsset({ type: 'server', name: 'inmutable' });
      const changeType = await request('PATCH', `/assets/${asset.id}`, {
        type: 'vm',
      });
      expect(changeType.statusCode).toBe(400);
      for (const status of ['retired', 'missing']) {
        const res = await request('PATCH', `/assets/${asset.id}`, { status });
        expect(res.statusCode, status).toBe(400);
      }
      expect(
        (await request('GET', `/assets/${asset.id}`)).json<Asset>().status,
      ).toBe('pending_enrollment');
      expect((await request('GET', '/assets/no-uuid')).statusCode).toBe(400);
      expect(
        (await request('GET', '/assets/00000000-0000-4000-8000-000000000000'))
          .statusCode,
      ).toBe(404);
    });

    it('la naturalKey es única por tipo (409)', async () => {
      await createAsset({
        type: 'server',
        name: 'a',
        naturalKey: 'machine-id:dup',
      });
      const dup = await request('POST', '/assets', {
        type: 'server',
        name: 'b',
        naturalKey: 'machine-id:dup',
      });
      expect(dup.statusCode).toBe(409);
      // Otro tipo puede repetirla.
      await createAsset({
        type: 'vm',
        name: 'c',
        naturalKey: 'machine-id:dup',
      });
    });

    it('filtra por tipo, estado, tag, rol, nombre y facts, con paginación', async () => {
      const tag = 'filtro:test';
      await createAsset({
        type: 'server',
        name: 'Filtro-Alfa',
        status: 'active',
        tags: [tag],
        roles: ['plesk'],
        facts: { os: { family: 'Debian' }, cpu: 4 },
      });
      const beta = await createAsset({
        type: 'server',
        name: 'filtro-beta',
        tags: [tag],
        facts: { os: { family: 'RedHat' } },
      });
      // `missing` solo lo pone la reconciliación: se simula en la BD.
      await db.query(`UPDATE assets SET status = 'missing' WHERE id = $1`, [
        beta.id,
      ]);
      await createAsset({ type: 'vm', name: 'filtro_gamma', tags: [tag] });

      const list = async (qs: string) => {
        const res = await request('GET', `/assets?${qs}`);
        expect(res.statusCode, res.body).toBe(200);
        return res.json<Page<Asset>>();
      };
      const byTag = `tag=${encodeURIComponent(tag)}`;

      expect((await list(byTag)).total).toBe(3);
      expect((await list(`${byTag}&type=vm`)).items.map((a) => a.name)).toEqual(
        ['filtro_gamma'],
      );
      expect((await list(`${byTag}&status=missing`)).items[0].name).toBe(
        'filtro-beta',
      );
      expect((await list(`${byTag}&role=plesk`)).items[0].name).toBe(
        'Filtro-Alfa',
      );
      expect((await list('q=FILTRO-')).total).toBe(2);
      // `_` es literal, no comodín
      expect((await list('q=filtro_')).items.map((a) => a.name)).toEqual([
        'filtro_gamma',
      ]);
      const facts = encodeURIComponent(
        JSON.stringify({ os: { family: 'Debian' } }),
      );
      expect(
        (await list(`${byTag}&facts=${facts}`)).items.map((a) => a.name),
      ).toEqual(['Filtro-Alfa']);

      const page = await list(`${byTag}&limit=2&offset=2`);
      expect(page.total).toBe(3);
      expect(page.items).toHaveLength(1);

      for (const qs of [
        'facts=no-json',
        'facts=%5B1%5D',
        'limit=0',
        'limit=500',
        'type=x',
      ]) {
        expect((await request('GET', `/assets?${qs}`)).statusCode, qs).toBe(
          400,
        );
      }
    });
  });

  describe('relaciones y árbol', () => {
    let pve: Asset;
    let ct101: Asset;
    let ct102: Asset;
    let nginx: Asset;
    let postgres: Asset;
    let redis: Asset;
    let standalone: Asset;
    let domain: Asset;

    beforeAll(async () => {
      // Limpia lo creado por otros describe para comparar el bosque completo.
      await db.query('TRUNCATE assets CASCADE');
      pve = await createAsset({
        type: 'server',
        name: 'pve01',
        roles: ['proxmox-node'],
      });
      ct101 = await createAsset({
        type: 'lxc',
        name: 'ct-101',
        naturalKey: 'pve:c1/101',
        facts: {
          proxmox: {
            status: 'running',
            interfaces: [
              { name: 'docker0', ipv4: ['172.17.0.1/16'] },
              { name: 'eth0', ipv4: ['192.168.1.101/24'] },
            ],
          },
        },
      });
      ct102 = await createAsset({
        type: 'lxc',
        name: 'ct-102',
        naturalKey: 'pve:c1/102',
      });
      nginx = await createAsset({
        type: 'container',
        name: 'nginx',
        facts: {
          docker: {
            state: 'exited',
            ports: [
              { proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080, containerPort: 80 },
              { proto: 'tcp', hostIp: '::', hostPort: 8080, containerPort: 80 },
            ],
          },
        },
      });
      postgres = await createAsset({ type: 'container', name: 'postgres' });
      redis = await createAsset({ type: 'container', name: 'redis' });
      standalone = await createAsset({ type: 'server', name: 'backup01' });
      domain = await createAsset({ type: 'domain', name: 'example.org' });

      // La conexión solo la fija el alta; aquí, a mano.
      await db.query(
        `UPDATE assets SET connection = '{"host":"10.0.0.1","port":2222,"user":"infraward"}' WHERE id = $1`,
        [pve.id],
      );
      await contains(pve, ct101);
      await contains(pve, ct102);
      await contains(ct101, nginx);
      await contains(ct101, postgres);
      await contains(ct102, redis);
      // Relación no jerárquica: no debe aparecer en el árbol.
      const rel = await relate(domain, ct101, 'depends_on');
      expect(rel.statusCode).toBe(201);
    });

    it('GET /assets/tree devuelve el bosque con la jerarquía recursiva', async () => {
      const res = await request('GET', '/assets/tree');
      expect(res.statusCode).toBe(200);
      expect(res.json<AssetTreeSummaryNode[]>().map(names)).toEqual([
        { name: 'backup01', children: [] },
        { name: 'example.org', children: [] },
        {
          name: 'pve01',
          children: [
            {
              name: 'ct-101',
              children: [
                { name: 'nginx', children: [] },
                { name: 'postgres', children: [] },
              ],
            },
            { name: 'ct-102', children: [{ name: 'redis', children: [] }] },
          ],
        },
      ]);
      // Los nodos son un resumen: nunca facts, conexión ni credenciales.
      const pveNode = res.json<AssetTreeSummaryNode[]>()[2];
      const { children, ...summary } = pveNode;
      expect(children).toHaveLength(2);
      expect(summary).toEqual({
        id: pve.id,
        name: 'pve01',
        discoveredName: null,
        type: pve.type,
        status: pve.status,
        roles: ['proxmox-node'],
        tags: pve.tags,
        projects: [],
        address: '10.0.0.1:2222',
        ips: ['10.0.0.1'],
        runtimeState: null,
        runtimeDetail: null,
        openFindings: { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        fixableFindings: { HIGH: 0, CRITICAL: 0 },
        kernelNotRunningFindings: 0,
        sudoersOutdated: false,
        collectionWarnings: 0,
        duplicateOf: null,
        machineIdClone: false,
        expiresAt: null,
        dnsWarning: null,
        sshCaOutdated: false,
        sshdRisk: null,
        scanDisabled: false,
      });
      // Dirección y estado de ejecución, leídos de los facts sin devolverlos.
      const ct = children.find((c) => c.name === 'ct-101')!;
      expect([ct.address, ct.runtimeState]).toEqual(['192.168.1.101', 'running']);
      const web = ct.children.find((c) => c.name === 'nginx')!;
      expect([web.address, web.runtimeState, web.runtimeDetail, web.status]).toEqual([
        '8080→80/tcp',
        'stopped',
        'exited',
        nginx.status,
      ]);
      for (const banned of [
        'facts',
        'credentials',
        'connection',
        'hostKeyFingerprint',
        'naturalKey',
      ])
        expect(res.body).not.toContain(`"${banned}"`);
    });

    it('GET /assets/:id/tree devuelve el subárbol desde cualquier nivel', async () => {
      const sub = await request('GET', `/assets/${ct101.id}/tree`);
      expect(sub.statusCode).toBe(200);
      expect(names(sub.json<AssetTreeSummaryNode>())).toEqual({
        name: 'ct-101',
        children: [
          { name: 'nginx', children: [] },
          { name: 'postgres', children: [] },
        ],
      });
      const leaf = await request('GET', `/assets/${redis.id}/tree`);
      expect(names(leaf.json<AssetTreeSummaryNode>())).toEqual({
        name: 'redis',
        children: [],
      });
    });

    it('GET /assets/:id/ancestors da la ruta de la raíz al padre', async () => {
      const res = await request('GET', `/assets/${nginx.id}/ancestors`);
      expect(res.statusCode).toBe(200);
      expect(res.json<AssetSummary[]>()).toEqual([
        { id: pve.id, name: 'pve01', type: 'server', status: pve.status },
        { id: ct101.id, name: 'ct-101', type: 'lxc', status: ct101.status },
      ]);
      expect((await request('GET', `/assets/${pve.id}/ancestors`)).json()).toEqual([]);
      expect(
        (await request('GET', '/assets/00000000-0000-4000-8000-000000000000/ancestors'))
          .statusCode,
      ).toBe(404);
      expect((await request('GET', '/assets/nope/ancestors')).statusCode).toBe(400);
    });

    it('GET /assets/:id/relations lista entrantes y salientes', async () => {
      const res = await request('GET', `/assets/${ct101.id}/relations`);
      const { incoming, outgoing } = res.json<AssetRelations>();
      expect(outgoing.map((r) => r.childId).sort()).toEqual(
        [nginx.id, postgres.id].sort(),
      );
      expect(incoming.map((r) => [r.parentId, r.type]).sort()).toEqual(
        [
          [pve.id, 'contains'],
          [domain.id, 'depends_on'],
        ].sort(),
      );
      // Cada relación trae el resumen del otro extremo (y nada más de él).
      expect(
        outgoing.map((r) => [r.peer.id === r.childId, r.peer.name]).sort(),
      ).toEqual([
        [true, 'nginx'],
        [true, 'postgres'],
      ]);
      const fromPve = incoming.find((r) => r.type === 'contains')!;
      expect(fromPve.peer).toEqual({
        id: pve.id,
        name: 'pve01',
        type: pve.type,
        status: pve.status,
      });
      expect(res.body).not.toContain('"facts"');
    });

    it('rechaza autorrelación, duplicados, segundo padre y ciclos (409)', async () => {
      expect((await relate(pve, pve)).statusCode).toBe(409);
      expect((await relate(domain, ct101, 'depends_on')).statusCode).toBe(409);
      // nginx ya cuelga de ct-101
      expect((await relate(ct102, nginx)).statusCode).toBe(409);
      // nieto → abuelo y padre → hijo directo invertido
      expect((await relate(nginx, pve)).statusCode).toBe(409);
      expect((await relate(ct101, pve)).statusCode).toBe(409);
      // las no jerárquicas pueden ir "hacia arriba"
      expect((await relate(nginx, pve, 'depends_on')).statusCode).toBe(201);
      expect(
        (
          await request('POST', '/asset-relations', {
            parentId: pve.id,
            childId: '00000000-0000-4000-8000-000000000000',
            type: 'contains',
          })
        ).statusCode,
      ).toBe(404);
    });

    it('no permite ciclos ni con altas concurrentes', async () => {
      // Muchos pares A→B / B→A a la vez: sin serializar las altas, alguno acabaría en ciclo.
      const pairs = await Promise.all(
        Array.from({ length: 10 }, async (_, i) => [
          await createAsset({ type: 'vm', name: `ciclo-${i}-a` }),
          await createAsset({ type: 'vm', name: `ciclo-${i}-b` }),
        ]),
      );
      const results = await Promise.all(
        pairs.flatMap(([a, b]) => [relate(a, b), relate(b, a)]),
      );
      for (let i = 0; i < pairs.length; i++) {
        const codes = [results[2 * i], results[2 * i + 1]].map(
          (r) => r.statusCode,
        );
        expect(codes.sort(), `par ${i}`).toEqual([201, 409]);
      }
      // Gane A→B o B→A, purgar ambos deja la BD limpia.
      for (const asset of pairs.flat())
        await request('DELETE', `/assets/${asset.id}?purge=true`);
    });

    it('DELETE /asset-relations/:id quita la relación (el hijo pasa a raíz)', async () => {
      const temp = await createAsset({ type: 'container', name: 'temporal' });
      const rel = await contains(ct102, temp);
      expect(
        (await request('DELETE', `/asset-relations/${rel.id}`)).statusCode,
      ).toBe(204);
      expect(
        (await request('DELETE', `/asset-relations/${rel.id}`)).statusCode,
      ).toBe(404);
      const forest = (await request('GET', '/assets/tree')).json<
        AssetTreeSummaryNode[]
      >();
      expect(forest.map((n) => n.name)).toContain('temporal');
      await request('DELETE', `/assets/${temp.id}?purge=true`);
    });

    it('DELETE retira en cascada todo el subárbol y conserva snapshots', async () => {
      const snapshot = await db
        .getRepository(SnapshotEntity)
        .save({ assetId: nginx.id, facts: { os: 'alpine' }, roles: [] });

      const res = await request('DELETE', `/assets/${ct101.id}`);
      expect(res.statusCode).toBe(200);
      const body = res.json<DeleteAssetResponse>();
      expect(body.mode).toBe('retired');
      expect(body.affectedIds.sort()).toEqual(
        [ct101.id, nginx.id, postgres.id].sort(),
      );

      for (const id of body.affectedIds) {
        expect(
          (await request('GET', `/assets/${id}`)).json<Asset>().status,
        ).toBe('retired');
      }
      expect(
        (await request('GET', `/assets/${pve.id}`)).json<Asset>().status,
      ).toBe('pending_enrollment');
      expect(
        (await request('GET', `/snapshots/${snapshot.id}`)).statusCode,
      ).toBe(200);

      // El árbol oculta lo retirado salvo que se pida; la raíz pedida por id siempre sale.
      const tree = (
        await request('GET', `/assets/${pve.id}/tree`)
      ).json<AssetTreeSummaryNode>();
      expect(tree.children.map((n) => n.name)).toEqual(['ct-102']);
      const full = (
        await request('GET', `/assets/${pve.id}/tree?includeRetired=true`)
      ).json<AssetTreeSummaryNode>();
      expect(full.children.map((n) => n.name)).toEqual(['ct-101', 'ct-102']);
      const retiredRoot = await request('GET', `/assets/${ct101.id}/tree`);
      expect(names(retiredRoot.json<AssetTreeSummaryNode>())).toEqual({
        name: 'ct-101',
        children: [],
      });
      expect(
        (await request('GET', '/assets/tree?includeRetired=quizá')).statusCode,
      ).toBe(400);
    });

    it('un viewer solo puede leer: toda escritura da 403 y no cambia nada', async () => {
      const as = (
        method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
        url: string,
        body?: object,
      ) => request(method, url, body, viewerToken);

      for (const url of [
        '/assets',
        '/assets/tree',
        `/assets/${pve.id}`,
        `/assets/${pve.id}/tree`,
        `/assets/${pve.id}/relations`,
        `/assets/${pve.id}/snapshots`,
      ]) {
        expect((await as('GET', url)).statusCode, url).toBe(200);
      }

      const relationId = (
        await request('GET', `/assets/${ct102.id}/relations`)
      ).json<AssetRelations>().incoming[0].id;
      const writes = [
        as('POST', '/assets', { type: 'server', name: 'intruso' }),
        as('PATCH', `/assets/${standalone.id}`, { displayName: 'renombrado' }),
        as('DELETE', `/assets/${standalone.id}`),
        as('DELETE', `/assets/${pve.id}?purge=true`),
        as('POST', '/asset-relations', {
          parentId: standalone.id,
          childId: domain.id,
          type: 'contains',
        }),
        as('DELETE', `/asset-relations/${relationId}`),
      ];
      for (const res of await Promise.all(writes)) {
        expect(res.statusCode, res.body).toBe(403);
      }

      const after = (
        await request('GET', `/assets/${standalone.id}`)
      ).json<Asset>();
      expect(after).toMatchObject({
        name: 'backup01',
        status: 'pending_enrollment',
      });
      expect(
        (await request('GET', `/assets?q=intruso`)).json<Page<Asset>>().total,
      ).toBe(0);
      expect(
        (
          await request('GET', `/assets/${ct102.id}/relations`)
        ).json<AssetRelations>().incoming,
      ).toHaveLength(1);
    });

    it('el rol se comprueba en la BD: un admin degradado pierde la escritura con el mismo token', async () => {
      await db.query(`UPDATE users SET role = 'viewer' WHERE email = $1`, [
        ADMIN.email,
      ]);
      try {
        expect(
          (await request('DELETE', `/assets/${pve.id}?purge=true`)).statusCode,
        ).toBe(403);
        expect(
          (await request('DELETE', `/assets/${standalone.id}`)).statusCode,
        ).toBe(403);
      } finally {
        await db.query(`UPDATE users SET role = 'admin' WHERE email = $1`, [
          ADMIN.email,
        ]);
      }
      // Y a la inversa: un viewer ascendido escribe sin volver a iniciar sesión.
      await db.query(`UPDATE users SET role = 'editor' WHERE email = $1`, [
        VIEWER.email,
      ]);
      try {
        const res = await request(
          'DELETE',
          `/assets/${standalone.id}`,
          undefined,
          viewerToken,
        );
        expect(res.statusCode).toBe(200);
        // Ascendido a admin sin TOTP: antes de nada, tiene que configurarlo.
        await db.query(`UPDATE users SET role = 'admin' WHERE email = $1`, [
          VIEWER.email,
        ]);
        const blocked = await request('GET', '/assets/tree', undefined, viewerToken);
        expect(blocked.statusCode).toBe(403);
        expect(blocked.json()).toMatchObject({ code: 'mfa_setup_required' });
      } finally {
        await db.query(`UPDATE users SET role = 'viewer' WHERE email = $1`, [
          VIEWER.email,
        ]);
      }
    });

    it('purge borra el subárbol, sus relaciones y snapshots sin dejar huérfanos', async () => {
      const res = await request('DELETE', `/assets/${pve.id}?purge=true`);
      expect(res.statusCode).toBe(200);
      const body = res.json<DeleteAssetResponse>();
      expect(body.mode).toBe('purged');
      expect(body.affectedIds.sort()).toEqual(
        [pve.id, ct101.id, ct102.id, nginx.id, postgres.id, redis.id].sort(),
      );

      for (const id of body.affectedIds) {
        expect((await request('GET', `/assets/${id}`)).statusCode).toBe(404);
      }
      const [{ relations, snapshots }] = await db.query<
        { relations: string; snapshots: string }[]
      >(
        `SELECT (SELECT count(*) FROM asset_relations
                  WHERE parent_id = ANY($1::uuid[]) OR child_id = ANY($1::uuid[])) AS relations,
                (SELECT count(*) FROM snapshots WHERE asset_id = ANY($1::uuid[])) AS snapshots`,
        [body.affectedIds],
      );
      expect([Number(relations), Number(snapshots)]).toEqual([0, 0]);

      const forest = (
        await request('GET', '/assets/tree?includeRetired=true')
      ).json<AssetTreeSummaryNode[]>();
      expect(forest.map((n) => n.name)).toEqual(['backup01', 'example.org']);
    });
  });

  describe('snapshots', () => {
    it('lista el historial (sin facts, del más reciente al más antiguo) y da el detalle', async () => {
      const asset = await createAsset({ type: 'server', name: 'historial' });
      const repo = db.getRepository(SnapshotEntity);
      const older = await repo.save({
        assetId: asset.id,
        collectedAt: new Date('2026-01-01T00:00:00Z'),
        facts: { kernel: '6.1' },
        roles: [],
      });
      const newer = await repo.save({
        assetId: asset.id,
        collectedAt: new Date('2026-02-01T00:00:00Z'),
        facts: { kernel: '6.12' },
        roles: ['docker-host'],
        jobId: 'job-1',
      });

      const list = await request('GET', `/assets/${asset.id}/snapshots`);
      expect(list.statusCode).toBe(200);
      const page = list.json<Page<SnapshotSummary>>();
      expect(page.total).toBe(2);
      expect(page.items.map((s) => s.id)).toEqual([newer.id, older.id]);
      expect(page.items[0]).toEqual({
        id: newer.id,
        assetId: asset.id,
        collectedAt: '2026-02-01T00:00:00.000Z',
        roles: ['docker-host'],
        jobId: 'job-1',
        source: 'collect',
        previousId: null,
        changeSummary: null,
      });

      const detail = await request('GET', `/snapshots/${older.id}`);
      expect(detail.json<Snapshot>()).toMatchObject({
        id: older.id,
        facts: { kernel: '6.1' },
        jobId: null,
        diff: null,
      });

      expect(
        (await request('GET', `/assets/${asset.id}/snapshots?limit=1&offset=1`))
          .json<Page<SnapshotSummary>>()
          .items.map((s) => s.id),
      ).toEqual([older.id]);
      expect(
        (
          await request(
            'GET',
            '/snapshots/00000000-0000-4000-8000-000000000000',
          )
        ).statusCode,
      ).toBe(404);
    });
  });
});
