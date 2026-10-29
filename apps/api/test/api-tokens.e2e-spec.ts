import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type {
  ApiTokenSummary,
  AuditPage,
  CreatedApiTokenResponse,
} from '@infraward/shared-types';
import { Redis } from 'ioredis';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  enableTotp,
  loginToken,
  prepareEnv,
  redisDb,
  redisUrl,
} from './support/app.js';
import { seedInventory, type SeededInventory } from './support/inventory-seed.js';

const EDITOR = { email: 'editora-tokens@infraward.test', password: 'contraseña-de-la-editora' };
const OTHER = { email: 'otro-tokens@infraward.test', password: 'contraseña-del-otro-usuario' };
const DAY = 24 * 60 * 60 * 1000;
const inDays = (n: number) => new Date(Date.now() + n * DAY).toISOString();

/**
 * Tokens de API personales (QoL-6, DESIGN §14): se crean con la sesión web y se enseñan una vez;
 * con `Authorization: Bearer` valen lo que el rol del usuario (o solo para leer), se revocan al
 * momento y nunca se guardan ni se registran en claro.
 */
describe('Tokens de API (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  let editor: string;
  let other: string;
  let inv: SeededInventory;
  const output: string[] = [];
  const responses: string[] = [];
  const secrets: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_tokens');
    for (const stream of [process.stdout, process.stderr]) {
      const write = stream.write.bind(stream) as (...args: unknown[]) => boolean;
      vi.spyOn(stream, 'write').mockImplementation((...args: unknown[]) => {
        output.push(String(args[0]));
        return write(...args);
      });
    }
    app = await createTestApp();
    db = app.get(DataSource);
    const users = app.get(UsersService);
    await users.create(EDITOR.email, EDITOR.password, 'editor');
    await users.create(OTHER.email, OTHER.password, 'viewer');
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    editor = await loginToken(app, EDITOR.email, EDITOR.password);
    other = await loginToken(app, OTHER.email, OTHER.password);
    inv = await seedInventory(db);
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await app?.close();
  });

  async function request(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    options: { session?: string | null; bearer?: string; payload?: object; headers?: object } = {},
  ) {
    const session = options.session === undefined ? (options.bearer ? null : admin) : options.session;
    const res = await app.inject({
      method,
      url,
      payload: options.payload,
      headers: {
        ...(session ? authHeaders(session) : {}),
        ...(options.bearer ? { authorization: `Bearer ${options.bearer}` } : {}),
        ...options.headers,
      },
    });
    responses.push(JSON.stringify(res.headers), res.body);
    return res;
  }

  async function create(
    session: string,
    body: { name: string; scope: 'read' | 'role'; expiresAt?: string },
  ): Promise<CreatedApiTokenResponse> {
    const res = await request('POST', '/auth/tokens', {
      session,
      payload: { expiresAt: inDays(30), ...body },
    });
    expect(res.statusCode).toBe(201);
    const out = res.json<CreatedApiTokenResponse>();
    secrets.push(out.secret);
    return out;
  }

  const audit = async (action: string) =>
    (await request('GET', `/audit?action=${action}`)).json<AuditPage>().items;

  it('crea un token de solo lectura: se enseña una vez y solo se guarda su hash', async () => {
    const out = await create(admin, { name: 'curl', scope: 'read' });
    expect(out.secret).toMatch(/^iwt_[A-Za-z0-9_-]{43}$/);
    expect(out.token).toMatchObject({
      name: 'curl',
      scope: 'read',
      prefix: out.secret.slice(0, 12),
      active: true,
      lastUsedAt: null,
    });
    const list = (await request('GET', '/auth/tokens')).json<ApiTokenSummary[]>();
    expect(list.map((t) => t.id)).toEqual([out.token.id]);
    expect(JSON.stringify(list)).not.toContain(out.secret);
    const [row]: { token_hash: Buffer; prefix: string }[] = await db.query(
      'SELECT token_hash, prefix FROM api_tokens WHERE id = $1',
      [out.token.id],
    );
    expect(row!.token_hash).toHaveLength(32);
    expect(row!.prefix).toBe(out.token.prefix);
    const [event] = await audit('api_token.created');
    expect(event).toMatchObject({
      targetType: 'api_token',
      targetId: out.token.id,
      targetLabel: 'curl',
      details: { scope: 'read', prefix: out.token.prefix },
    });
  });

  it('solo lectura: GET 200 y cualquier escritura 403 (aunque el rol pueda)', async () => {
    const { secret, token } = await create(admin, { name: 'lectura', scope: 'read' });
    const tree = await request('GET', '/assets/tree', { bearer: secret });
    expect(tree.statusCode).toBe(200);
    expect(JSON.stringify(tree.json())).toContain('ct-docker');
    // Lo que el rol puede leer con permiso (admin: auditoría).
    expect((await request('GET', '/audit', { bearer: secret })).statusCode).toBe(200);
    expect((await request('GET', '/assets/export', { bearer: secret })).statusCode).toBe(200);
    for (const [method, url, payload] of [
      ['POST', '/assets/bulk/tags', { assetIds: [inv.web], add: ['x'], remove: [] }],
      ['PATCH', `/assets/${inv.web}`, { tags: ['x'] }],
      ['POST', `/assets/${inv.web}/scan`, {}],
      ['DELETE', `/assets/${inv.web}`, undefined],
    ] as const) {
      const res = await request(method, url, { bearer: secret, payload });
      expect(res.statusCode, `${method} ${url}`).toBe(403);
      expect(res.json()).toMatchObject({ code: 'api_token_read_only' });
    }
    // Sin cookie ni CSRF: el Bearer no necesita token CSRF (no hay cookie que robar).
    const used = (await request('GET', '/auth/tokens')).json<ApiTokenSummary[]>();
    expect(used.find((t) => t.id === token.id)!.lastUsedAt).not.toBeNull();
  });

  it('uno de escritura exige TOTP (y la reautenticación reciente); uno de lectura no', async () => {
    const body = { name: 'sin-2fa', scope: 'role', expiresAt: inDays(30) };
    const denied = await request('POST', '/auth/tokens', { session: editor, payload: body });
    expect(denied.statusCode).toBe(403);
    expect(denied.json()).toMatchObject({
      code: 'mfa_required_for_action',
      action: 'api_token.create_write',
    });
    // Un viewer con alcance `role` no escribe: no lo pide.
    await create(other, { name: 'viewer-role', scope: 'role' });
    // Con TOTP (la sesión queda recién reautenticada al activarlo), sí.
    await enableTotp(app, EDITOR.email, editor);
  });

  it('alcance del rol: escribe lo que el rol permita y queda en la auditoría con su token', async () => {
    const { secret, token } = await create(editor, { name: 'ci', scope: 'role' });
    const res = await request('POST', '/assets/bulk/tags', {
      bearer: secret,
      payload: { assetIds: [inv.web], add: ['desde-api'], remove: [] },
    });
    expect(res.statusCode).toBe(200);
    const [event] = await audit('asset.bulk_tags');
    expect(event).toMatchObject({
      actorEmail: EDITOR.email,
      details: { viaApi: `api:${token.prefix}` },
    });
    // Un editor no gestiona usuarios, ni con token.
    expect((await request('GET', '/users', { bearer: secret })).statusCode).toBe(403);
    // Bajarle el rol surte efecto al momento en el token.
    const [{ id }]: { id: string }[] = await db.query('SELECT id FROM users WHERE email = $1', [
      EDITOR.email,
    ]);
    expect(
      (await request('PATCH', `/users/${id}`, { payload: { role: 'viewer' } })).statusCode,
    ).toBe(200);
    expect(
      (
        await request('POST', '/assets/bulk/tags', {
          bearer: secret,
          payload: { assetIds: [inv.web], add: ['otra'], remove: [] },
        })
      ).statusCode,
    ).toBe(403);
    await request('PATCH', `/users/${id}`, { payload: { role: 'editor' } });
  });

  it('con un token no se gestionan tokens, ni la sesión, ni la contraseña ni el email', async () => {
    const { secret } = await create(admin, { name: 'sin-poderes', scope: 'role' });
    for (const [method, url, payload] of [
      ['GET', '/auth/tokens', undefined],
      ['POST', '/auth/tokens', { name: 'otro', scope: 'role', expiresAt: inDays(5) }],
      ['GET', '/api-tokens', undefined],
      ['GET', '/auth/session', undefined],
      ['POST', '/auth/logout', {}],
      ['POST', '/auth/password', { currentPassword: 'x', newPassword: 'y'.repeat(14) }],
      ['POST', '/auth/email', { email: 'otro@infraward.test', currentPassword: 'x' }],
    ] as const) {
      const res = await request(method, url, { bearer: secret, payload });
      expect(res.statusCode, `${method} ${url}`).toBe(403);
      expect(res.json()).toMatchObject({ code: 'session_required' });
    }
  });

  it('Bearer iwt_ inválido o caducado → 401 (aunque venga una cookie válida); otras credenciales se ignoran', async () => {
    expect((await request('GET', '/assets/tree', { bearer: 'iwt_inventado' })).statusCode).toBe(401);
    expect(
      (await request('GET', '/assets/tree', { session: admin, bearer: 'iwt_inventado' })).statusCode,
    ).toBe(401);
    // Credenciales que el navegador o un proxy añaden solos no estorban a la cookie.
    for (const authorization of ['Basic eDp5', 'Bearer eyJhbGciOi.jwt.ajeno'])
      expect(
        (await request('GET', '/auth/session', { headers: { authorization } })).statusCode,
      ).toBe(200);
    expect(
      (
        await request('GET', '/assets/tree', {
          session: null,
          headers: { authorization: 'Basic eDp5' },
        })
      ).statusCode,
    ).toBe(401);
    const { secret, token } = await create(admin, { name: 'caduca', scope: 'read' });
    await db.query(`UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, [
      token.id,
    ]);
    expect((await request('GET', '/assets/tree', { bearer: secret })).statusCode).toBe(401);
  });

  it('validación: caducidad obligatoria (futura, ≤ 1 año), nombre único y alcance válido', async () => {
    const post = (payload: object) => request('POST', '/auth/tokens', { session: other, payload });
    expect((await post({ name: 'x', scope: 'read' })).statusCode).toBe(400);
    expect((await post({ name: 'x', scope: 'read', expiresAt: inDays(-1) })).statusCode).toBe(400);
    expect((await post({ name: 'x', scope: 'read', expiresAt: inDays(400) })).statusCode).toBe(400);
    expect((await post({ name: 'x', scope: 'admin', expiresAt: inDays(5) })).statusCode).toBe(400);
    await create(other, { name: 'repetido', scope: 'read' });
    expect((await post({ name: 'Repetido', scope: 'read', expiresAt: inDays(5) })).statusCode).toBe(
      409,
    );
  });

  it('revocar: el dueño, al momento (401); uno ajeno es 404', async () => {
    const { secret, token } = await create(other, { name: 'para-revocar', scope: 'read' });
    expect((await request('GET', '/assets/tree', { bearer: secret })).statusCode).toBe(200);
    expect((await request('DELETE', `/auth/tokens/${token.id}`, { session: editor })).statusCode).toBe(
      404,
    );
    const res = await request('DELETE', `/auth/tokens/${token.id}`, { session: other });
    expect(res.statusCode).toBe(200);
    expect(res.json<ApiTokenSummary>()).toMatchObject({ active: false });
    expect((await request('GET', '/assets/tree', { bearer: secret })).statusCode).toBe(401);
    const [event] = await audit('api_token.revoked');
    expect(event).toMatchObject({
      actorEmail: OTHER.email,
      targetId: token.id,
      details: { byOwner: true },
    });
  });

  it('un admin ve los de todos y los revoca; a los demás les es 403', async () => {
    const { secret, token } = await create(editor, { name: 'de-la-editora', scope: 'read' });
    const all = (await request('GET', '/api-tokens')).json<ApiTokenSummary[]>();
    const mine = all.find((t) => t.id === token.id)!;
    expect(mine.user).toMatchObject({ email: EDITOR.email });
    expect(JSON.stringify(all)).not.toMatch(/iwt_[A-Za-z0-9_-]{43}/);
    expect((await request('GET', '/api-tokens', { session: editor })).statusCode).toBe(403);
    expect((await request('DELETE', `/api-tokens/${token.id}`)).statusCode).toBe(200);
    expect((await request('GET', '/assets/tree', { bearer: secret })).statusCode).toBe(401);
    const [event] = await audit('api_token.revoked');
    expect(event!.details).toMatchObject({ owner: EDITOR.email, byOwner: false });
  });

  it('desactivar a un usuario revoca sus tokens (y no vuelven al reactivarlo)', async () => {
    const { secret } = await create(other, { name: 'al-desactivar', scope: 'read' });
    const [{ id }]: { id: string }[] = await db.query('SELECT id FROM users WHERE email = $1', [
      OTHER.email,
    ]);
    expect((await request('POST', `/users/${id}/deactivate`)).statusCode).toBe(200);
    expect((await request('GET', '/assets/tree', { bearer: secret })).statusCode).toBe(401);
    expect((await request('POST', `/users/${id}/reactivate`)).statusCode).toBe(200);
    expect((await request('GET', '/assets/tree', { bearer: secret })).statusCode).toBe(401);
    const [event] = await audit('user.deactivated');
    expect(event!.details['apiAccessRevoked']).toBeGreaterThanOrEqual(1);
  });

  it('restablecer la contraseña de un usuario revoca sus tokens (revisión #3, M2)', async () => {
    const email = 'reset-tokens@infraward.test';
    const password = 'una-contraseña-larga-de-prueba';
    const { id } = await app.get(UsersService).create(email, password, 'viewer');
    const session = await loginToken(app, email, password);
    const { secret } = await create(session, { name: 'al-restablecer', scope: 'read' });
    expect((await request('GET', '/assets/tree', { bearer: secret })).statusCode).toBe(200);
    expect((await request('POST', `/users/${id}/reset-password`)).statusCode).toBe(200);
    expect((await request('GET', '/assets/tree', { bearer: secret })).statusCode).toBe(401);
    const [event] = await audit('user.password_reset');
    expect(event!.details['apiAccessRevoked']).toBe(1);
  });

  it('OpenAPI anuncia el Bearer como alternativa a la cookie', async () => {
    const doc = (await app.inject({ method: 'GET', url: '/openapi.json' })).json<{
      components: { securitySchemes: Record<string, { scheme?: string }> };
      paths: Record<string, Record<string, { security?: object[] }>>;
    }>();
    expect(doc.components.securitySchemes['bearer']).toMatchObject({ scheme: 'bearer' });
    expect(doc.paths['/assets/tree']!['get']!.security).toEqual(
      expect.arrayContaining([{ bearer: [] }]),
    );
  });

  it('0 fugas: ningún token en claro en la BD, la auditoría, Redis, los logs ni las respuestas', async () => {
    expect(secrets.length).toBeGreaterThan(5);
    const dump = JSON.stringify(
      await db.query(`SELECT row_to_json(t) AS r FROM (
         SELECT * FROM api_tokens) t
       UNION ALL SELECT row_to_json(a) FROM audit_events a
       UNION ALL SELECT row_to_json(j) FROM job_runs j
       UNION ALL SELECT row_to_json(s) FROM user_sessions s`),
    );
    const redis = new Redis({
      host: redisUrl().hostname,
      port: Number(redisUrl().port || 6379),
      db: Number(redisDb()),
    });
    const keys = await redis.keys('*');
    const values: string[] = [];
    for (const key of keys) {
      const type = await redis.type(key);
      if (type === 'string') values.push((await redis.get(key)) ?? '');
      if (type === 'hash') values.push(JSON.stringify(await redis.hgetall(key)));
      if (type === 'list') values.push(JSON.stringify(await redis.lrange(key, 0, -1)));
    }
    await redis.quit();
    const logs = output.join('');
    // Las respuestas de creación son las únicas que lo llevan (una vez cada token).
    const otherResponses = responses.filter((r) => !r.includes('"secret":"iwt_'));
    for (const secret of secrets) {
      expect(dump).not.toContain(secret);
      expect(values.join('\n')).not.toContain(secret);
      expect(logs).not.toContain(secret);
      expect(otherResponses.join('\n')).not.toContain(secret);
      // Ni siquiera más allá del prefijo.
      expect(dump).not.toContain(secret.slice(0, 20));
    }
  });
});
