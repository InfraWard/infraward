import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import type {
  AuditPage,
  EnrollServerResponse,
  SessionInfo,
  TemporaryPasswordResponse,
  UserRole,
  UserSummary,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { ConflictException } from '@nestjs/common';
import { SessionRegistry } from '../src/auth/session-registry.js';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  enableTotp,
  login,
  loginToken,
  prepareEnv,
  SESSION_COOKIE,
  sessionToken,
} from './support/app.js';

/**
 * QoL-1 (DESIGN §14): gestión de usuarios, sesión con cookie httpOnly + CSRF, invalidación al
 * momento y registro de auditoría.
 */
describe('Usuarios, sesiones y auditoría (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  let baseUrl: string;
  const output: string[] = [];
  const responses: string[] = [];
  const temporaryPasswords: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_users', { LOGIN_THROTTLE_LIMIT: '100' });
    for (const stream of [process.stdout, process.stderr]) {
      const write = stream.write.bind(stream) as (
        ...args: unknown[]
      ) => boolean;
      vi.spyOn(stream, 'write').mockImplementation((...args: unknown[]) => {
        output.push(String(args[0]));
        return write(...args);
      });
    }
    app = await createTestApp();
    db = app.get(DataSource);
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    await app.listen(0, '127.0.0.1');
    baseUrl = await app.getUrl();
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await app?.close();
  });

  async function request(
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    url: string,
    options: {
      token?: string | null;
      payload?: object;
      headers?: Record<string, string>;
      remoteAddress?: string;
    } = {},
  ) {
    const token = options.token === undefined ? admin : options.token;
    const res = await app.inject({
      method,
      url,
      payload: options.payload,
      remoteAddress: options.remoteAddress,
      headers: { ...(token ? authHeaders(token) : {}), ...options.headers },
    });
    responses.push(JSON.stringify(res.headers), res.body);
    return res;
  }

  async function createUser(
    email: string,
    role: UserRole = 'viewer',
    name = email.split('@')[0],
  ): Promise<TemporaryPasswordResponse> {
    const res = await request('POST', '/users', {
      payload: { email, name, role },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json<TemporaryPasswordResponse>();
    temporaryPasswords.push(body.temporaryPassword);
    return body;
  }

  /** Entra con la temporal y la cambia: devuelve la sesión completa nueva. */
  async function activate(
    email: string,
    temporary: string,
    password: string,
  ): Promise<string> {
    const limited = await login(app, email, temporary);
    expect(limited.statusCode).toBe(200);
    expect(limited.json<SessionInfo>().mustChangePassword).toBe(true);
    const changed = await request('POST', '/auth/password', {
      token: sessionToken(limited),
      payload: { newPassword: password },
    });
    expect(changed.statusCode).toBe(200);
    return sessionToken(changed);
  }

  async function audit(query = ''): Promise<AuditPage> {
    const res = await request('GET', `/audit${query}`);
    expect(res.statusCode).toBe(200);
    return res.json<AuditPage>();
  }

  describe('CSRF y cabeceras de origen', () => {
    it('una escritura sin X-CSRF-Token o con otro → 403; con el suyo, sí', async () => {
      const [cookie] = admin.split(' ');
      const noCsrf = await request('POST', '/notifications/seen', {
        token: null,
        headers: { cookie: `${SESSION_COOKIE}=${cookie}` },
      });
      expect(noCsrf.statusCode).toBe(403);
      expect(noCsrf.json()).toMatchObject({ code: 'csrf' });
      const wrong = await request('POST', '/notifications/seen', {
        token: null,
        headers: {
          cookie: `${SESSION_COOKIE}=${cookie}`,
          'x-csrf-token': 'x'.repeat(43),
        },
      });
      expect(wrong.statusCode).toBe(403);
      expect((await request('POST', '/notifications/seen')).statusCode).toBe(200);
      // Las lecturas no lo necesitan.
      const read = await request('GET', '/auth/session', {
        token: null,
        headers: { cookie: `${SESSION_COOKIE}=${cookie}` },
      });
      expect(read.statusCode).toBe(200);
    });

    it('Origin ajeno o petición entre sitios → 403, también en el login', async () => {
      const foreign = await request('POST', '/notifications/seen', {
        headers: { origin: 'https://evil.example' },
      });
      expect(foreign.statusCode).toBe(403);
      const crossSite = await request('POST', '/notifications/seen', {
        headers: { 'sec-fetch-site': 'cross-site' },
      });
      expect(crossSite.statusCode).toBe(403);
      const loginCsrf = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { origin: 'https://evil.example' },
        payload: ADMIN,
      });
      expect(loginCsrf.statusCode).toBe(403);
      expect(loginCsrf.cookies).toHaveLength(0);
      const sameOrigin = await request('POST', '/notifications/seen', {
        headers: { origin: 'http://infraward.test', 'sec-fetch-site': 'same-origin' },
      });
      expect(sameOrigin.statusCode).toBe(200);
    });

    it('logout borra la sesión: la cookie deja de valer', async () => {
      const token = await loginToken(app, ADMIN.email, ADMIN.password);
      const out = await request('POST', '/auth/logout', { token });
      expect(out.statusCode).toBe(200);
      // Sesión local: no hay sesión del proveedor que cerrar.
      expect(out.json()).toEqual({ providerLogoutUrl: null });
      expect(out.cookies.find((c) => c.name === SESSION_COOKIE)?.value).toBe('');
      expect((await request('GET', '/auth/me', { token })).statusCode).toBe(401);
    });
  });

  describe('gestión de usuarios', () => {
    it('alta de un viewer con temporal de un solo uso que obliga a cambiarla', async () => {
      const created = await createUser('ana@infraward.test', 'viewer', 'Ana');
      expect(created.user).toMatchObject({
        email: 'ana@infraward.test',
        name: 'Ana',
        role: 'viewer',
        active: true,
        mustChangePassword: true,
        lastLoginAt: null,
      });
      expect(created.temporaryPassword).toMatch(/^[\w]{5}(-[\w]{5}){3}$/);

      // La sesión de la temporal solo sirve para cambiarla.
      const limited = await login(app, 'ana@infraward.test', created.temporaryPassword);
      const limitedToken = sessionToken(limited);
      const blocked = await request('GET', '/assets/tree', { token: limitedToken });
      expect(blocked.statusCode).toBe(403);
      expect(blocked.json()).toMatchObject({ code: 'password_change_required' });
      expect(
        (await request('GET', '/auth/session', { token: limitedToken })).json<SessionInfo>()
          .mustChangePassword,
      ).toBe(true);

      // Un solo uso: la segunda vez ya no vale.
      expect(
        (await login(app, 'ana@infraward.test', created.temporaryPassword)).statusCode,
      ).toBe(401);

      const tooShort = await request('POST', '/auth/password', {
        token: limitedToken,
        payload: { newPassword: 'corta' },
      });
      expect(tooShort.statusCode).toBe(400);
      const changed = await request('POST', '/auth/password', {
        token: limitedToken,
        payload: { newPassword: 'la-contraseña-de-ana' },
      });
      expect(changed.statusCode).toBe(200);
      expect(changed.json<SessionInfo>().mustChangePassword).toBe(false);
      // La sesión limitada se cierra; la nueva vale para todo (lectura) pero no para admin.
      expect((await request('GET', '/auth/me', { token: limitedToken })).statusCode).toBe(401);
      const ana = sessionToken(changed);
      expect((await request('GET', '/assets/tree', { token: ana })).statusCode).toBe(200);
      expect((await request('GET', '/users', { token: ana })).statusCode).toBe(403);
      expect((await request('GET', '/audit', { token: ana })).statusCode).toBe(403);
      expect(
        (await request('POST', '/users', {
          token: ana,
          payload: { email: 'x@infraward.test', name: 'x', role: 'admin' },
        })).statusCode,
      ).toBe(403);
    });

    it('email repetido → 409; validación → 400', async () => {
      expect(
        (await request('POST', '/users', {
          payload: { email: 'ANA@infraward.test', name: 'Otra', role: 'viewer' },
        })).statusCode,
      ).toBe(409);
      expect(
        (await request('POST', '/users', {
          payload: { email: 'no-es-email', name: '', role: 'root' },
        })).statusCode,
      ).toBe(400);
    });

    it('lista sin hashes, con estado y último acceso', async () => {
      const res = await request('GET', '/users');
      const users = res.json<UserSummary[]>();
      const ana = users.find((u) => u.email === 'ana@infraward.test')!;
      expect(ana).toMatchObject({ active: true, mustChangePassword: false });
      expect(ana.lastLoginAt).not.toBeNull();
      expect(res.body).not.toMatch(/argon2|password_?hash/i);
    });

    it('desactivar con la sesión abierta: la pierde al momento (también su SSE)', async () => {
      const ana = await loginToken(app, 'ana@infraward.test', 'la-contraseña-de-ana');
      const id = (await request('GET', '/users')).json<UserSummary[]>().find(
        (u) => u.email === 'ana@infraward.test',
      )!.id;

      // Flujo SSE abierto por Ana (progreso de un alta).
      const enrolled = (
        await request('POST', '/assets/enroll', {
          payload: { host: '127.0.0.1', port: 22, name: 'e2e-users-sse' },
        })
      ).json<EnrollServerResponse>();
      const controller = new AbortController();
      const sse = await fetch(`${baseUrl}/assets/${enrolled.asset.id}/enrollment/events`, {
        headers: authHeaders(ana),
        signal: controller.signal,
      });
      expect(sse.status).toBe(200);
      const sessionId = (
        await db.query(
          `SELECT s.id FROM user_sessions s WHERE s.user_id = $1 ORDER BY created_at DESC LIMIT 1`,
          [id],
        )
      )[0].id as string;
      const registry = app.get(SessionRegistry);
      expect(registry.openStreams(sessionId)).toBe(1);
      const ended = (async () => {
        const reader = sse.body!.getReader();
        for (;;) if ((await reader.read()).done) return true;
      })();

      // Su propia cuenta no.
      const me = (await request('GET', '/auth/me')).json<{ id: string }>();
      expect((await request('POST', `/users/${me.id}/deactivate`)).statusCode).toBe(400);

      const res = await request('POST', `/users/${id}/deactivate`);
      expect(res.statusCode).toBe(200);
      expect(res.json<UserSummary>().active).toBe(false);
      expect((await request('GET', '/auth/me', { token: ana })).statusCode).toBe(401);
      await expect(
        Promise.race([ended, new Promise((r) => setTimeout(() => r(false), 3000))]),
      ).resolves.toBe(true);
      expect(registry.openStreams(sessionId)).toBe(0);
      controller.abort();
      // Y no puede volver a entrar (mismo 401 genérico).
      const again = await login(app, 'ana@infraward.test', 'la-contraseña-de-ana');
      expect(again.statusCode).toBe(401);
      expect(again.json()).toMatchObject({ message: 'Credenciales inválidas' });
      expect(
        (await db.query(`SELECT count(*)::int AS n FROM user_sessions WHERE user_id = $1`, [id]))[0]
          .n,
      ).toBe(0);
    });

    it('reactivar y restablecer la contraseña: temporal nueva de un solo uso', async () => {
      const id = (await request('GET', '/users')).json<UserSummary[]>().find(
        (u) => u.email === 'ana@infraward.test',
      )!.id;
      expect(
        (await request('POST', `/users/${id}/reactivate`)).json<UserSummary>().active,
      ).toBe(true);
      const ana = await loginToken(app, 'ana@infraward.test', 'la-contraseña-de-ana');

      const reset = await request('POST', `/users/${id}/reset-password`);
      expect(reset.statusCode).toBe(200);
      const { temporaryPassword } = reset.json<TemporaryPasswordResponse>();
      temporaryPasswords.push(temporaryPassword);
      // Sus sesiones caen y la contraseña anterior ya no vale.
      expect((await request('GET', '/auth/me', { token: ana })).statusCode).toBe(401);
      expect((await login(app, 'ana@infraward.test', 'la-contraseña-de-ana')).statusCode).toBe(401);
      await activate('ana@infraward.test', temporaryPassword, 'otra-contraseña-de-ana');
      expect((await login(app, 'ana@infraward.test', temporaryPassword)).statusCode).toBe(401);
    });

    it('cambiar la propia contraseña pide la actual y cierra las demás sesiones', async () => {
      const a = await loginToken(app, 'ana@infraward.test', 'otra-contraseña-de-ana');
      const b = await loginToken(app, 'ana@infraward.test', 'otra-contraseña-de-ana');
      const bad = await request('POST', '/auth/password', {
        token: a,
        payload: { currentPassword: 'mala', newPassword: 'tercera-contraseña-de-ana' },
      });
      expect(bad.statusCode).toBe(400);
      const missing = await request('POST', '/auth/password', {
        token: a,
        payload: { newPassword: 'tercera-contraseña-de-ana' },
      });
      expect(missing.statusCode).toBe(400);
      const ok = await request('POST', '/auth/password', {
        token: a,
        payload: {
          currentPassword: 'otra-contraseña-de-ana',
          newPassword: 'tercera-contraseña-de-ana',
        },
      });
      expect(ok.statusCode).toBe(200);
      expect((await request('GET', '/auth/me', { token: b })).statusCode).toBe(401);
      expect((await request('GET', '/auth/me', { token: a })).statusCode).toBe(401);
      expect((await request('GET', '/auth/me', { token: sessionToken(ok) })).statusCode).toBe(200);
    });

    it('perfil propio: cambia el nombre', async () => {
      const ana = await loginToken(app, 'ana@infraward.test', 'tercera-contraseña-de-ana');
      const res = await request('PATCH', '/auth/me', {
        token: ana,
        payload: { name: '  Ana García ' },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({ name: 'Ana García', role: 'viewer' });
      // Solo el nombre: el rol no se puede cambiar desde el perfil.
      expect(
        (await request('PATCH', '/auth/me', { token: ana, payload: { name: 'x', role: 'admin' } }))
          .statusCode,
      ).toBe(400);
    });

    it('cambio de rol con efecto inmediato y sin dejar el sistema sin admins', async () => {
      const users = (await request('GET', '/users')).json<UserSummary[]>();
      const adminId = users.find((u) => u.email === ADMIN.email)!.id;
      const anaId = users.find((u) => u.email === 'ana@infraward.test')!.id;
      const ana = await loginToken(app, 'ana@infraward.test', 'tercera-contraseña-de-ana');

      // Único admin: no puede quitarse el rol.
      const demote = await request('PATCH', `/users/${adminId}`, { payload: { role: 'viewer' } });
      expect(demote.statusCode).toBe(409);

      const promote = await request('PATCH', `/users/${anaId}`, { payload: { role: 'admin' } });
      expect(promote.json<UserSummary>().role).toBe('admin');
      // Ya es admin con la misma sesión, pero sin TOTP: antes de nada, configurarlo.
      const blocked = await request('GET', '/users', { token: ana });
      expect(blocked.statusCode).toBe(403);
      expect(blocked.json()).toMatchObject({ code: 'mfa_setup_required' });
      await enableTotp(app, 'ana@infraward.test', ana);
      expect((await request('GET', '/users', { token: ana })).statusCode).toBe(200);
      await request('PATCH', `/users/${anaId}`, { payload: { role: 'viewer' } });
      expect((await request('GET', '/users', { token: ana })).statusCode).toBe(403);
    });

    it('dos admins que se desactivan a la vez: solo uno lo consigue', async () => {
      const created = await createUser('beto@infraward.test', 'admin', 'Beto');
      const beto = await activate('beto@infraward.test', created.temporaryPassword, 'contraseña-de-beto');
      await enableTotp(app, 'beto@infraward.test', beto);
      const adminId = (await request('GET', '/auth/me')).json<{ id: string }>().id;
      const [a, b] = await Promise.all([
        request('POST', `/users/${created.user.id}/deactivate`),
        request('POST', `/users/${adminId}/deactivate`, { token: beto }),
      ]);
      // Uno gana; el otro recibe 409 (esperó al bloqueo y ya no hay otro admin) o 401 (su
      // sesión ya se había revocado al llegar). Nunca los dos.
      const codes = [a.statusCode, b.statusCode].sort();
      expect(codes[0]).toBe(200);
      expect([401, 409]).toContain(codes[1]);
      const active = await db.query(
        `SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND disabled_at IS NULL`,
      );
      expect(active[0].n).toBe(1);
      // Deja todo como estaba: el admin inicial activo con su sesión y Beto desactivado. Si ganó
      // Beto, seguiría siendo un segundo admin activo y los tests siguientes (la carrera en la BD)
      // verían tres admins: las dos desactivaciones cruzadas pasarían y el admin inicial perdería
      // la sesión con la que siguen los demás.
      if (a.statusCode !== 200) {
        await db.query(
          `UPDATE users SET disabled_at = CASE WHEN id = $1 THEN NULL ELSE now() END
            WHERE id IN ($1, $2)`,
          [adminId, created.user.id],
        );
        admin = await loginToken(app, ADMIN.email, ADMIN.password);
      }
    });

    it('cambio de email: admin y propio (con contraseña), único, auditado; no en cuentas OIDC', async () => {
      const created = await createUser('eva@infraward.test', 'viewer', 'Eva');
      const id = created.user.id;
      await activate('eva@infraward.test', created.temporaryPassword, 'la-contraseña-de-eva');

      // Admin: normaliza, valida y exige que sea único.
      const byAdmin = await request('PATCH', `/users/${id}`, {
        payload: { email: '  Eva.Nueva@InfraWard.test ' },
      });
      expect(byAdmin.statusCode).toBe(200);
      expect(byAdmin.json<UserSummary>().email).toBe('eva.nueva@infraward.test');
      expect(
        (await request('PATCH', `/users/${id}`, { payload: { email: 'no-es-email' } })).statusCode,
      ).toBe(400);
      expect(
        (await request('PATCH', `/users/${id}`, { payload: { email: ADMIN.email.toUpperCase() } }))
          .statusCode,
      ).toBe(409);
      expect((await login(app, 'eva@infraward.test', 'la-contraseña-de-eva')).statusCode).toBe(401);

      // Propio: pide la contraseña actual.
      const eva = await loginToken(app, 'eva.nueva@infraward.test', 'la-contraseña-de-eva');
      expect(
        (await request('POST', '/auth/email', {
          token: eva,
          payload: { email: 'eva@infraward.test', currentPassword: 'mala-contraseña' },
        })).statusCode,
      ).toBe(400);
      expect(
        (await request('POST', '/auth/email', {
          token: eva,
          payload: { email: 'ana@infraward.test', currentPassword: 'la-contraseña-de-eva' },
        })).statusCode,
      ).toBe(409);
      const self = await request('POST', '/auth/email', {
        token: eva,
        payload: { email: 'eva@infraward.test', currentPassword: 'la-contraseña-de-eva' },
      });
      expect(self.statusCode).toBe(200);
      expect(self.json<{ email: string }>().email).toBe('eva@infraward.test');
      // La sesión sigue abierta y entra con el nuevo.
      expect((await request('GET', '/auth/me', { token: eva })).statusCode).toBe(200);
      expect((await login(app, 'eva@infraward.test', 'la-contraseña-de-eva')).statusCode).toBe(200);

      const changes = (await audit('?action=user.email_changed')).items;
      expect(changes.some((e) => e.details.to === 'eva.nueva@infraward.test')).toBe(true);
      expect(
        changes.some((e) => e.details.to === 'eva@infraward.test' && e.details.self === true),
      ).toBe(true);
      expect(changes.some((e) => e.outcome === 'failure')).toBe(true);

      // Cuenta del proveedor OIDC: el email lo da el proveedor.
      await db.query(`UPDATE users SET origin = 'oidc' WHERE id = $1`, [id]);
      expect(
        (await request('PATCH', `/users/${id}`, { payload: { email: 'otra@infraward.test' } }))
          .statusCode,
      ).toBe(409);
      expect(
        (await request('POST', '/auth/email', {
          token: eva,
          payload: { email: 'otra@infraward.test', currentPassword: 'la-contraseña-de-eva' },
        })).statusCode,
      ).toBe(409);
      await db.query(`UPDATE users SET origin = 'local' WHERE id = $1`, [id]);
    });
  });

  it('la carrera en la BD: dos desactivaciones cruzadas simultáneas → una 409', async () => {
    const created = await createUser('carla@infraward.test', 'admin', 'Carla');
    const adminId = (await request('GET', '/auth/me')).json<{ id: string }>().id;
    const users = app.get(UsersService);
    const results = await Promise.allSettled([
      users.deactivate(created.user.id, { actorId: adminId, actorEmail: ADMIN.email, ip: null }),
      users.deactivate(adminId, { actorId: created.user.id, actorEmail: 'carla@infraward.test', ip: null }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual(['fulfilled', 'rejected']);
    const rejected = results.find((r) => r.status === 'rejected') as PromiseRejectedResult;
    expect(rejected.reason).toBeInstanceOf(ConflictException);
    const active = await db.query(
      `SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND disabled_at IS NULL`,
    );
    expect(active[0].n).toBe(1);
    await db.query(`UPDATE users SET disabled_at = NULL WHERE id = $1`, [adminId]);
    await db.query(`UPDATE users SET role = 'viewer' WHERE id = $1`, [created.user.id]);
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
  });

  it('roles: cada uno puede justo lo de su tabla de permisos', async () => {
    const ghost = '00000000-0000-4000-8000-00000000dead';
    // [método, url, cuerpo, código sin permiso = 403, con permiso = esperado]
    const probes: [string, 'GET' | 'POST' | 'PUT' | 'DELETE', string, object | undefined, number][] = [
      ['operate', 'POST', `/assets/${ghost}/collect`, undefined, 404],
      ['write', 'POST', '/assets', {}, 400],
      ['write', 'DELETE', `/assets/${ghost}`, undefined, 404],
      ['purge', 'DELETE', `/assets/${ghost}?purge=true`, undefined, 404],
      ['policy', 'PUT', '/inventory-policies/global', { reconcileIntervalMinutes: -5 }, 400],
      ['secrets', 'GET', '/secrets/providers', undefined, 200],
      ['audit', 'GET', '/audit', undefined, 200],
      ['usersRead', 'GET', '/users', undefined, 200],
      ['usersManage', 'POST', '/users', {}, 400],
    ];
    const allowed: Record<string, string[]> = {
      editor: ['operate', 'write', 'policy', 'secrets'],
      operator: ['operate'],
      auditor: ['secrets', 'audit', 'usersRead'],
      viewer: [],
    };
    for (const role of ['editor', 'operator', 'auditor', 'viewer'] as const) {
      const email = `rol-${role}@infraward.test`;
      const created = await createUser(email, role);
      const token = await activate(email, created.temporaryPassword, `contraseña-de-${role}-1`);
      const got = [];
      for (const [name, method, url, payload] of probes)
        got.push([name, (await request(method, url, { token, payload })).statusCode]);
      expect(got).toEqual(
        probes.map(([name, , , , ok]) => [name, allowed[role].includes(name) ? ok : 403]),
      );
      // Todos leen el inventario.
      expect((await request('GET', '/assets/tree', { token })).statusCode).toBe(200);
    }
    // Y el admin, todo.
    for (const [, method, url, payload, ok] of probes)
      expect((await request(method, url, { payload })).statusCode).toBe(ok);
  });

  describe('auditoría', () => {
    it('login fallido con la IP y sin la contraseña', async () => {
      await app.inject({
        method: 'POST',
        url: '/auth/login',
        remoteAddress: '198.51.100.23',
        payload: { email: 'ana@infraward.test', password: 'intento-malo-123' },
      });
      const page = await audit('?action=auth.login_failed');
      const event = page.items.find((e) => e.ip === '198.51.100.23')!;
      expect(event).toMatchObject({
        actorEmail: 'ana@infraward.test',
        outcome: 'failure',
        details: { reason: 'bad_password' },
      });
      expect(JSON.stringify(page)).not.toContain('intento-malo-123');
    });

    it('registra el ciclo de vida del usuario con quién y sobre qué', async () => {
      const anaId = (await request('GET', '/users')).json<UserSummary[]>().find(
        (u) => u.email === 'ana@infraward.test',
      )!.id;
      const page = await audit(`?targetId=${anaId}&limit=200`);
      const actions = page.items.map((e) => e.action);
      for (const a of [
        'user.created',
        'auth.login',
        'auth.password_changed',
        'user.deactivated',
        'user.reactivated',
        'user.password_reset',
        'user.updated',
        'user.role_changed',
        'auth.login_failed',
      ])
        expect(actions).toContain(a);
      const deactivated = page.items.find((e) => e.action === 'user.deactivated')!;
      expect(deactivated).toMatchObject({
        actorEmail: ADMIN.email,
        targetLabel: 'ana@infraward.test',
        targetType: 'user',
      });
      expect(deactivated.details.sessionsRevoked).toBeGreaterThanOrEqual(1);
      expect(
        page.items.filter((e) => e.action === 'user.role_changed').map((e) => e.details),
      ).toEqual([
        { from: 'admin', to: 'viewer' },
        { from: 'viewer', to: 'admin' },
      ]);
    });

    it('altas y bajas de assets, purgas y políticas', async () => {
      const created = await request('POST', '/assets', {
        payload: { type: 'server', name: 'e2e-auditado', status: 'active' },
      });
      const id = created.json<{ id: string }>().id;
      await request('PUT', `/assets/${id}/policy`, { payload: { scanEnabled: false } });
      await request('PUT', '/inventory-policies/global', {
        payload: { reconcileIntervalMinutes: 120 },
      });
      await request('DELETE', `/assets/${id}`);
      await request('DELETE', `/assets/${id}?purge=true`);
      const page = await audit(`?targetId=${id}`);
      expect(page.items.map((e) => e.action)).toEqual([
        'asset.purged',
        'asset.retired',
        'policy.asset_set',
        'asset.created',
      ]);
      expect(page.items[0]).toMatchObject({ targetLabel: 'e2e-auditado', details: { affected: 1 } });
      expect(page.items[2].details).toMatchObject({ scanEnabledFrom: null, scanEnabledTo: false });
      const global = await audit('?action=policy.global_updated');
      expect(global.items[0].details).toMatchObject({
        reconcileIntervalMinutesFrom: 360,
        reconcileIntervalMinutesTo: 120,
      });
    });

    it('filtros por categoría, actor, resultado y texto; paginación por cursor', async () => {
      const byCategory = await audit('?category=user');
      expect(byCategory.items.every((e) => e.action.startsWith('user.'))).toBe(true);
      const adminId = (await request('GET', '/auth/me')).json<{ id: string }>().id;
      const byActor = await audit(`?actorId=${adminId}`);
      expect(byActor.items.every((e) => e.actorId === adminId)).toBe(true);
      const failures = await audit('?outcome=failure');
      expect(failures.items.every((e) => e.outcome === 'failure')).toBe(true);
      const text = await audit('?q=auditad');
      expect(text.items.every((e) => e.targetLabel === 'e2e-auditado')).toBe(true);
      expect(text.items.length).toBeGreaterThan(0);

      const first = await audit('?limit=3');
      expect(first.items).toHaveLength(3);
      const second = await audit(`?limit=3&cursor=${first.nextCursor}`);
      expect(second.items[0].id).not.toBe(first.items[2].id);
      expect(new Date(second.items[0].occurredAt) <= new Date(first.items[2].occurredAt)).toBe(true);
      expect((await request('GET', '/audit?cursor=basura')).statusCode).toBe(400);
      expect((await request('GET', '/audit?action=no.existe')).statusCode).toBe(400);
    });
  });

  it('0 fugas: ni contraseñas temporales ni tokens de sesión en logs ni en la auditoría', async () => {
    const logs = output.join('');
    const rows = JSON.stringify(await db.query(`SELECT * FROM audit_events`));
    const sessions: { token_hash: Buffer }[] = await db.query(`SELECT token_hash FROM user_sessions`);
    expect(temporaryPasswords.length).toBeGreaterThanOrEqual(3);
    for (const secret of [...temporaryPasswords, 'la-contraseña-de-ana', ADMIN.password]) {
      expect(logs).not.toContain(secret);
      expect(rows).not.toContain(secret);
    }
    // Las temporales solo aparecen en la respuesta que las crea.
    for (const t of temporaryPasswords)
      expect(responses.filter((r) => r.includes(t))).toHaveLength(1);
    expect(logs + rows).not.toContain('PRIVATE KEY');
    expect(sessions.every((s) => s.token_hash.length === 32)).toBe(true);
    const [cookie] = admin.split(' ');
    expect(logs + rows).not.toContain(cookie);
  });
});
