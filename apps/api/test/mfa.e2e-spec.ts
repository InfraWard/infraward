import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  AuditPage,
  CreatedApiTokenResponse,
  MfaSetupResponse,
  MfaStatus,
  SessionInfo,
  UserSummary,
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
  nextTotpCode,
  prepareEnv,
  redisDb,
  redisUrl,
  SESSION_COOKIE,
  sessionToken,
  totpSecretOf,
} from './support/app.js';
import { FakeOidcProvider, type FakeOidcUser } from './support/fake-oidc.js';

const WEB = 'http://infraward.test';
const FLOW_COOKIE = '__Host-iw_oidc';
const SECRET_REF = 'secret://local/oidc/e2e#client_secret';
/** Cupo de códigos por usuario y minuto (alto: el admin de este fichero introduce muchos). */
const THROTTLE = 30;

const EDITOR = { email: 'editor-mfa@infraward.test', password: 'contraseña-del-editor-mfa' };
const BRUNO = { email: 'bruno-mfa@infraward.test', password: 'contraseña-de-bruno-mfa' };
const TINA = { email: 'tina-mfa@infraward.test', password: 'contraseña-de-tina-mfa' };
const RITA = { email: 'rita-mfa@infraward.test', password: 'contraseña-de-rita-mfa' };

/**
 * MFA y reautenticación reciente (DESIGN §14): TOTP obligatorio para los admins locales, segundo
 * paso del login, códigos de recuperación de un solo uso, step-up local (código) y OIDC (nuevo
 * login con prompt=login y auth_time), límite de intentos, auditoría y 0 fugas.
 */
describe('MFA y reautenticación (e2e)', () => {
  const fake = new FakeOidcProvider();
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  let ip = 0;
  const output: string[] = [];
  const responses: string[] = [];
  /** Respuestas que llevan a propósito el secreto o los códigos (alta y confirmación). */
  const revealing: string[] = [];
  const recoveryCodes: string[] = [];

  const ana: FakeOidcUser = {
    sub: 'kc-ana-mfa',
    email: 'ana-mfa@example.test',
    email_verified: true,
    name: 'Ana',
    groups: ['infraward-admins'],
  };

  beforeAll(async () => {
    await fake.start();
    await prepareEnv('e2e_mfa', {
      LOGIN_THROTTLE_LIMIT: String(THROTTLE),
      OIDC_ISSUER: fake.issuer,
      OIDC_CLIENT_ID: fake.clientId,
      OIDC_CLIENT_SECRET_REF: SECRET_REF,
      OIDC_REDIRECT_URI: `${WEB}/api/auth/oidc/callback`,
      OIDC_PROVIDER_NAME: 'Fake IdP',
      OIDC_ROLE_MAPPING: 'infraward-admins=admin,infraward-editors=editor',
    });
    for (const stream of [process.stdout, process.stderr]) {
      const write = stream.write.bind(stream) as (...args: unknown[]) => boolean;
      vi.spyOn(stream, 'write').mockImplementation((...args: unknown[]) => {
        output.push(String(args[0]));
        return write(...args);
      });
    }
    app = await createTestApp();
    db = app.get(DataSource);
    await app
      .get(SecretsService)
      .store(SECRET_REF.split('#')[0], { client_secret: fake.clientSecret });
    const users = app.get(UsersService);
    await users.create(EDITOR.email, EDITOR.password, 'editor');
    await users.create(BRUNO.email, BRUNO.password, 'viewer');
    await users.create(TINA.email, TINA.password, 'editor');
    await users.create(RITA.email, RITA.password, 'editor');
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await app?.close();
    await fake.stop();
  });

  /** Cada login desde una IP distinta: el límite del login es por IP y aquí entramos mucho. */
  const nextIp = () => `198.51.100.${++ip}`;

  async function inject(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    options: {
      token?: string | null;
      payload?: object;
      cookie?: string;
      bearer?: string;
      remoteAddress?: string;
    } = {},
  ) {
    const token = options.token === undefined ? admin : options.token;
    const headers: Record<string, string> = token ? authHeaders(token) : {};
    if (options.cookie) headers.cookie = options.cookie;
    if (options.bearer) headers.authorization = `Bearer ${options.bearer}`;
    const res = await app.inject({
      method,
      url,
      payload: options.payload,
      headers,
      remoteAddress: options.remoteAddress,
    });
    const record = JSON.stringify(res.headers) + res.body;
    if (/"(secret|recoveryCodes)":/.test(res.body)) revealing.push(record);
    else responses.push(record);
    return res;
  }

  async function passwordStep(email: string, password: string) {
    const res = await inject('POST', '/auth/login', {
      token: null,
      payload: { email, password },
      remoteAddress: nextIp(),
    });
    expect(res.statusCode).toBe(200);
    return { res, info: res.json<SessionInfo>(), token: sessionToken(res) };
  }

  async function lastEvent(action: string) {
    const res = await inject('GET', `/audit?action=${action}&limit=1`);
    expect(res.statusCode).toBe(200);
    return res.json<AuditPage>().items[0];
  }

  /** Mueve la última reautenticación de la sesión `minutes` minutos atrás. */
  async function ageReauth(token: string, minutes: number) {
    const csrf = token.split(' ')[1];
    await db.query(
      `UPDATE user_sessions SET reauthenticated_at = now() - make_interval(mins => $2)
       WHERE csrf_token = $1`,
      [csrf, minutes],
    );
  }

  async function retiredAsset(name: string): Promise<string> {
    const [row]: { id: string }[] = await db.query(
      `INSERT INTO assets (type, discovered_name, status) VALUES ('server', $1, 'retired') RETURNING id`,
      [name],
    );
    return row.id;
  }

  describe('TOTP obligatorio para los admins locales', () => {
    it('sin TOTP, el admin solo puede configurarlo (y ver su sesión o salir)', async () => {
      const { info, token } = await passwordStep(ADMIN.email, ADMIN.password);
      expect(info).toMatchObject({ mfaPending: false, mfaSetupRequired: true });
      for (const url of ['/assets/tree', '/users', '/audit']) {
        const res = await inject('GET', url, { token });
        expect(res.statusCode, url).toBe(403);
        expect(res.json()).toMatchObject({ code: 'mfa_setup_required' });
      }
      expect((await inject('GET', '/auth/session', { token })).statusCode).toBe(200);
      expect((await inject('GET', '/auth/mfa', { token })).json<MfaStatus>()).toEqual({
        enabled: false,
        recoveryCodesLeft: 0,
        required: true,
      });

      const setup = await inject('POST', '/auth/mfa/setup', { token });
      expect(setup.statusCode).toBe(200);
      const body = setup.json<MfaSetupResponse>();
      expect(body.secret).toMatch(/^[A-Z2-7]{32}$/);
      expect(body.otpauthUri).toContain(`secret=${body.secret}`);
      expect(body.qrDataUrl).toMatch(/^data:image\/png;base64,/);

      // Código incorrecto: 400 y auditado; todavía no vale.
      const bad = await inject('POST', '/auth/mfa/enable', { token, payload: { code: '000000' } });
      expect(bad.statusCode).toBe(400);
      expect((await inject('GET', '/assets/tree', { token })).statusCode).toBe(403);

      admin = token;
      // Mismo camino que el helper de los e2e (recuerda el secreto para los logins siguientes).
      const codes = await enableTotp(app, ADMIN.email, token);
      expect(codes).toHaveLength(10);
      expect(new Set(codes).size).toBe(10);
      for (const c of codes) expect(c).toMatch(/^([a-z2-9]{4}-){3}[a-z2-9]{4}$/);
      recoveryCodes.push(...codes);
      expect((await inject('GET', '/assets/tree')).statusCode).toBe(200);
      expect(await lastEvent('auth.mfa_enabled')).toMatchObject({ outcome: 'success' });
      const failed = await inject('GET', '/audit?action=auth.mfa_enabled&outcome=failure');
      expect(failed.json<AuditPage>().items[0]).toMatchObject({
        details: { reason: 'bad_code' },
      });
    });

    it('en BD solo la referencia del secreto (cifrado en el proveedor) y los hashes de los códigos', async () => {
      const [row]: { totp_secret_ref: string; totp_pending_ref: string | null }[] =
        await db.query(`SELECT totp_secret_ref, totp_pending_ref FROM users WHERE email = $1`, [
          ADMIN.email,
        ]);
      expect(row.totp_secret_ref).toMatch(
        /^secret:\/\/local\/infraward\/users\/[0-9a-f-]+\/totp\/[0-9a-f-]+#secret$/,
      );
      expect(row.totp_pending_ref).toBeNull();
      const hashes: { code_hash: Buffer }[] = await db.query(
        `SELECT code_hash FROM user_recovery_codes c JOIN users u ON u.id = c.user_id WHERE u.email = $1`,
        [ADMIN.email],
      );
      expect(hashes).toHaveLength(10);
      for (const h of hashes) expect(h.code_hash).toHaveLength(32);
    });

    it('un admin local no puede quitarse el TOTP (409)', async () => {
      const res = await inject('POST', '/auth/mfa/disable');
      expect(res.statusCode).toBe(409);
    });

    it('cambiar de dispositivo exige reautenticación y sustituye el secreto', async () => {
      await ageReauth(admin, 11);
      const denied = await inject('POST', '/auth/mfa/setup');
      expect(denied.statusCode).toBe(403);
      expect(denied.json()).toMatchObject({ code: 'recent_auth_required', action: 'mfa.replace' });
      const old = totpSecretOf(ADMIN.email);
      const reauth = await inject('POST', '/auth/reauth', {
        payload: { code: await nextTotpCode(ADMIN.email), action: 'mfa.replace' },
      });
      expect(reauth.statusCode).toBe(200);
      const codes = await enableTotp(app, ADMIN.email, admin);
      expect(totpSecretOf(ADMIN.email)).not.toBe(old);
      // Los códigos anteriores dejan de valer.
      recoveryCodes.splice(0, recoveryCodes.length, ...codes);
      expect(await lastEvent('auth.mfa_enabled')).toMatchObject({ details: { replaced: true } });
    });
  });

  describe('segundo paso del login', () => {
    it('la sesión intermedia no vale para nada más; el código la cambia por otra', async () => {
      const step = await passwordStep(ADMIN.email, ADMIN.password);
      expect(step.info).toMatchObject({ mfaPending: true, mfaSetupRequired: false });
      for (const [method, url] of [
        ['GET', '/assets/tree'],
        ['GET', '/auth/me'],
        ['POST', '/auth/reauth'],
        ['POST', '/auth/mfa/setup'],
      ] as const) {
        const res = await inject(method, url, { token: step.token, payload: { code: '123456' } });
        expect(res.statusCode, url).toBe(403);
        expect(res.json()).toMatchObject({ code: 'mfa_pending' });
      }
      const code = await nextTotpCode(ADMIN.email);
      const ok = await inject('POST', '/auth/mfa/verify', {
        token: step.token,
        payload: { code },
      });
      expect(ok.statusCode).toBe(200);
      const full = sessionToken(ok);
      expect(full.split(' ')[0]).not.toBe(step.token.split(' ')[0]);
      expect(ok.json<SessionInfo>()).toMatchObject({ mfaPending: false });
      expect(ok.json<SessionInfo>().reauthenticatedUntil).not.toBeNull();
      // La intermedia ya no existe.
      expect((await inject('GET', '/auth/session', { token: step.token })).statusCode).toBe(401);
      expect((await inject('GET', '/assets/tree', { token: full })).statusCode).toBe(200);
      expect(await lastEvent('auth.login')).toMatchObject({ details: { mfa: 'totp' } });

      // El mismo código no vale dos veces (anti-replay), aunque siga en su ventana de 30 s.
      const replay = await passwordStep(ADMIN.email, ADMIN.password);
      const res = await inject('POST', '/auth/mfa/verify', {
        token: replay.token,
        payload: { code },
      });
      expect(res.statusCode).toBe(400);
      expect(await lastEvent('auth.mfa_challenge')).toMatchObject({
        outcome: 'failure',
        details: { reason: 'bad_code' },
      });
    });

    it('un código de recuperación vale una sola vez', async () => {
      const code = recoveryCodes[0];
      const first = await passwordStep(ADMIN.email, ADMIN.password);
      const ok = await inject('POST', '/auth/mfa/verify', {
        token: first.token,
        payload: { code: code.toUpperCase().replace(/-/g, ' ') },
      });
      expect(ok.statusCode).toBe(200);
      expect(await lastEvent('auth.mfa_challenge')).toMatchObject({
        details: { method: 'recovery', recoveryCodesLeft: 9 },
      });
      const second = await passwordStep(ADMIN.email, ADMIN.password);
      const again = await inject('POST', '/auth/mfa/verify', {
        token: second.token,
        payload: { code },
      });
      expect(again.statusCode).toBe(400);
      const status = await inject('GET', '/auth/mfa');
      expect(status.json<MfaStatus>().recoveryCodesLeft).toBe(9);
    });

    it('el mismo código de recuperación en dos logins simultáneos: solo entra uno', async () => {
      const code = recoveryCodes[1];
      const [a, b] = await Promise.all([
        passwordStep(ADMIN.email, ADMIN.password),
        passwordStep(ADMIN.email, ADMIN.password),
      ]);
      const results = await Promise.all(
        [a, b].map((s) =>
          inject('POST', '/auth/mfa/verify', { token: s.token, payload: { code } }),
        ),
      );
      expect(results.map((r) => r.statusCode).sort()).toEqual([200, 400]);
    });

    it('a los 5 códigos incorrectos se borra la sesión intermedia (401)', async () => {
      const bruno = await loginToken(app, BRUNO.email, BRUNO.password);
      await enableTotp(app, BRUNO.email, bruno);
      const step = await passwordStep(BRUNO.email, BRUNO.password);
      const statuses: number[] = [];
      for (let i = 0; i < 5; i++)
        statuses.push(
          (
            await inject('POST', '/auth/mfa/verify', {
              token: step.token,
              payload: { code: '000000' },
            })
          ).statusCode,
        );
      expect(statuses).toEqual([400, 400, 400, 400, 401]);
      expect((await inject('GET', '/auth/session', { token: step.token })).statusCode).toBe(401);
      // Un código bueno ya no sirve con esa sesión.
      const late = await inject('POST', '/auth/mfa/verify', {
        token: step.token,
        payload: { code: await nextTotpCode(BRUNO.email) },
      });
      expect(late.statusCode).toBe(401);
      expect(await lastEvent('auth.mfa_challenge')).toMatchObject({
        outcome: 'failure',
        actorEmail: BRUNO.email,
      });
    });

    it('límite por usuario y compartido: repartir intentos entre IPs y rutas no sirve (429)', async () => {
      const tina = await loginToken(app, TINA.email, TINA.password);
      await enableTotp(app, TINA.email, tina); // la confirmación ya gasta una del cupo
      const statuses: number[] = [];
      for (let i = 0; i <= THROTTLE; i++)
        statuses.push(
          (
            await inject('POST', '/auth/reauth', {
              token: tina,
              payload: { code: '000000' },
              remoteAddress: i % 2 ? '203.0.113.1' : '203.0.113.2',
            })
          ).statusCode,
        );
      expect(statuses.slice(0, THROTTLE - 1).every((s) => s === 400)).toBe(true);
      expect(statuses.slice(THROTTLE - 1)).toEqual([429, 429]);
      // Otra ruta de códigos tampoco: el cupo es del usuario.
      const other = await inject('POST', '/auth/mfa/enable', {
        token: tina,
        payload: { code: '000000' },
        remoteAddress: '203.0.113.3',
      });
      expect(other.statusCode).toBe(429);
    });
  });

  describe('reautenticación reciente (step-up) con código', () => {
    it('purgar pide el código si han pasado más de 10 minutos; retirar no', async () => {
      const id = await retiredAsset('purga-mfa');
      await ageReauth(admin, 11);
      const denied = await inject('DELETE', `/assets/${id}?purge=true`);
      expect(denied.statusCode).toBe(403);
      expect(denied.json()).toMatchObject({
        code: 'recent_auth_required',
        method: 'totp',
        action: 'asset.purge',
      });
      expect(await lastEvent('auth.reauth_required')).toMatchObject({
        outcome: 'failure',
        details: { action: 'asset.purge', reason: 'recent_auth_required' },
      });
      // Retirar (reversible) no lo pide.
      const other = await retiredAsset('retirar-mfa');
      await db.query(`UPDATE assets SET status = 'active' WHERE id = $1`, [other]);
      expect((await inject('DELETE', `/assets/${other}`)).statusCode).toBe(200);

      const bad = await inject('POST', '/auth/reauth', {
        payload: { code: '000000', action: 'asset.purge' },
      });
      expect(bad.statusCode).toBe(400);
      expect(await lastEvent('auth.reauth')).toMatchObject({
        outcome: 'failure',
        details: { reason: 'bad_code', action: 'asset.purge' },
      });
      const ok = await inject('POST', '/auth/reauth', {
        payload: { code: await nextTotpCode(ADMIN.email), action: 'asset.purge' },
      });
      expect(ok.statusCode).toBe(200);
      expect(Date.parse(ok.json<{ reauthenticatedUntil: string }>().reauthenticatedUntil)).toBeGreaterThan(
        Date.now() + 9 * 60_000,
      );
      expect((await inject('DELETE', `/assets/${id}?purge=true`)).statusCode).toBe(200);
      expect(await lastEvent('auth.reauth')).toMatchObject({
        outcome: 'success',
        details: { method: 'totp', action: 'asset.purge' },
      });
    });

    it('cambiar roles, desactivar y restablecer el TOTP de otro también la piden', async () => {
      const [rita] = await db.query(`SELECT id FROM users WHERE email = $1`, [RITA.email]);
      await ageReauth(admin, 11);
      for (const [method, url, payload, action] of [
        ['PATCH', `/users/${rita.id}`, { role: 'viewer' }, 'user.role_change'],
        ['POST', `/users/${rita.id}/deactivate`, undefined, 'user.deactivate'],
        ['POST', `/users/${rita.id}/mfa/reset`, undefined, 'user.mfa_reset'],
      ] as const) {
        const res = await inject(method, url, { payload });
        expect(res.statusCode, url).toBe(403);
        expect(res.json()).toMatchObject({ code: 'recent_auth_required', action });
      }
      // Cambiar solo el nombre no.
      expect(
        (await inject('PATCH', `/users/${rita.id}`, { payload: { name: 'Rita' } })).statusCode,
      ).toBe(200);
    });

    it('un admin restablece el TOTP de otro: le cierra las sesiones y queda auditado', async () => {
      const rita = await loginToken(app, RITA.email, RITA.password);
      await enableTotp(app, RITA.email, rita);
      const [row] = await db.query(`SELECT id FROM users WHERE email = $1`, [RITA.email]);
      await inject('POST', '/auth/reauth', { payload: { code: await nextTotpCode(ADMIN.email) } });
      const res = await inject('POST', `/users/${row.id}/mfa/reset`);
      expect(res.statusCode).toBe(200);
      expect(res.json<UserSummary>().mfaEnabled).toBe(false);
      expect((await inject('GET', '/auth/session', { token: rita })).statusCode).toBe(401);
      expect(await lastEvent('user.mfa_reset')).toMatchObject({
        outcome: 'success',
        targetLabel: RITA.email,
        details: { sessionsRevoked: 1 },
      });
      const after: { n: number }[] = await db.query(
        `SELECT count(*)::int AS n FROM user_recovery_codes WHERE user_id = $1`,
        [row.id],
      );
      expect(after[0].n).toBe(0);
      // Sin TOTP que quitar, 409; a uno mismo, 400.
      expect((await inject('POST', `/users/${row.id}/mfa/reset`)).statusCode).toBe(409);
      const [me] = await db.query(`SELECT id FROM users WHERE email = $1`, [ADMIN.email]);
      expect((await inject('POST', `/users/${me.id}/mfa/reset`)).statusCode).toBe(400);
    });

    it('un usuario local sin TOTP: crear un token de escritura le pide activarlo', async () => {
      const editor = await loginToken(app, EDITOR.email, EDITOR.password);
      const res = await inject('POST', '/auth/tokens', {
        token: editor,
        payload: {
          name: 'ci',
          scope: 'role',
          expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json()).toMatchObject({ code: 'mfa_required_for_action', method: 'totp' });
      // Sin TOTP, /auth/reauth no tiene con qué: 409.
      expect(
        (await inject('POST', '/auth/reauth', { token: editor, payload: { code: '123456' } }))
          .statusCode,
      ).toBe(409);
    });

    it('un no admin puede quitarse el TOTP (con reautenticación)', async () => {
      const bruno = await loginToken(app, BRUNO.email, BRUNO.password);
      await ageReauth(bruno, 11);
      expect((await inject('POST', '/auth/mfa/disable', { token: bruno })).statusCode).toBe(403);
      await inject('POST', '/auth/reauth', {
        token: bruno,
        payload: { code: await nextTotpCode(BRUNO.email) },
      });
      expect((await inject('POST', '/auth/mfa/disable', { token: bruno })).statusCode).toBe(204);
      expect(
        (await inject('GET', '/auth/mfa', { token: bruno })).json<MfaStatus>().enabled,
      ).toBe(false);
      // Y vuelve a entrar sin segundo paso.
      expect((await passwordStep(BRUNO.email, BRUNO.password)).info.mfaPending).toBe(false);
    });

    it('con un token de API, una acción sensible siempre es 403 (solo desde la web)', async () => {
      await inject('POST', '/auth/reauth', { payload: { code: await nextTotpCode(ADMIN.email) } });
      const created = await inject('POST', '/auth/tokens', {
        payload: {
          name: 'admin-role',
          scope: 'role',
          expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        },
      });
      expect(created.statusCode).toBe(201);
      const { secret } = created.json<CreatedApiTokenResponse>();
      const id = await retiredAsset('purga-con-token');
      const res = await inject('DELETE', `/assets/${id}?purge=true`, {
        token: null,
        bearer: secret,
      });
      expect(res.statusCode).toBe(403);
      expect(res.json()).toMatchObject({ code: 'recent_auth_required', method: null });
      // Lo no sensible con el mismo token sí.
      expect(
        (await inject('GET', '/assets/tree', { token: null, bearer: secret })).statusCode,
      ).toBe(200);
    });
  });

  describe('reautenticación con el proveedor OIDC', () => {
    async function begin() {
      const res = await inject('GET', '/auth/oidc/login', { token: null });
      expect(res.statusCode).toBe(302);
      const binding = res.cookies.find((c) => c.name === FLOW_COOKIE)!.value;
      return { location: String(res.headers.location), binding };
    }

    function callback(query: Record<string, string>, binding: string) {
      return inject('GET', `/auth/oidc/callback?${new URLSearchParams(query)}`, {
        token: null,
        cookie: `${FLOW_COOKIE}=${binding}`,
      });
    }

    async function oidcSession(authTime: number): Promise<string> {
      const { location, binding } = await begin();
      const { code, state } = fake.authorize(location, ana, { authTime });
      const res = await callback({ code, state }, binding);
      expect(res.statusCode).toBe(302);
      const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE && c.value)!.value;
      const session = await app.inject({
        method: 'GET',
        url: '/auth/session',
        headers: { cookie: `${SESSION_COOKIE}=${cookie}` },
      });
      return `${cookie} ${session.json<SessionInfo>().csrfToken}`;
    }

    /** Empieza la reautenticación con la sesión (navegación con su cookie Strict). */
    async function startReauth(token: string, returnUrl: string) {
      const res = await inject('GET', `/auth/oidc/reauth?returnUrl=${encodeURIComponent(returnUrl)}`, {
        token,
      });
      expect(res.statusCode).toBe(302);
      const binding = res.cookies.find((c) => c.name === FLOW_COOKIE)!.value;
      return { location: String(res.headers.location), binding };
    }

    it('una sesión SSO antigua no cuenta; purgar redirige al proveedor y a la vuelta purga', async () => {
      // El proveedor reutilizó una sesión de hace una hora: no es una reautenticación reciente.
      const anaToken = await oidcSession(-3600);
      const session = (await inject('GET', '/auth/session', { token: anaToken })).json<SessionInfo>();
      expect(session).toMatchObject({ reauthMethod: 'oidc', mfaSetupRequired: false });
      expect(session.reauthenticatedUntil).not.toBeNull();
      expect(Date.parse(session.reauthenticatedUntil!)).toBeLessThan(Date.now());

      const id = await retiredAsset('purga-oidc');
      const denied = await inject('DELETE', `/assets/${id}?purge=true`, { token: anaToken });
      expect(denied.statusCode).toBe(403);
      expect(denied.json()).toMatchObject({ code: 'recent_auth_required', method: 'oidc' });
      // Con una sesión OIDC, el código local no aplica.
      expect(
        (await inject('POST', '/auth/reauth', { token: anaToken, payload: { code: '123456' } }))
          .statusCode,
      ).toBe(409);

      const returnUrl = `/inventory/${id}?tab=resumen`;
      const { location, binding } = await startReauth(anaToken, returnUrl);
      expect(location.startsWith(fake.issuer)).toBe(true);
      const { code, state } = fake.authorize(location, ana, { authTime: 0 });
      // El proveedor debe volver a pedir las credenciales.
      expect(fake.lastAuthorization?.get('prompt')).toBe('login');
      expect(fake.lastAuthorization?.get('max_age')).toBe('0');
      const back = await callback({ code, state }, binding);
      expect(back.statusCode).toBe(302);
      expect(back.headers.location).toBe(`${WEB}/inventory/${id}?tab=resumen&reauth=ok`);
      // No abre otra sesión: marca la que lo pidió.
      expect(back.cookies.find((c) => c.name === SESSION_COOKIE && c.value)).toBeUndefined();
      expect((await inject('DELETE', `/assets/${id}?purge=true`, { token: anaToken })).statusCode).toBe(200);
      expect(await lastEvent('auth.reauth')).toMatchObject({
        outcome: 'success',
        actorEmail: ana.email,
        details: { method: 'oidc' },
      });
    });

    it.each([
      ['sin auth_time', { authTime: null }, 'auth_time_missing'],
      ['auth_time anterior al inicio (no volvió a pedir las credenciales)', { authTime: -120 }, 'auth_time_stale'],
      ['otra identidad del proveedor', { authTime: 0, sub: 'kc-otra' }, 'subject_mismatch'],
    ] as const)('rechazo: %s', async (_label, tamper, reason) => {
      const anaToken = await oidcSession(-3600);
      const { location, binding } = await startReauth(anaToken, '/vulnerabilities');
      const { code, state } = fake.authorize(location, ana, tamper);
      const back = await callback({ code, state }, binding);
      expect(back.statusCode).toBe(302);
      expect(back.headers.location).toBe(`${WEB}/vulnerabilities?reauth=failed`);
      expect(await lastEvent('auth.reauth')).toMatchObject({
        outcome: 'failure',
        details: { method: 'oidc', reason },
      });
      const id = await retiredAsset(`no-purga-${reason}`);
      expect(
        (await inject('DELETE', `/assets/${id}?purge=true`, { token: anaToken })).statusCode,
      ).toBe(403);
    });

    it('rechazo: la sesión se cerró antes de volver', async () => {
      const anaToken = await oidcSession(-3600);
      const { location, binding } = await startReauth(anaToken, '/dashboard');
      await inject('POST', '/auth/logout', { token: anaToken });
      const { code, state } = fake.authorize(location, ana, { authTime: 0 });
      const back = await callback({ code, state }, binding);
      expect(back.headers.location).toBe(`${WEB}/dashboard?reauth=failed`);
      expect(await lastEvent('auth.reauth')).toMatchObject({
        outcome: 'failure',
        details: { reason: 'session_closed' },
      });
    });

    it('rechazo: el state es de un solo uso y va atado al navegador', async () => {
      const anaToken = await oidcSession(-3600);
      const { location } = await startReauth(anaToken, '/dashboard');
      const { code, state } = fake.authorize(location, ana, { authTime: 0 });
      const other = await callback({ code, state }, 'cookie-de-otro-navegador');
      expect(other.headers.location).toBe(`${WEB}/login?oidcError=failed`);
      const id = await retiredAsset('no-purga-state');
      expect(
        (await inject('DELETE', `/assets/${id}?purge=true`, { token: anaToken })).statusCode,
      ).toBe(403);
    });

    it('una sesión local no se reautentica con el proveedor (409)', async () => {
      expect((await inject('GET', '/auth/oidc/reauth?returnUrl=/')).statusCode).toBe(409);
    });

    it('un login OIDC recién tecleado ya cuenta como reautenticación', async () => {
      const anaToken = await oidcSession(0);
      const id = await retiredAsset('purga-oidc-fresca');
      expect(
        (await inject('DELETE', `/assets/${id}?purge=true`, { token: anaToken })).statusCode,
      ).toBe(200);
    });
  });

  it('0 fugas: ni los secretos TOTP ni los códigos de recuperación en BD, Redis, logs ni respuestas', async () => {
    const secrets = [ADMIN, EDITOR, BRUNO, TINA, RITA]
      .map((u) => totpSecretOf(u.email))
      .filter((s): s is string => Boolean(s));
    expect(secrets.length).toBeGreaterThanOrEqual(3);
    expect(recoveryCodes.length).toBe(10);
    const dump = JSON.stringify(
      await db.query(`SELECT row_to_json(t) AS r FROM (SELECT * FROM users) t
         UNION ALL SELECT row_to_json(a) FROM audit_events a
         UNION ALL SELECT row_to_json(s) FROM user_sessions s
         UNION ALL SELECT row_to_json(c) FROM user_recovery_codes c
         UNION ALL SELECT row_to_json(l) FROM local_secrets l`),
    );
    const redis = new Redis({
      host: redisUrl().hostname,
      port: Number(redisUrl().port || 6379),
      db: Number(redisDb()),
    });
    const values: string[] = [];
    for (const key of await redis.keys('*'))
      if ((await redis.type(key)) === 'string') values.push((await redis.get(key)) ?? '');
    await redis.quit();
    const logs = output.join('');
    const others = responses.join('\n');
    const normalized = recoveryCodes.map((c) => c.replace(/-/g, '').toUpperCase());
    for (const value of [...secrets, ...recoveryCodes, ...normalized]) {
      expect(dump).not.toContain(value);
      expect(values.join('\n')).not.toContain(value);
      expect(logs).not.toContain(value);
      expect(others).not.toContain(value);
    }
    // Solo las respuestas del alta y la confirmación los llevan (una vez).
    expect(revealing.length).toBeGreaterThan(0);
  });
});
