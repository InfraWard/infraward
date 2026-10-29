import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  AuditEvent,
  AuditPage,
  AuthProviders,
  LogoutResponse,
  SessionInfo,
  TemporaryPasswordResponse,
  UserSummary,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { User } from '../src/users/user.entity.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
  SESSION_COOKIE,
} from './support/app.js';
import {
  FakeOidcProvider,
  type FakeOidcUser,
  type IdTokenTamper,
} from './support/fake-oidc.js';

const WEB = 'http://infraward.test';
const FLOW_COOKIE = '__Host-iw_oidc';
const SECRET_REF = 'secret://local/oidc/e2e#client_secret';

/**
 * QoL-2 (DESIGN §14): login con OIDC contra un proveedor falso en proceso. Rechazos (state,
 * nonce, issuer, audiencia, caducidad, firma…), alta automática con rol por grupo,
 * reevaluación del rol, enlace por email verificado, logout del proveedor y auditoría.
 */
describe('Login con OIDC (e2e)', () => {
  const fake = new FakeOidcProvider();
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  const output: string[] = [];
  const responses: string[] = [];

  const ana: FakeOidcUser = {
    sub: 'kc-ana',
    email: 'Ana@Example.test',
    email_verified: true,
    name: 'Ana García',
    groups: ['infraward-editors'],
  };

  beforeAll(async () => {
    await fake.start();
    await prepareEnv('e2e_oidc', {
      LOGIN_THROTTLE_LIMIT: '1000',
      OIDC_ISSUER: fake.issuer,
      OIDC_CLIENT_ID: fake.clientId,
      OIDC_CLIENT_SECRET_REF: SECRET_REF,
      OIDC_REDIRECT_URI: `${WEB}/api/auth/oidc/callback`,
      OIDC_PROVIDER_NAME: 'Fake IdP',
      OIDC_ROLE_MAPPING:
        'infraward-admins=admin,infraward-editors=editor,infraward-viewers=viewer',
    });
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
    await app
      .get(SecretsService)
      .store(SECRET_REF.split('#')[0], { client_secret: fake.clientSecret });
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await app?.close();
    await fake.stop();
  });

  async function inject(
    method: 'GET' | 'POST' | 'PATCH',
    url: string,
    options: { token?: string | null; payload?: object; cookie?: string } = {},
  ) {
    const token = options.token === undefined ? admin : options.token;
    const headers: Record<string, string> = token ? authHeaders(token) : {};
    if (options.cookie) headers.cookie = options.cookie;
    const res = await app.inject({
      method,
      url,
      payload: options.payload,
      headers,
    });
    responses.push(JSON.stringify(res.headers), res.body);
    return res;
  }

  /** Empieza el flujo como lo haría el navegador: redirección al proveedor y cookie de enlace. */
  async function begin(returnUrl?: string) {
    const res = await inject(
      'GET',
      `/auth/oidc/login${returnUrl === undefined ? '' : `?returnUrl=${encodeURIComponent(returnUrl)}`}`,
      { token: null },
    );
    expect(res.statusCode).toBe(302);
    const flow = res.cookies.find((c) => c.name === FLOW_COOKIE);
    expect(flow).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      path: '/',
    });
    return { location: String(res.headers.location), binding: flow!.value };
  }

  function callback(query: Record<string, string>, binding?: string) {
    return inject('GET', `/auth/oidc/callback?${new URLSearchParams(query)}`, {
      token: null,
      cookie: binding ? `${FLOW_COOKIE}=${binding}` : undefined,
    });
  }

  async function oidcLogin(
    user: FakeOidcUser,
    tamper: IdTokenTamper = {},
    returnUrl?: string,
  ) {
    const { location, binding } = await begin(returnUrl);
    const { code, state } = fake.authorize(location, user, tamper);
    return callback({ code, state }, binding);
  }

  function sessionCookieOf(res: {
    cookies: { name: string; value: string }[];
  }) {
    return res.cookies.find((c) => c.name === SESSION_COOKIE && c.value)?.value;
  }

  /** Sesión abierta por el callback: cookie + CSRF (como `sessionToken`). */
  async function sessionOf(
    res: Awaited<ReturnType<typeof callback>>,
  ): Promise<string> {
    expect(res.statusCode).toBe(302);
    const cookie = sessionCookieOf(res);
    expect(cookie).toBeTruthy();
    const session = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: `${SESSION_COOKIE}=${cookie}` },
    });
    expect(session.statusCode).toBe(200);
    return `${cookie} ${session.json<SessionInfo>().csrfToken}`;
  }

  async function profile(token: string): Promise<SessionInfo['user']> {
    const res = await inject('GET', '/auth/session', { token });
    return res.json<SessionInfo>().user;
  }

  async function lastEvent(action: string): Promise<AuditEvent> {
    const res = await inject('GET', `/audit?action=${action}&limit=1`);
    expect(res.statusCode).toBe(200);
    return res.json<AuditPage>().items[0];
  }

  /** Rechazo: vuelta a /login con el código, sin sesión, cookie del flujo borrada y auditado. */
  async function expectRejected(
    res: Awaited<ReturnType<typeof callback>>,
    reason: string,
    error = 'failed',
  ) {
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe(`${WEB}/login?oidcError=${error}`);
    expect(sessionCookieOf(res)).toBeUndefined();
    expect(res.cookies.find((c) => c.name === FLOW_COOKIE)?.value).toBe('');
    const event = await lastEvent('auth.login_failed');
    expect(event).toMatchObject({
      outcome: 'failure',
      details: { method: 'oidc', reason },
    });
    return event;
  }

  async function userByEmail(email: string) {
    return db.getRepository(User).findOneBy({ email });
  }

  it('GET /auth/providers anuncia el login local y el proveedor', async () => {
    const res = await inject('GET', '/auth/providers', { token: null });
    expect(res.statusCode).toBe(200);
    expect(res.json<AuthProviders>()).toEqual({
      local: true,
      oidc: { name: 'Fake IdP' },
    });
  });

  it('el inicio pide code + PKCE S256 + state + nonce con la redirect_uri de la web', async () => {
    const { location } = await begin();
    const url = new URL(location);
    expect(url.searchParams.get('redirect_uri')).toBe(
      `${WEB}/api/auth/oidc/callback`,
    );
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('state')?.length).toBeGreaterThanOrEqual(32);
    expect(url.searchParams.get('nonce')?.length).toBeGreaterThanOrEqual(32);
    expect(url.searchParams.get('scope')).toBe('openid email profile');
  });

  describe('rechazos', () => {
    it('state desconocido', async () => {
      const { binding } = await begin();
      await expectRejected(
        await callback({ code: 'x', state: 'inventado' }, binding),
        'state_invalid',
      );
    });

    it('state reutilizado (replay) tras un login correcto', async () => {
      const { location, binding } = await begin();
      const { code, state } = fake.authorize(location, {
        ...ana,
        sub: 'kc-replay',
        email: 'replay@example.test',
        email_verified: true,
      });
      const ok = await callback({ code, state }, binding);
      expect(sessionCookieOf(ok)).toBeTruthy();
      await expectRejected(
        await callback({ code, state }, binding),
        'state_invalid',
      );
    });

    it('sin la cookie del navegador que empezó el flujo, o con la de otro', async () => {
      const first = await begin();
      const { code, state } = fake.authorize(first.location, ana);
      await expectRejected(await callback({ code, state }), 'state_invalid');

      const victim = await begin();
      const attacker = await begin();
      const stolen = fake.authorize(attacker.location, ana);
      await expectRejected(
        await callback(
          { code: stolen.code, state: stolen.state },
          victim.binding,
        ),
        'state_invalid',
      );
    });

    it('code de otro flujo: el code_verifier no casa (PKCE) → error del proveedor', async () => {
      const a = await begin();
      const b = await begin();
      const codeOfB = fake.authorize(b.location, ana).code;
      const stateOfA = new URL(a.location).searchParams.get('state')!;
      await expectRejected(
        await callback({ code: codeOfB, state: stateOfA }, a.binding),
        'provider_error',
      );
    });

    it('error del proveedor (access_denied)', async () => {
      const { location, binding } = await begin();
      const state = new URL(location).searchParams.get('state')!;
      const event = await expectRejected(
        await callback({ error: 'access_denied', state }, binding),
        'provider_error',
      );
      expect(event.details.providerError).toBe('access_denied');
    });

    it('nonce inválido', async () => {
      await expectRejected(
        await oidcLogin(ana, { nonce: 'otro-nonce' }),
        'nonce_invalid',
      );
    });

    it('issuer incorrecto', async () => {
      await expectRejected(
        await oidcLogin(ana, { iss: 'https://evil.example' }),
        'issuer_invalid',
      );
    });

    it('audiencia incorrecta', async () => {
      await expectRejected(
        await oidcLogin(ana, { aud: 'otra-app' }),
        'audience_invalid',
      );
    });

    it('token caducado', async () => {
      await expectRejected(
        await oidcLogin(ana, { expiresIn: -600 }),
        'token_expired',
      );
    });

    it('firma con una clave que no es del proveedor', async () => {
      await expectRejected(
        await oidcLogin(ana, { signWith: 'rogue' }),
        'signature_invalid',
      );
    });

    it('sin firma (alg: none)', async () => {
      await expectRejected(
        await oidcLogin(ana, { signWith: 'none' }),
        'signature_invalid',
      );
    });

    it('ningún rechazo creó la cuenta', async () => {
      expect(await userByEmail('ana@example.test')).toBeNull();
    });
  });

  describe('alta automática y rol por grupo', () => {
    let anaToken: string;

    it('primer login: se crea sola con el rol de su grupo y vuelve a returnUrl', async () => {
      const res = await oidcLogin(ana, {}, '/assets?x=1');
      expect(res.headers.location).toBe(`${WEB}/assets?x=1`);
      const session = res.cookies.find((c) => c.name === SESSION_COOKIE)!;
      expect(session).toMatchObject({
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        path: '/',
      });
      expect(session.maxAge).toBeUndefined();
      anaToken = await sessionOf(res);
      expect(await profile(anaToken)).toMatchObject({
        email: 'ana@example.test',
        name: 'Ana García',
        role: 'editor',
        origin: 'oidc',
        oidcLinked: true,
      });
      expect(await lastEvent('user.created')).toMatchObject({
        targetLabel: 'ana@example.test',
        details: {
          method: 'oidc',
          role: 'editor',
          groups: ['infraward-editors'],
        },
      });
      expect(await lastEvent('auth.login')).toMatchObject({
        actorEmail: 'ana@example.test',
        details: { method: 'oidc', role: 'editor' },
      });
      // Sin contraseña utilizable.
      const row = await userByEmail('ana@example.test');
      expect(row?.passwordHash).toBe('!consumed');
    });

    it('una returnUrl externa se ignora', async () => {
      const res = await oidcLogin(ana, {}, '//evil.example/x');
      expect(res.headers.location).toBe(`${WEB}/`);
    });

    it('cambia de grupo en el proveedor → nuevo rol al volver a entrar (y nombre)', async () => {
      const res = await oidcLogin({
        ...ana,
        name: 'Ana G.',
        groups: ['infraward-admins', 'otros'],
      });
      const token = await sessionOf(res);
      expect(await profile(token)).toMatchObject({
        role: 'admin',
        name: 'Ana G.',
      });
      expect(await lastEvent('user.role_changed')).toMatchObject({
        outcome: 'success',
        details: {
          method: 'oidc',
          from: 'editor',
          to: 'admin',
          groups: ['infraward-admins'],
        },
      });
      // El rol se lee de la BD en cada petición: la sesión anterior ya es admin.
      expect(
        (await inject('GET', '/users', { token: anaToken })).statusCode,
      ).toBe(200);
    });

    it('el rol de un usuario enlazado no se cambia a mano; tampoco su contraseña', async () => {
      const row = await userByEmail('ana@example.test');
      const patch = await inject('PATCH', `/users/${row!.id}`, {
        payload: { role: 'viewer' },
      });
      expect(patch.statusCode).toBe(409);
      const reset = await inject('POST', `/users/${row!.id}/reset-password`);
      expect(reset.statusCode).toBe(409);
      const list = (await inject('GET', '/users')).json<UserSummary[]>();
      expect(list.find((u) => u.email === 'ana@example.test')).toMatchObject({
        origin: 'oidc',
        oidcLinked: true,
        emergency: false,
      });
    });

    it('sin grupo con rol → acceso denegado y no se crea la cuenta', async () => {
      const bruno = {
        sub: 'kc-bruno',
        email: 'bruno@example.test',
        email_verified: true,
        groups: ['otros'],
      };
      const event = await expectRejected(
        await oidcLogin(bruno),
        'no_role_mapping',
        'denied',
      );
      expect(event.details.groups).toEqual(['otros']);
      expect(await userByEmail('bruno@example.test')).toBeNull();
    });

    it('email sin verificar (o sin el claim) → no se crea la cuenta (revisión #3, M3)', async () => {
      for (const email_verified of [false, undefined]) {
        await expectRejected(
          await oidcLogin({
            sub: 'kc-dora',
            email: 'dora@example.test',
            ...(email_verified === undefined ? {} : { email_verified }),
            groups: ['infraward-editors'],
          }),
          'email_unverified',
          'email_unverified',
        );
        expect(await userByEmail('dora@example.test')).toBeNull();
      }
    });

    it('desactivado en InfraWard → no entra aunque el proveedor diga que sí', async () => {
      const row = await userByEmail('ana@example.test');
      expect(
        (await inject('POST', `/users/${row!.id}/deactivate`)).statusCode,
      ).toBe(200);
      await expectRejected(await oidcLogin(ana), 'disabled', 'disabled');
      expect(
        (await inject('POST', `/users/${row!.id}/reactivate`)).statusCode,
      ).toBe(200);
    });
  });

  describe('enlace con usuarios locales por email', () => {
    async function createLocal(email: string): Promise<string> {
      const res = await inject('POST', '/users', {
        payload: { email, name: 'Local', role: 'viewer' },
      });
      expect(res.statusCode).toBe(201);
      return res.json<TemporaryPasswordResponse>().user.id;
    }

    it('email verificado → enlaza la cuenta local y aplica el rol del grupo', async () => {
      const id = await createLocal('carlos@example.test');
      const res = await oidcLogin({
        sub: 'kc-carlos',
        email: 'carlos@example.test',
        email_verified: true,
        groups: ['infraward-editors'],
      });
      const token = await sessionOf(res);
      expect(await profile(token)).toMatchObject({
        id,
        origin: 'local',
        oidcLinked: true,
        role: 'editor',
      });
      expect(await lastEvent('user.oidc_linked')).toMatchObject({
        targetId: id,
      });
    });

    it('email sin verificar → no enlaza (email_conflict) y la cuenta sigue intacta', async () => {
      const id = await createLocal('carla@example.test');
      await expectRejected(
        await oidcLogin({
          sub: 'kc-carla',
          email: 'carla@example.test',
          email_verified: false,
          groups: ['infraward-admins'],
        }),
        'email_unverified',
        'email_conflict',
      );
      // email_verified ausente (p. ej. Entra) tampoco cuenta.
      await expectRejected(
        await oidcLogin({
          sub: 'kc-carla',
          email: 'carla@example.test',
          groups: ['infraward-admins'],
        }),
        'email_unverified',
        'email_conflict',
      );
      const row = await db.getRepository(User).findOneBy({ id });
      expect(row).toMatchObject({ oidcSubject: null, role: 'viewer' });
    });

    it('otra identidad con el email de una cuenta ya enlazada → email_conflict', async () => {
      await expectRejected(
        await oidcLogin({
          sub: 'kc-otro',
          email: 'carlos@example.test',
          email_verified: true,
          groups: ['infraward-admins'],
        }),
        'already_linked',
        'email_conflict',
      );
    });

    it('con OIDC configurado, el email propio no se cambia (se apropiaría del rol de otro al enlazar); un admin sí', async () => {
      // Sin esto, un viewer local tomaría el email de un admin del proveedor que aún no ha
      // entrado: al entrar este, se enlazaría a su cuenta con el rol de admin.
      const session = await inject('GET', '/auth/session');
      expect(session.json<SessionInfo>().canChangeEmail).toBe(false);
      const self = await inject('POST', '/auth/email', {
        payload: { email: 'nuevo-admin@example.test', currentPassword: ADMIN.password },
      });
      expect(self.statusCode).toBe(409);
      expect(await userByEmail(ADMIN.email)).not.toBeNull();

      const id = await createLocal('dora@example.test');
      const byAdmin = await inject('PATCH', `/users/${id}`, {
        payload: { email: 'dora.nueva@example.test' },
      });
      expect(byAdmin.statusCode).toBe(200);
      expect(byAdmin.json<UserSummary>().email).toBe('dora.nueva@example.test');
    });
  });

  it('el último admin activo conserva el rol aunque el proveedor se lo quite', async () => {
    const res = await oidcLogin({ ...ana, groups: ['infraward-admins'] });
    const anaToken = await sessionOf(res);
    const local = await userByEmail(ADMIN.email);
    expect(
      (
        await inject('POST', `/users/${local!.id}/deactivate`, {
          token: anaToken,
        })
      ).statusCode,
    ).toBe(200);
    try {
      const again = await sessionOf(
        await oidcLogin({ ...ana, groups: ['infraward-editors'] }),
      );
      expect((await profile(again)).role).toBe('admin');
      const event = await (async () => {
        const page = await inject(
          'GET',
          '/audit?action=user.role_changed&limit=1',
          { token: again },
        );
        return page.json<AuditPage>().items[0];
      })();
      expect(event).toMatchObject({
        outcome: 'failure',
        details: {
          method: 'oidc',
          from: 'admin',
          to: 'editor',
          roleKept: 'last_admin',
        },
      });
      expect(
        (
          await inject('POST', `/users/${local!.id}/reactivate`, {
            token: again,
          })
        ).statusCode,
      ).toBe(200);
    } finally {
      await db
        .getRepository(User)
        .update({ id: local!.id }, { disabledAt: null });
    }
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
  });

  describe('cierre de sesión', () => {
    it('una sesión OIDC devuelve la URL para cerrar también la del proveedor', async () => {
      const token = await sessionOf(await oidcLogin(ana));
      const res = await inject('POST', '/auth/logout', { token });
      // Esta respuesta lleva el ID token como id_token_hint a propósito (la web navega al
      // proveedor con él): no cuenta en la comprobación de fugas del final.
      responses.splice(responses.lastIndexOf(res.body), 1);
      expect(res.statusCode).toBe(200);
      const url = new URL(res.json<LogoutResponse>().providerLogoutUrl!);
      expect(`${url.origin}${url.pathname}`).toBe(
        `${fake.issuer}/protocol/openid-connect/logout`,
      );
      expect(url.searchParams.get('post_logout_redirect_uri')).toBe(
        `${WEB}/login?loggedOut=1`,
      );
      expect(url.searchParams.get('client_id')).toBe(fake.clientId);
      expect(fake.issuedIdTokens).toContain(
        url.searchParams.get('id_token_hint'),
      );
      expect((await inject('GET', '/auth/session', { token })).statusCode).toBe(
        401,
      );
      expect(await lastEvent('auth.logout')).toMatchObject({
        details: { method: 'oidc', providerLogout: true },
      });
    });

    it('una sesión local no toca el proveedor', async () => {
      const token = await loginToken(app, ADMIN.email, ADMIN.password);
      const res = await inject('POST', '/auth/logout', { token });
      expect(res.json<LogoutResponse>()).toEqual({ providerLogoutUrl: null });
    });
  });

  it('la auditoría nunca guarda tokens, codes ni el secreto del cliente', async () => {
    const rows: {
      details: unknown;
      actor_email: string | null;
      target_label: string | null;
    }[] = await db.query(
      'SELECT details, actor_email, target_label FROM audit_events',
    );
    const dump = JSON.stringify(rows);
    for (const value of [
      fake.clientSecret,
      ...fake.issuedIdTokens,
      ...fake.issuedCodes,
    ])
      expect(dump).not.toContain(value);
  });

  it('0 fugas: ni el secreto del cliente ni los ID tokens ni los codes en logs o respuestas', () => {
    const logs = output.join('');
    const bodies = responses.join('\n');
    for (const value of [fake.clientSecret, ...fake.issuedIdTokens]) {
      expect(logs).not.toContain(value);
      expect(bodies).not.toContain(value);
    }
    for (const code of fake.issuedCodes) expect(logs).not.toContain(code);
  });
});
