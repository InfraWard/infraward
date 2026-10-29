import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  AuditPage,
  AuthProviders,
  SessionInfo,
  UserSummary,
} from '@infraward/shared-types';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  login,
  loginToken,
  prepareEnv,
  SESSION_COOKIE,
} from './support/app.js';
import { FakeOidcProvider, type FakeOidcUser } from './support/fake-oidc.js';

const WEB = 'http://infraward.test';
const FLOW_COOKIE = '__Host-iw_oidc';
const SECRET_REF = 'secret://local/oidc/e2e#client_secret';

/**
 * QoL-2 (DESIGN §14): login local desactivado (LOCAL_LOGIN=false) salvo el admin de emergencia,
 * y usuarios sin grupo con rol como viewer (OIDC_UNMAPPED=viewer).
 */
describe('Login local desactivado y admin de emergencia (e2e)', () => {
  const fake = new FakeOidcProvider();
  let app: NestFastifyApplication;
  let admin: string;

  beforeAll(async () => {
    await fake.start();
    await prepareEnv('e2e_oidc_local', {
      LOGIN_THROTTLE_LIMIT: '1000',
      OIDC_ISSUER: fake.issuer,
      OIDC_CLIENT_ID: fake.clientId,
      OIDC_CLIENT_SECRET_REF: SECRET_REF,
      OIDC_REDIRECT_URI: `${WEB}/api/auth/oidc/callback`,
      OIDC_ROLE_MAPPING: 'infraward-admins=admin',
      OIDC_UNMAPPED: 'viewer',
      LOCAL_LOGIN: 'false',
      LOCAL_LOGIN_EMERGENCY_EMAIL: ADMIN.email.toUpperCase(),
    });
    app = await createTestApp();
    await app
      .get(SecretsService)
      .store(SECRET_REF.split('#')[0], { client_secret: fake.clientSecret });
    // Un usuario local de antes de desactivar el login local.
    await app
      .get(UsersService)
      .create('local@example.test', 'otra-contraseña-larga', 'admin');
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
  });

  afterAll(async () => {
    await app?.close();
    await fake.stop();
  });

  async function oidcLogin(user: FakeOidcUser) {
    const start = await app.inject({ method: 'GET', url: '/auth/oidc/login' });
    const binding = start.cookies.find((c) => c.name === FLOW_COOKIE)!.value;
    const { code, state } = fake.authorize(
      String(start.headers.location),
      user,
    );
    return app.inject({
      method: 'GET',
      url: `/auth/oidc/callback?${new URLSearchParams({ code, state })}`,
      headers: { cookie: `${FLOW_COOKIE}=${binding}` },
    });
  }

  async function lastFailure() {
    const res = await app.inject({
      method: 'GET',
      url: '/audit?action=auth.login_failed&limit=1',
      headers: authHeaders(admin),
    });
    return res.json<AuditPage>().items[0];
  }

  it('GET /auth/providers: sin login local, con el proveedor', async () => {
    const res = await app.inject({ method: 'GET', url: '/auth/providers' });
    expect(res.json<AuthProviders>()).toEqual({
      local: false,
      oidc: { name: 'OIDC' },
    });
  });

  it('el admin de emergencia entra con contraseña (email sin distinguir mayúsculas)', async () => {
    expect((await login(app, ADMIN.email, ADMIN.password)).statusCode).toBe(
      200,
    );
  });

  it('cualquier otro usuario local: «Credenciales inválidas» y el motivo en la auditoría', async () => {
    const res = await login(app, 'local@example.test', 'otra-contraseña-larga');
    expect(res.statusCode).toBe(401);
    expect(res.json<{ message: string }>().message).toBe(
      'Credenciales inválidas',
    );
    expect(await lastFailure()).toMatchObject({
      actorEmail: 'local@example.test',
      details: { reason: 'local_login_disabled' },
    });
  });

  it('no se crean usuarios locales ni se restablecen contraseñas (salvo la de emergencia)', async () => {
    const create = await app.inject({
      method: 'POST',
      url: '/users',
      headers: authHeaders(admin),
      payload: { email: 'nuevo@example.test', name: 'Nuevo', role: 'viewer' },
    });
    expect(create.statusCode).toBe(409);
    const users = (
      await app.inject({
        method: 'GET',
        url: '/users',
        headers: authHeaders(admin),
      })
    ).json<UserSummary[]>();
    const local = users.find((u) => u.email === 'local@example.test')!;
    const reset = await app.inject({
      method: 'POST',
      url: `/users/${local.id}/reset-password`,
      headers: authHeaders(admin),
    });
    expect(reset.statusCode).toBe(409);
    expect(users.find((u) => u.email === ADMIN.email)).toMatchObject({
      emergency: true,
    });
    expect(local.emergency).toBe(false);
  });

  it('OIDC sin grupo con rol → viewer (OIDC_UNMAPPED=viewer)', async () => {
    const res = await oidcLogin({
      sub: 's-dani',
      email: 'dani@example.test',
      email_verified: true,
    });
    const cookie = res.cookies.find(
      (c) => c.name === SESSION_COOKIE && c.value,
    )!.value;
    const session = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: `${SESSION_COOKIE}=${cookie}` },
    });
    expect(session.json<SessionInfo>().user).toMatchObject({
      role: 'viewer',
      origin: 'oidc',
    });
  });

  it('el proveedor nunca se queda con la cuenta de emergencia (aunque el email esté verificado)', async () => {
    const res = await oidcLogin({
      sub: 's-admin',
      email: ADMIN.email,
      email_verified: true,
      groups: ['infraward-admins'],
    });
    expect(res.headers.location).toBe(`${WEB}/login?oidcError=email_conflict`);
    expect(await lastFailure()).toMatchObject({
      details: { reason: 'emergency_account' },
    });
    // Y sigue pudiendo entrar con su contraseña.
    expect((await login(app, ADMIN.email, ADMIN.password)).statusCode).toBe(
      200,
    );
  });
});
