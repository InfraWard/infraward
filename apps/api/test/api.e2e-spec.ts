import { randomBytes } from 'node:crypto';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { Redis } from 'ioredis';
import type { SessionInfo, UserProfile } from '@infraward/shared-types';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  login as loginAs,
  prepareEnv,
  SESSION_COOKIE,
  sessionToken,
} from './support/app.js';

const LOGIN_THROTTLE_LIMIT = 10;
const LOGIN_ACCOUNT_THROTTLE_LIMIT = 25;

/**
 * Una IPv6 de documentación en su propio /64 (el throttler agrupa los clientes IPv6 por /64),
 * única en esta ejecución: los contadores de Redis sobreviven al proceso.
 */
const uniqueIp = () =>
  `2001:db8:${randomBytes(4)
    .toString('hex')
    .replace(/(.{4})/, '$1:')}::1`;

describe('API (e2e)', () => {
  let app: NestFastifyApplication;
  const output: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_api', {
      LOGIN_THROTTLE_LIMIT: String(LOGIN_THROTTLE_LIMIT),
      LOGIN_ACCOUNT_THROTTLE_LIMIT: String(LOGIN_ACCOUNT_THROTTLE_LIMIT),
      // Contadores en Redis, como en producción.
      THROTTLE_STORAGE: 'redis',
    });
    // Los contadores de una ejecución local anterior de este fichero bloquearían sus logins.
    const redis = new Redis({
      host: process.env.REDIS_HOST,
      port: Number(process.env.REDIS_PORT),
      db: Number(process.env.REDIS_DB),
    });
    const stale = await redis.keys('infraward:throttle:*');
    if (stale.length > 0) await redis.del(...stale);
    await redis.quit();
    // Captura todo lo que escribe la API (Nest, TypeORM...) para comprobar que no filtra secretos.
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
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await app?.close();
  });

  const login = (email: string, password: string) =>
    loginAs(app, email, password);

  it('aplica las migraciones al arrancar', async () => {
    const { DataSource } = await import('typeorm');
    const dataSource = app.get(DataSource);
    expect(await dataSource.showMigrations()).toBe(false);
    const rows: unknown[] = await dataSource.query(
      'SELECT name FROM migrations',
    );
    expect(rows.length).toBeGreaterThan(0);
  });

  it('GET /health es público', async () => {
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ service: 'api', status: 'ok' });
  });

  it('POST /auth/login abre la sesión en una cookie httpOnly; el cuerpo no lleva el token', async () => {
    const res = await login(ADMIN.email.toUpperCase(), ADMIN.password);
    expect(res.statusCode).toBe(200);
    const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE)!;
    expect(cookie).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
    });
    expect(cookie.domain).toBeUndefined();
    expect(cookie.maxAge).toBeUndefined();
    expect(cookie.value.length).toBeGreaterThanOrEqual(43);
    const body = res.json<SessionInfo>();
    expect(body).toMatchObject({
      mustChangePassword: false,
      user: { email: ADMIN.email, role: 'admin' },
    });
    expect(body.csrfToken.length).toBeGreaterThanOrEqual(43);
    expect(res.body).not.toContain(cookie.value);
    expect(Date.parse(body.expiresAt)).toBeGreaterThan(Date.now());
  });

  it('POST /auth/login rechaza credenciales inválidas con 401 genérico', async () => {
    const wrongPassword = await login(ADMIN.email, 'contraseña-incorrecta');
    const unknownUser = await login('nadie@infraward.test', ADMIN.password);
    expect(wrongPassword.statusCode).toBe(401);
    expect(unknownUser.statusCode).toBe(401);
    expect(wrongPassword.json()).toEqual(unknownUser.json());
  });

  it('POST /auth/login valida el cuerpo', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'no-es-un-email', password: 'x', role: 'admin' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('GET /auth/me exige sesión y devuelve el perfil sin el hash', async () => {
    expect(
      (await app.inject({ method: 'GET', url: '/auth/me' })).statusCode,
    ).toBe(401);
    const badCookie = await app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { cookie: `${SESSION_COOKIE}=no-es-valida` },
    });
    expect(badCookie.statusCode).toBe(401);
    // El Bearer ya no autentica (volverá con los tokens de API).
    const bearer = await app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { authorization: 'Bearer cualquier.cosa.aqui' },
    });
    expect(bearer.statusCode).toBe(401);

    const token = sessionToken(await login(ADMIN.email, ADMIN.password));
    const res = await app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: authHeaders(token),
    });
    expect(res.statusCode).toBe(200);
    const profile = res.json<UserProfile>();
    expect(profile.email).toBe(ADMIN.email);
    expect(profile).not.toHaveProperty('passwordHash');
  });

  it('POST /auth/login limita los intentos por IP', async () => {
    const ip = uniqueIp(); // IP propia: no comparte cupo con los demás tests
    const attempt = () =>
      app.inject({
        method: 'POST',
        url: '/auth/login',
        remoteAddress: ip,
        payload: { email: ADMIN.email, password: 'fuerza-bruta' },
      });
    for (let i = 0; i < LOGIN_THROTTLE_LIMIT; i++) {
      expect((await attempt()).statusCode).toBe(401);
    }
    const blocked = await attempt();
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers['retry-after']).toBeDefined();

    // Bloqueada esa IP, incluso la contraseña correcta se rechaza.
    const correct = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: ip,
      payload: ADMIN,
    });
    expect(correct.statusCode).toBe(429);
  });

  it('POST /auth/login limita los fallos por cuenta desde cualquier IP (sin distinguir mayúsculas)', async () => {
    const email = `spray-${randomBytes(4).toString('hex')}@infraward.test`;
    const attempt = (address: string, as = email) =>
      app.inject({
        method: 'POST',
        url: '/auth/login',
        remoteAddress: address,
        payload: { email: as, password: 'password-spray' },
      });
    // Una IP distinta cada vez: el límite por IP nunca salta.
    for (let i = 0; i < LOGIN_ACCOUNT_THROTTLE_LIMIT; i++)
      expect((await attempt(uniqueIp())).statusCode).toBe(401);
    const blocked = await attempt(uniqueIp(), email.toUpperCase());
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers['retry-after']).toBeDefined();
    // Las demás cuentas, no.
    expect((await attempt(uniqueIp(), `other-${email}`)).statusCode).toBe(401);
  });

  it('POST /auth/login: el bloqueo por cuenta no deja fuera al dueño desde donde ya entró', async () => {
    const login = (address: string, password: string) =>
      app.inject({
        method: 'POST',
        url: '/auth/login',
        remoteAddress: address,
        payload: { email: ADMIN.email, password },
      });
    const known = uniqueIp();
    expect((await login(known, ADMIN.password)).statusCode).toBe(200);
    // Alguien inunda la cuenta desde muchas IP: queda bloqueada para las IP nuevas...
    for (let i = 0; i < LOGIN_ACCOUNT_THROTTLE_LIMIT; i++)
      expect((await login(uniqueIp(), 'password-spray')).statusCode).toBe(401);
    expect((await login(uniqueIp(), ADMIN.password)).statusCode).toBe(429);
    // ...pero el dueño entra desde su red de siempre, y eso pone el contador a cero.
    expect((await login(known, ADMIN.password)).statusCode).toBe(200);
    expect((await login(uniqueIp(), ADMIN.password)).statusCode).toBe(200);
  });

  it('no escribe ADMIN_PASSWORD en los logs', () => {
    const logs = output.join('');
    expect(logs).toContain('Administrador inicial creado');
    expect(logs).not.toContain(ADMIN.password);
  });

  it('cabeceras de seguridad en las respuestas JSON', async () => {
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.headers).toMatchObject({
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
      'x-frame-options': 'DENY',
    });
  });

  it('publica OpenAPI y la referencia de Scalar', async () => {
    const spec = await app.inject({ method: 'GET', url: '/openapi.json' });
    expect(spec.statusCode).toBe(200);
    expect(Object.keys(spec.json().paths)).toEqual(
      expect.arrayContaining(['/health', '/auth/login', '/auth/me']),
    );
    const docs = await app.inject({ method: 'GET', url: '/docs' });
    expect(docs.statusCode).toBe(200);
    expect(docs.headers['content-type']).toContain('text/html');
  });
});
