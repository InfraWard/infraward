import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { DataSource } from 'typeorm';
import { inject } from 'vitest';
import { base32Decode, hotp, totpStep } from '../../src/auth/mfa/totp.js';

export const ADMIN = {
  email: 'admin@infraward.test',
  password: 'una-contraseña-larga',
};

/** Clave maestra de los e2e (base64, 32 bytes). Se pasa por fichero, como en producción. */
export const MASTER_KEY = 'ZTJlLWNsYXZlLW1hZXN0cmEtZGUtMzItYnl0ZXMhISE=';

function masterKeyFile(): string {
  const file = join(
    mkdtempSync(join(tmpdir(), 'infraward-e2e-')),
    'master.key',
  );
  writeFileSync(file, `${MASTER_KEY}\n`, { mode: 0o600 });
  return file;
}

/** Clave de la caja fuerte de los e2e: distinta de la maestra (la API no arranca si es la misma). */
export const VAULT_KEY = 'ZTJlLWNsYXZlLWRlLWxhLWNhamEtZnVlcnRlLTMyYiE=';

/** Fichero con la clave de la caja fuerte (para `VAULT_LOCAL_MASTER_KEY_FILE`). */
export function vaultKeyFile(): string {
  const file = join(mkdtempSync(join(tmpdir(), 'infraward-e2e-')), 'vault.key');
  writeFileSync(file, `${VAULT_KEY}\n`, { mode: 0o600 });
  return file;
}

/** URL de conexión a Redis compartida por los e2e (ver global-setup.ts). */
export function redisUrl(): URL {
  return new URL(inject('redisUrl'));
}

/**
 * Índice de BD de Redis de los e2e: el de REDIS_URL (`redis://…/<n>`) o, si no lleva, el 1.
 * Nunca el 0 de desarrollo, para que un worker de `start:dev` no se lleve los jobs del test.
 */
export function redisDb(): string {
  return redisUrl().pathname.slice(1) || '1';
}

/**
 * Crea (o recrea vacía) la BD `<bd base>_<suffix>` en el servidor de los e2e y deja en
 * process.env la configuración de la API apuntando a ella y al Redis de los tests.
 */
export async function prepareEnv(
  suffix: string,
  extra: Record<string, string> = {},
): Promise<void> {
  const base = new URL(inject('databaseUrl'));
  const database = `${base.pathname.slice(1)}_${suffix}`;
  const admin = new DataSource({ type: 'postgres', url: base.toString() });
  await admin.initialize();
  await admin.query(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`);
  await admin.query(`CREATE DATABASE "${database}"`);
  await admin.destroy();

  const redis = redisUrl();
  Object.assign(process.env, {
    NODE_ENV: 'test',
    DATABASE_HOST: base.hostname,
    DATABASE_PORT: base.port || '5432',
    DATABASE_USER: decodeURIComponent(base.username),
    DATABASE_PASSWORD: decodeURIComponent(base.password),
    DATABASE_NAME: database,
    REDIS_HOST: redis.hostname,
    REDIS_PORT: redis.port || '6379',
    REDIS_DB: redisDb(),
    ADMIN_EMAIL: ADMIN.email,
    ADMIN_PASSWORD: ADMIN.password,
    SECRETS_PROVIDERS: 'local',
    SECRETS_LOCAL_MASTER_KEY_FILE: masterKeyFile(),
    // Vacía para que no la complete el .env de desarrollo (solo una de las dos).
    SECRETS_LOCAL_MASTER_KEY: '',
    PUBLIC_URL: 'http://infraward.test',
    // Sin OIDC y con login local salvo que el test lo pida (vacías: no las completa el .env).
    OIDC_ISSUER: '',
    OIDC_CLIENT_ID: '',
    OIDC_CLIENT_SECRET_REF: '',
    OIDC_REDIRECT_URI: '',
    OIDC_ROLE_MAPPING: '',
    OIDC_UNMAPPED: '',
    OIDC_ALLOW_UNVERIFIED_SIGNUP: '',
    OIDC_GROUPS_CLAIM: '',
    OIDC_PROVIDER_NAME: '',
    OIDC_SCOPES: '',
    OIDC_TOKEN_AUTH_METHOD: '',
    LOCAL_LOGIN: 'true',
    LOCAL_LOGIN_EMERGENCY_EMAIL: '',
    // Sin caja fuerte salvo que el test la pida (vacías: no las completa el .env de desarrollo).
    VAULT_PROVIDER: '',
    VAULT_LOCAL_MASTER_KEY: '',
    VAULT_LOCAL_MASTER_KEY_FILE: '',
    VAULT_OPENBAO_ROLE_ID: '',
    VAULT_OPENBAO_SECRET_ID: '',
    VAULT_OPENBAO_SECRET_ID_FILE: '',
    VAULT_OPENBAO_KV_PREFIX: '',
    // Contadores de los límites por proceso: los ficheros e2e comparten Redis y van seguidos, así
    // que los de Redis pasarían de un fichero al siguiente. api.e2e-spec prueba los de Redis.
    THROTTLE_STORAGE: 'memory',
    LOGIN_ACCOUNT_THROTTLE_LIMIT: '1000',
    ...extra,
  });
}

/** Crea la API con el entorno ya preparado (import dinámico: ConfigModule lee el entorno al cargar). */
export async function createTestApp(): Promise<NestFastifyApplication> {
  const { createApp } = await import('../../src/setup-app.js');
  const app = await createApp();
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
  return app;
}

export function login(
  app: NestFastifyApplication,
  email: string,
  password: string,
) {
  return app.inject({
    method: 'POST',
    url: '/auth/login',
    payload: { email, password },
  });
}

/** Cookie de sesión (con SESSION_COOKIE_SECURE por defecto). */
export const SESSION_COOKIE = '__Host-iw_session';

/**
 * Credencial de los e2e en un solo texto: el valor de la cookie de sesión y el token CSRF
 * (`<cookie> <csrf>`). `authHeaders` la convierte en cabeceras.
 */
export function sessionToken(res: {
  cookies: { name: string; value: string }[];
  json: <T>() => T;
}): string {
  const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE)?.value;
  const { csrfToken } = res.json<{ csrfToken: string }>();
  if (!cookie || !csrfToken)
    throw new Error('Login sin cookie o sin token CSRF');
  return `${cookie} ${csrfToken}`;
}

/**
 * Secretos TOTP de los usuarios de los e2e (por email) y el último paso usado: la API no acepta
 * dos veces el mismo paso, así que cada código se calcula para un paso posterior.
 */
const totpSecrets = new Map<string, { secret: string; lastStep: number }>();

/** Secreto TOTP que `loginToken` configuró para ese usuario (o undefined). */
export function totpSecretOf(email: string): string | undefined {
  return totpSecrets.get(email.toLowerCase())?.secret;
}

export function forgetTotp(email: string): void {
  totpSecrets.delete(email.toLowerCase());
}

/**
 * Código TOTP válido y no usado para ese usuario (si el paso siguiente aún no ha llegado, espera
 * a él: la API admite ±1 paso).
 */
export async function nextTotpCode(email: string): Promise<string> {
  const entry = totpSecrets.get(email.toLowerCase());
  if (!entry) throw new Error(`Sin TOTP conocido para ${email}`);
  for (;;) {
    const current = totpStep(Date.now());
    const step = Math.max(current - 1, entry.lastStep + 1);
    if (step <= current + 1) {
      entry.lastStep = step;
      return hotp(base32Decode(entry.secret), step);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

/** Configura el TOTP con la sesión dada (alta + confirmación) y recuerda el secreto. */
export async function enableTotp(
  app: NestFastifyApplication,
  email: string,
  token: string,
): Promise<string[]> {
  const setup = await app.inject({
    method: 'POST',
    url: '/auth/mfa/setup',
    headers: authHeaders(token),
  });
  if (setup.statusCode !== 200)
    throw new Error(`Alta de TOTP de ${email}: ${setup.statusCode} ${setup.body}`);
  const { secret } = setup.json<{ secret: string }>();
  totpSecrets.set(email.toLowerCase(), { secret, lastStep: -1 });
  const enable = await app.inject({
    method: 'POST',
    url: '/auth/mfa/enable',
    headers: authHeaders(token),
    payload: { code: await nextTotpCode(email) },
  });
  if (enable.statusCode !== 200)
    throw new Error(`Confirmar TOTP de ${email}: ${enable.statusCode} ${enable.body}`);
  return enable.json<{ recoveryCodes: string[] }>().recoveryCodes;
}

/**
 * Login completo de los e2e: con TOTP, segundo paso con el código; un admin local sin TOTP lo
 * configura antes (es obligatorio). Así la sesión que devuelve vale para todo y está recién
 * reautenticada (step-up).
 */
export async function loginToken(
  app: NestFastifyApplication,
  email: string,
  password: string,
): Promise<string> {
  const res = await login(app, email, password);
  if (res.statusCode !== 200)
    throw new Error(`Login de ${email} fallido: ${res.statusCode}`);
  const info = res.json<{ mfaPending: boolean; mfaSetupRequired: boolean }>();
  let token = sessionToken(res);
  if (info.mfaPending) {
    const verify = await app.inject({
      method: 'POST',
      url: '/auth/mfa/verify',
      headers: authHeaders(token),
      payload: { code: await nextTotpCode(email) },
    });
    if (verify.statusCode !== 200)
      throw new Error(`Código TOTP de ${email}: ${verify.statusCode} ${verify.body}`);
    token = sessionToken(verify);
  } else if (info.mfaSetupRequired) {
    await enableTotp(app, email, token);
  }
  return token;
}

/** Cabeceras de una petición autenticada: cookie de sesión y X-CSRF-Token. */
export function authHeaders(token: string): Record<string, string> {
  const [cookie, csrf] = token.split(' ');
  return { cookie: `${SESSION_COOKIE}=${cookie}`, 'x-csrf-token': csrf };
}
