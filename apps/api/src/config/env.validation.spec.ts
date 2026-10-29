import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  docsPublic,
  trustProxySetting,
  validateEnv,
  webOrigins,
} from './env.validation.js';

const valid = {
  DATABASE_USER: 'infraward',
  DATABASE_PASSWORD: 'secret',
  DATABASE_NAME: 'infraward',
  SECRETS_LOCAL_MASTER_KEY: 'A'.repeat(43) + '=',
  PUBLIC_URL: 'https://infraward.example.com',
};

describe('validateEnv', () => {

  it('REDIS_PASSWORD_FILE: la contraseña desde un fichero, excluyente con REDIS_PASSWORD y sin enseñar el valor', () => {
    const dir = mkdtempSync(join(tmpdir(), 'iw-redis-'));
    const file = join(dir, 'redis_password');
    writeFileSync(file, 'contraseña-de-redis\n');
    expect(validateEnv({ ...valid, REDIS_PASSWORD_FILE: file }).REDIS_PASSWORD).toBe(
      'contraseña-de-redis',
    );
    expect(() =>
      validateEnv({ ...valid, REDIS_PASSWORD_FILE: file, REDIS_PASSWORD: 'otra' }),
    ).toThrow(/REDIS_PASSWORD y REDIS_PASSWORD_FILE son excluyentes/);
    expect(() =>
      validateEnv({ ...valid, REDIS_PASSWORD_FILE: join(dir, 'no-existe') }),
    ).toThrow(/REDIS_PASSWORD_FILE: no se puede leer el fichero \(ENOENT\)/);
    writeFileSync(file, '\n');
    expect(() => validateEnv({ ...valid, REDIS_PASSWORD_FILE: file })).toThrow(
      /REDIS_PASSWORD_FILE está vacío/,
    );
    // Sin fichero, REDIS_PASSWORD como siempre.
    expect(validateEnv({ ...valid, REDIS_PASSWORD: 'p' }).REDIS_PASSWORD).toBe('p');
  });
  it('aplica valores por defecto y convierte números', () => {
    const env = validateEnv({ ...valid, DATABASE_PORT: '5433' });
    expect(env.DATABASE_PORT).toBe(5433);
    expect(env.PORT).toBe(3000);
    expect(env.SESSION_TTL).toBe(12 * 3600);
    expect(env.SESSION_IDLE_TTL).toBe(2 * 3600);
    expect(env.SESSION_COOKIE_SECURE).toBe(true);
    expect(env.TRUST_PROXY).toBe('false');
    expect(env.ENROLLMENT_TOKEN_TTL).toBe(1200);
  });

  it('PUBLIC_URL: obligatoria, http(s), sin query ni comillas', () => {
    expect(() => validateEnv({ ...valid, PUBLIC_URL: undefined })).toThrow(
      /PUBLIC_URL/,
    );
    for (const url of [
      'ftp://infraward.example.com',
      'infraward.example.com',
      'https://infraward.example.com/?a=1',
      "https://infraward.example.com/'x",
    ]) {
      expect(() => validateEnv({ ...valid, PUBLIC_URL: url })).toThrow(
        /PUBLIC_URL/,
      );
    }
    for (const url of [
      'http://localhost:3000',
      'https://infraward.example.com/api',
      'http://10.0.0.5:3000/',
    ]) {
      expect(validateEnv({ ...valid, PUBLIC_URL: url }).PUBLIC_URL).toBe(url);
    }
  });

  it('PUBLIC_URL: https en producción, salvo loopback', () => {
    const prod = { ...valid, NODE_ENV: 'production' };
    for (const url of [
      'http://infraward.example.com',
      'http://10.0.0.5:3000',
      'http://127.example.com',
    ]) {
      expect(() => validateEnv({ ...prod, PUBLIC_URL: url })).toThrow(
        /PUBLIC_URL tiene que ser https/,
      );
    }
    for (const url of [
      'https://infraward.example.com',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
      'http://[::1]:3000',
    ]) {
      expect(validateEnv({ ...prod, PUBLIC_URL: url }).PUBLIC_URL).toBe(url);
    }
    expect(
      validateEnv({ ...valid, PUBLIC_URL: 'http://10.0.0.5:3000' }).PUBLIC_URL,
    ).toBe('http://10.0.0.5:3000');
  });

  it('DOCS_PUBLIC: true o false (nada más); sin definir, la documentación se apaga en producción', () => {
    expect(validateEnv(valid).DOCS_PUBLIC).toBeUndefined();
    expect(validateEnv({ ...valid, DOCS_PUBLIC: 'true' }).DOCS_PUBLIC).toBe(
      true,
    );
    expect(validateEnv({ ...valid, DOCS_PUBLIC: 'false' }).DOCS_PUBLIC).toBe(
      false,
    );
    expect(validateEnv({ ...valid, DOCS_PUBLIC: ' TRUE ' }).DOCS_PUBLIC).toBe(
      true,
    );
    // Lo que docsPublic no entiende tampoco pasa la validación (antes «yes» valía como false).
    for (const value of ['yes', '1', 'on'])
      expect(() => validateEnv({ ...valid, DOCS_PUBLIC: value })).toThrow(
        /DOCS_PUBLIC/,
      );
    expect(docsPublic({})).toBe(true);
    expect(docsPublic({ NODE_ENV: 'development' })).toBe(true);
    expect(docsPublic({ NODE_ENV: 'production' })).toBe(false);
    expect(docsPublic({ NODE_ENV: 'production', DOCS_PUBLIC: 'TRUE' })).toBe(
      true,
    );
    expect(docsPublic({ NODE_ENV: 'test', DOCS_PUBLIC: 'false' })).toBe(false);
  });

  it('ENROLLMENT_TOKEN_TTL entre 15 y 30 minutos', () => {
    expect(() =>
      validateEnv({ ...valid, ENROLLMENT_TOKEN_TTL: '600' }),
    ).toThrow(/ENROLLMENT_TOKEN_TTL/);
    expect(() =>
      validateEnv({ ...valid, ENROLLMENT_TOKEN_TTL: '3600' }),
    ).toThrow(/ENROLLMENT_TOKEN_TTL/);
  });

  it('SESSION_COOKIE_SECURE: «false» de verdad, y nunca en producción', () => {
    expect(
      validateEnv({ ...valid, SESSION_COOKIE_SECURE: 'false' })
        .SESSION_COOKIE_SECURE,
    ).toBe(false);
    expect(
      validateEnv({ ...valid, SESSION_COOKIE_SECURE: 'TRUE' })
        .SESSION_COOKIE_SECURE,
    ).toBe(true);
    expect(() =>
      validateEnv({
        ...valid,
        NODE_ENV: 'production',
        SESSION_COOKIE_SECURE: 'false',
      }),
    ).toThrow(/producción/);
  });

  it('TRUST_PROXY y el origen de la web', () => {
    expect(trustProxySetting('false')).toBe(false);
    expect(trustProxySetting('true')).toBe(true);
    expect(trustProxySetting('loopback, 10.0.0.0/8')).toEqual([
      'loopback',
      '10.0.0.0/8',
    ]);
    expect(
      webOrigins({
        PUBLIC_URL: 'https://infraward.example.com/api',
        NODE_ENV: 'production',
      }),
    ).toEqual(['https://infraward.example.com']);
    expect(
      webOrigins({
        PUBLIC_URL: 'http://localhost:3000',
        NODE_ENV: 'development',
      }),
    ).toEqual(['http://localhost:3000', 'http://localhost:4200']);
    expect(
      webOrigins({
        PUBLIC_URL: 'http://10.0.0.5:3000',
        WEB_ORIGIN: 'http://localhost:4300,https://web.example.com',
        NODE_ENV: 'development',
      }),
    ).toEqual(['http://localhost:4300', 'https://web.example.com']);
    expect(() =>
      validateEnv({ ...valid, WEB_ORIGIN: 'javascript:alert(1)' }),
    ).toThrow(/WEB_ORIGIN/);
  });

  it('exige ADMIN_EMAIL y ADMIN_PASSWORD juntas', () => {
    expect(() =>
      validateEnv({ ...valid, ADMIN_EMAIL: 'admin@example.com' }),
    ).toThrow(/van juntas/);
  });
});

describe('validateEnv (secretos)', () => {
  const key = 'A'.repeat(43) + '=';

  it('local por defecto, con la clave obligatoria', () => {
    const env = validateEnv(valid);
    expect(env.SECRETS_PROVIDERS).toBe('local');
    expect(env.SECRETS_CACHE_TTL).toBe(60);
    expect(() =>
      validateEnv({ ...valid, SECRETS_LOCAL_MASTER_KEY: undefined }),
    ).toThrow(
      /exactamente una de SECRETS_LOCAL_MASTER_KEY o SECRETS_LOCAL_MASTER_KEY_FILE \(falta\)/,
    );
  });

  it('rechaza la clave y el fichero a la vez, sin mostrar el valor', () => {
    const run = () =>
      validateEnv({
        ...valid,
        SECRETS_LOCAL_MASTER_KEY: key,
        SECRETS_LOCAL_MASTER_KEY_FILE: '/run/secrets/master.key',
      });
    expect(run).toThrow(/están las dos/);
    expect(run).toThrow(/^(?![\s\S]*AAAAAAAA)/);
  });

  it('rechaza proveedores desconocidos o mal escritos', () => {
    expect(() =>
      validateEnv({
        ...valid,
        SECRETS_PROVIDERS: 'local,vaultwarden',
        SECRETS_LOCAL_MASTER_KEY: key,
      }),
    ).toThrow(/desconocidos \(vaultwarden\); disponibles: local, openbao/);
    expect(() =>
      validateEnv({ ...valid, SECRETS_PROVIDERS: 'local, x' }),
    ).toThrow(/SECRETS_PROVIDERS: matches/);
  });

  it('con openbao exige su configuración, sin mostrar el secret_id', () => {
    const bao = {
      ...valid,
      SECRETS_PROVIDERS: 'openbao,local',
      SECRETS_LOCAL_MASTER_KEY: key,
    };
    expect(() => validateEnv(bao)).toThrow(/falta OPENBAO_ADDR/);
    const run = () =>
      validateEnv({
        ...bao,
        OPENBAO_ADDR: 'http://127.0.0.1:8200',
        OPENBAO_ROLE_ID: 'r',
        OPENBAO_SECRET_ID: 'sid-que-no-debe-salir',
        OPENBAO_SECRET_ID_FILE: '/run/secrets/bao',
      });
    expect(run).toThrow(/solo una de OPENBAO_SECRET_ID/);
    expect(run).toThrow(/^(?![\s\S]*sid-que-no-debe-salir)/);
    const env = validateEnv({
      ...bao,
      OPENBAO_ADDR: 'http://127.0.0.1:8200',
      OPENBAO_ROLE_ID: 'r',
      OPENBAO_SECRET_ID: 's',
      OPENBAO_TIMEOUT_MS: '2000',
    });
    expect(env.OPENBAO_TIMEOUT_MS).toBe(2000);
  });

  it('limita la caché a 300 s', () => {
    expect(() =>
      validateEnv({
        ...valid,
        SECRETS_LOCAL_MASTER_KEY: key,
        SECRETS_CACHE_TTL: '301',
      }),
    ).toThrow(/SECRETS_CACHE_TTL: max/);
  });
});

describe('validateEnv · OIDC y login local (QoL-2)', () => {
  const oidc = {
    OIDC_ISSUER: 'https://idp.example.com/realms/infraward',
    OIDC_CLIENT_ID: 'infraward',
    OIDC_REDIRECT_URI: 'https://infraward.example.com/api/auth/oidc/callback',
  };

  it('sin OIDC_ISSUER no hay OIDC y el login local está activo', () => {
    const env = validateEnv(valid);
    expect(env.OIDC_ISSUER).toBeUndefined();
    expect(env.LOCAL_LOGIN).toBe(true);
    expect(env.OIDC_UNMAPPED).toBe('deny');
    expect(env.OIDC_ALLOW_UNVERIFIED_SIGNUP).toBe(false);
    expect(env.OIDC_GROUPS_CLAIM).toBe('groups');
  });

  it('las variables OIDC vacías cuentan como no definidas', () => {
    expect(
      validateEnv({
        ...valid,
        OIDC_ISSUER: '',
        LOCAL_LOGIN_EMERGENCY_EMAIL: '',
      }).OIDC_ISSUER,
    ).toBeUndefined();
  });

  it('con OIDC_ISSUER exige el client id y la URL de retorno', () => {
    expect(validateEnv({ ...valid, ...oidc }).OIDC_CLIENT_ID).toBe('infraward');
    expect(() =>
      validateEnv({ ...valid, ...oidc, OIDC_CLIENT_ID: undefined }),
    ).toThrow(/OIDC_CLIENT_ID/);
    expect(() =>
      validateEnv({ ...valid, ...oidc, OIDC_REDIRECT_URI: undefined }),
    ).toThrow(/OIDC_REDIRECT_URI/);
  });

  it('en producción, issuer y retorno https', () => {
    expect(() =>
      validateEnv({
        ...valid,
        ...oidc,
        NODE_ENV: 'production',
        OIDC_ISSUER: 'http://idp.example.com/realms/infraward',
      }),
    ).toThrow(/OIDC_ISSUER tiene que ser https/);
    expect(() =>
      validateEnv({
        ...valid,
        ...oidc,
        OIDC_ISSUER: 'http://localhost:8081/realms/x',
      }),
    ).not.toThrow();
  });

  it('el secreto del cliente es una referencia secret:// con #campo, nunca el valor', () => {
    expect(() =>
      validateEnv({
        ...valid,
        ...oidc,
        OIDC_CLIENT_SECRET_REF: 'secret://local/oidc/kc#client_secret',
      }),
    ).not.toThrow();
    for (const ref of ['s3cr3t-en-claro', 'secret://local/oidc/kc']) {
      let message = '';
      try {
        validateEnv({ ...valid, ...oidc, OIDC_CLIENT_SECRET_REF: ref });
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toMatch(/OIDC_CLIENT_SECRET_REF/);
      expect(message).not.toContain('s3cr3t');
    }
  });

  it('mapeo de roles y scopes válidos', () => {
    expect(() =>
      validateEnv({ ...valid, ...oidc, OIDC_ROLE_MAPPING: 'admins=root' }),
    ).toThrow(/OIDC_ROLE_MAPPING/);
    expect(() =>
      validateEnv({ ...valid, ...oidc, OIDC_SCOPES: 'email profile' }),
    ).toThrow(/openid/);
    expect(() =>
      validateEnv({ ...valid, ...oidc, OIDC_UNMAPPED: 'admin' }),
    ).toThrow(/OIDC_UNMAPPED/);
  });

  it('LOCAL_LOGIN=false exige OIDC', () => {
    expect(() => validateEnv({ ...valid, LOCAL_LOGIN: 'false' })).toThrow(
      /LOCAL_LOGIN/,
    );
    const env = validateEnv({
      ...valid,
      ...oidc,
      LOCAL_LOGIN: 'false',
      LOCAL_LOGIN_EMERGENCY_EMAIL: 'admin@example.com',
    });
    expect(env.LOCAL_LOGIN).toBe(false);
  });
});
