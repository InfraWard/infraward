import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gatewayOrigins, validateGatewayEnv } from './gateway.env.js';

const BASE = {
  DATABASE_USER: 'u',
  DATABASE_PASSWORD: 'p',
  DATABASE_NAME: 'd',
  GATEWAY_API_URL: 'http://api:3000',
  GATEWAY_API_SECRET_FILE: '/run/secrets/gateway',
};

describe('validateGatewayEnv', () => {

  it('REDIS_PASSWORD_FILE: la contraseña desde un fichero, excluyente con REDIS_PASSWORD y sin enseñar el valor', () => {
    const dir = mkdtempSync(join(tmpdir(), 'iw-redis-'));
    const file = join(dir, 'redis_password');
    writeFileSync(file, 'contraseña-de-redis\n');
    expect(validateGatewayEnv({ ...BASE, REDIS_PASSWORD_FILE: file }).REDIS_PASSWORD).toBe(
      'contraseña-de-redis',
    );
    expect(() =>
      validateGatewayEnv({ ...BASE, REDIS_PASSWORD_FILE: file, REDIS_PASSWORD: 'otra' }),
    ).toThrow(/REDIS_PASSWORD y REDIS_PASSWORD_FILE son excluyentes/);
    expect(() =>
      validateGatewayEnv({ ...BASE, REDIS_PASSWORD_FILE: join(dir, 'no-existe') }),
    ).toThrow(/REDIS_PASSWORD_FILE: no se puede leer el fichero \(ENOENT\)/);
    writeFileSync(file, '\n');
    expect(() => validateGatewayEnv({ ...BASE, REDIS_PASSWORD_FILE: file })).toThrow(
      /REDIS_PASSWORD_FILE está vacío/,
    );
    // Sin fichero, REDIS_PASSWORD como siempre.
    expect(validateGatewayEnv({ ...BASE, REDIS_PASSWORD: 'p' }).REDIS_PASSWORD).toBe('p');
  });
  it('valores por defecto: sin colas, con cupos y tiempos de la terminal', () => {
    const env = validateGatewayEnv(BASE);
    expect(env).toMatchObject({
      GATEWAY_PORT: 3010,
      GATEWAY_SHUTDOWN_GRACE: 60,
      HOST_MAX_TERMINAL_SESSIONS: 4,
      TERMINAL_MAX_SESSIONS_PER_USER: 3,
      TERMINAL_IDLE_TIMEOUT: 900,
      TERMINAL_MAX_DURATION: 28800,
      GATEWAY_TRUST_PROXY: false,
    });
  });

  it('se niega a arrancar con cualquier variable del gestor de secretos (sin enseñar su valor)', () => {
    for (const name of [
      'SECRETS_PROVIDERS',
      'SECRETS_LOCAL_MASTER_KEY_FILE',
      'OPENBAO_ADDR',
      'OPENBAO_SECRET_ID',
      'VAULT_PROVIDER',
      'TERMINAL_OPENBAO_ROLE_ID',
    ]) {
      const run = () => validateGatewayEnv({ ...BASE, [name]: 'valor-centinela' });
      expect(run, name).toThrow(new RegExp(`no accede al gestor de secretos: quita ${name}`));
      expect(run).not.toThrow(/valor-centinela/);
    }
    // Vacías cuentan como sin definir (los compose las dejan así a veces).
    expect(() => validateGatewayEnv({ ...BASE, OPENBAO_ADDR: '' })).not.toThrow();
  });

  it('exige la URL de la API y el fichero del secreto; los errores nombran la variable', () => {
    expect(() => validateGatewayEnv({ ...BASE, GATEWAY_API_URL: 'ftp://x' })).toThrow(
      /GATEWAY_API_URL/,
    );
    expect(() => validateGatewayEnv({ ...BASE, GATEWAY_API_SECRET_FILE: undefined })).toThrow(
      /GATEWAY_API_SECRET_FILE/,
    );
  });

  it('orígenes web del WebSocket', () => {
    expect(gatewayOrigins({ WEB_ORIGIN: 'https://infra.example/, http://localhost:4200' })).toEqual([
      'https://infra.example',
      'http://localhost:4200',
    ]);
    expect(gatewayOrigins({})).toEqual([]);
  });
});
