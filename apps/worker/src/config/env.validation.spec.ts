import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { queueConcurrency, validateEnv } from './env.validation.js';

const BASE = {
  DATABASE_USER: 'infraward',
  DATABASE_PASSWORD: 'x',
  DATABASE_NAME: 'infraward',
  SECRETS_LOCAL_MASTER_KEY_FILE: '/run/secrets/master.key',
};

describe('validateEnv (worker)', () => {

  it('REDIS_PASSWORD_FILE: la contraseña desde un fichero, excluyente con REDIS_PASSWORD y sin enseñar el valor', () => {
    const dir = mkdtempSync(join(tmpdir(), 'iw-redis-'));
    const file = join(dir, 'redis_password');
    writeFileSync(file, 'contraseña-de-redis\n');
    expect(validateEnv({ ...BASE, REDIS_PASSWORD_FILE: file }).REDIS_PASSWORD).toBe(
      'contraseña-de-redis',
    );
    expect(() =>
      validateEnv({ ...BASE, REDIS_PASSWORD_FILE: file, REDIS_PASSWORD: 'otra' }),
    ).toThrow(/REDIS_PASSWORD y REDIS_PASSWORD_FILE son excluyentes/);
    expect(() =>
      validateEnv({ ...BASE, REDIS_PASSWORD_FILE: join(dir, 'no-existe') }),
    ).toThrow(/REDIS_PASSWORD_FILE: no se puede leer el fichero \(ENOENT\)/);
    writeFileSync(file, '\n');
    expect(() => validateEnv({ ...BASE, REDIS_PASSWORD_FILE: file })).toThrow(
      /REDIS_PASSWORD_FILE está vacío/,
    );
    // Sin fichero, REDIS_PASSWORD como siempre.
    expect(validateEnv({ ...BASE, REDIS_PASSWORD: 'p' }).REDIS_PASSWORD).toBe('p');
  });
  it('aplica valores por defecto y convierte tipos', () => {
    const env = validateEnv({ ...BASE, REDIS_PORT: '6380' });
    expect(env.REDIS_HOST).toBe('localhost');
    expect(env.REDIS_PORT).toBe(6380);
    expect(env.WORKER_CONCURRENCY).toBe(5);
    expect(env.SECRETS_PROVIDERS).toBe('local');
    expect(env.SSH_CONNECT_TIMEOUT).toBe(15);
  });

  it('exige la BD y exactamente una fuente de la clave maestra del proveedor local', () => {
    expect(() => validateEnv({ REDIS_PORT: '6380' })).toThrow(/DATABASE_USER/);
    const noKey: Record<string, string> = { ...BASE };
    delete noKey.SECRETS_LOCAL_MASTER_KEY_FILE;
    expect(() => validateEnv(noKey)).toThrow(/falta/);
    expect(() =>
      validateEnv({
        ...BASE,
        SECRETS_LOCAL_MASTER_KEY: 'clave-que-no-debe-salir',
      }),
    ).toThrow(/están las dos/);
    try {
      validateEnv({
        ...BASE,
        SECRETS_LOCAL_MASTER_KEY: 'clave-que-no-debe-salir',
      });
    } catch (e) {
      expect((e as Error).message).not.toContain('clave-que-no-debe-salir');
    }
    expect(() => validateEnv({ ...BASE, SECRETS_PROVIDERS: 'nope' })).toThrow(
      /desconocidos \(nope\)/,
    );
  });

  it('con openbao exige su configuración (la misma regla que en la API)', () => {
    const bao = { ...BASE, SECRETS_PROVIDERS: 'openbao,local' };
    expect(() => validateEnv(bao)).toThrow(/falta OPENBAO_ADDR/);
    expect(() =>
      validateEnv({
        ...bao,
        OPENBAO_ADDR: 'http://bao:8200',
        OPENBAO_ROLE_ID: 'r',
      }),
    ).toThrow(/falta OPENBAO_SECRET_ID_FILE o OPENBAO_SECRET_ID/);
    expect(
      validateEnv({
        ...bao,
        OPENBAO_ADDR: 'http://bao:8200',
        OPENBAO_ROLE_ID: 'r',
        OPENBAO_SECRET_ID: 's',
      }).SECRETS_PROVIDERS,
    ).toBe('openbao,local');
  });

  it('rechaza valores inválidos sin mostrarlos', () => {
    expect(() =>
      validateEnv({ REDIS_PORT: '99999', REDIS_PASSWORD: 12345 }),
    ).toThrow(/REDIS_PORT/);
    try {
      validateEnv({ REDIS_PORT: 'no-es-un-puerto-secreto' });
    } catch (e) {
      expect((e as Error).message).not.toContain('no-es-un-puerto-secreto');
    }
  });

  it('concurrencia por cola (0 = no la consume) y SCAN_CONCURRENCY como alias obsoleto', () => {
    const env = validateEnv({ ...BASE, COLLECT_CONCURRENCY: '0' });
    expect(queueConcurrency(env)).toEqual({
      system: 5,
      enrollment: 5,
      collect: 0,
      discovery: 2,
      domains: 2,
      reconcile: 1,
      'image-scan': 1,
      'host-scan': 1,
      sbom: 1,
      scan: 1,
    });
    expect(
      queueConcurrency(validateEnv({ ...BASE, SCAN_CONCURRENCY: '3' }))['image-scan'],
    ).toBe(3);
    expect(
      queueConcurrency(
        validateEnv({ ...BASE, SCAN_CONCURRENCY: '3', IMAGE_SCAN_CONCURRENCY: '2' }),
      )['image-scan'],
    ).toBe(2);
    // Un worker remoto solo de escaneos no drena la cola antigua si no escanea.
    const zero = {
      WORKER_CONCURRENCY: '0',
      COLLECT_CONCURRENCY: '0',
      DISCOVERY_CONCURRENCY: '0',
      DOMAINS_SYNC_CONCURRENCY: '0',
      RECONCILE_CONCURRENCY: '0',
      HOST_SCAN_CONCURRENCY: '0',
      SBOM_CONCURRENCY: '0',
    };
    expect(
      queueConcurrency(validateEnv({ ...BASE, ...zero, IMAGE_SCAN_CONCURRENCY: '0', COLLECT_CONCURRENCY: '1' })).scan,
    ).toBe(0);
    expect(() =>
      validateEnv({ ...BASE, ...zero, IMAGE_SCAN_CONCURRENCY: '0' }),
    ).toThrow(/todas las concurrencias son 0/);
  });

  it('límites por host, nombre de la réplica y líder', () => {
    expect(() =>
      validateEnv({ ...BASE, HOST_MAX_JOBS: '1', HOST_MAX_SCAN_JOBS: '2' }),
    ).toThrow(/HOST_MAX_SCAN_JOBS/);
    expect(() => validateEnv({ ...BASE, WORKER_NAME: 'mal nombre' })).toThrow(
      /WORKER_NAME/,
    );
    const env = validateEnv({ ...BASE, WORKER_LEADER_ELIGIBLE: 'false' });
    expect(env.WORKER_LEADER_ELIGIBLE).toBe(false);
    expect(validateEnv(BASE).WORKER_LEADER_ELIGIBLE).toBe(true);
    expect(env.WORKER_SHUTDOWN_GRACE).toBe(90);
  });
});
