import { randomBytes } from 'node:crypto';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { masterKeyId, SecretsService } from '@infraward/secrets';
import type {
  CheckSecretResponse,
  SecretProviderInfo,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  MASTER_KEY,
  prepareEnv,
} from './support/app.js';

const CHECK_LIMIT = 40;

const ADMIN_2 = {
  email: 'admin2-secrets@infraward.test',
  password: 'contraseña-del-segundo-admin',
};

const VIEWER = {
  email: 'viewer-secrets@infraward.test',
  password: 'otra-contraseña-larga',
};

/** Valores centinela: no pueden aparecer en ninguna respuesta, log ni fila de la BD. */
const SENTINEL_A = `centinela-A-${randomBytes(12).toString('hex')}`;
const SENTINEL_B = `centinela-B-${randomBytes(12).toString('hex')}`;
const REF_A = 'secret://local/e2e/server-a/ssh';
const REF_B = 'secret://local/e2e/server-b/ssh';

describe('Secretos (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let adminToken: string;
  let viewerToken: string;
  const output: string[] = [];
  const responses: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_secrets', {
      SECRETS_CHECK_THROTTLE_LIMIT: String(CHECK_LIMIT),
    });
    // Todo lo que escribe la API desde el arranque (Nest, TypeORM…).
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
    await app.get(UsersService).create(VIEWER.email, VIEWER.password);
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
    viewerToken = await loginToken(app, VIEWER.email, VIEWER.password);

    // La API aún no escribe secretos por HTTP (llegará con el enrolamiento): por el servicio.
    const secrets = app.get(SecretsService);
    await secrets.store(REF_A, {
      private_key: SENTINEL_A,
      public_key: 'ssh-ed25519 AAAA-a',
    });
    await secrets.store(REF_B, {
      private_key: SENTINEL_B,
      public_key: 'ssh-ed25519 AAAA-b',
    });
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await app?.close();
  });

  /** Petición (admin por defecto) que guarda el cuerpo de la respuesta para revisarlo al final. */
  async function request(
    method: 'GET' | 'POST',
    url: string,
    payload?: object,
    token: string | null = adminToken,
  ) {
    const res = await app.inject({
      method,
      url,
      payload,
      headers: token ? authHeaders(token) : {},
    });
    responses.push(JSON.stringify(res.headers), res.body);
    return res;
  }

  const check = (ref: string) => request('POST', '/secrets/check', { ref });

  it('GET /secrets/providers lista el proveedor local sano y con escritura', async () => {
    const res = await request('GET', '/secrets/providers');
    expect(res.statusCode).toBe(200);
    expect(res.json<SecretProviderInfo[]>()).toEqual([
      { id: 'local', healthy: true, capabilities: ['write'] },
    ]);
  });

  it('POST /secrets/check dice si resuelve, sin devolver el valor', async () => {
    const res = await check(`${REF_A}#private_key`);
    expect(res.statusCode).toBe(200);
    expect(res.json<CheckSecretResponse>()).toEqual({
      ref: `${REF_A}#private_key`,
      provider: 'local',
      resolves: true,
    });
  });

  it.each([
    [`${REF_A}#otro`, 'field_not_found'],
    [REF_A, 'field_not_found'],
    ['secret://local/e2e/no-existe#private_key', 'not_found'],
    ['secret://openbao/infra/pve1#private_key', 'provider_not_configured'],
    ['secret://vaultwarden/item#token', 'provider_not_configured'],
  ])('%s no resuelve: %s', async (ref, error) => {
    const res = await check(ref);
    expect(res.statusCode).toBe(200);
    expect(res.json<CheckSecretResponse>()).toMatchObject({
      ref,
      resolves: false,
      error,
    });
  });

  it.each([
    { ref: 'local/e2e/server-a/ssh' },
    { ref: 'secret://local/../etc/passwd' },
    { ref: 42 },
    {},
    { ref: `${REF_A}#private_key`, extra: true },
    { ref: `secret://local/${'a'.repeat(2000)}` },
  ])('valida el cuerpo: %j ⇒ 400', async (payload) => {
    const res = await request('POST', '/secrets/check', payload);
    expect(res.statusCode).toBe(400);
  });

  it('un viewer recibe 403 y sin token 401', async () => {
    for (const token of [viewerToken, null]) {
      const expected = token ? 403 : 401;
      expect(
        (await request('GET', '/secrets/providers', undefined, token))
          .statusCode,
      ).toBe(expected);
      expect(
        (
          await request(
            'POST',
            '/secrets/check',
            { ref: `${REF_A}#private_key` },
            token,
          )
        ).statusCode,
      ).toBe(expected);
    }
  });

  it('la BD solo guarda texto cifrado con el id de la clave maestra', async () => {
    const rows: {
      path: string;
      key_id: string;
      iv: Buffer;
      ciphertext: Buffer;
      auth_tag: Buffer;
    }[] = await db.query(
      `SELECT path, key_id, iv, ciphertext, auth_tag FROM local_secrets ORDER BY path`,
    );
    // Además de los del test, el secreto TOTP del admin (obligatorio), también cifrado.
    expect(rows.map((r) => r.path)).toEqual([
      'e2e/server-a/ssh',
      'e2e/server-b/ssh',
      expect.stringMatching(/^infraward\/users\/[0-9a-f-]{36}\/totp\/[0-9a-f-]{36}$/),
    ]);
    const expectedKeyId = masterKeyId(Buffer.from(MASTER_KEY, 'base64'));
    for (const row of rows) {
      expect(row.key_id).toBe(expectedKeyId);
      expect(row.iv).toHaveLength(12);
      expect(row.auth_tag).toHaveLength(16);
      const raw = row.ciphertext.toString('latin1');
      expect(raw).not.toContain('centinela');
      expect(raw).not.toContain('ssh-ed25519');
    }
    // Ningún volcado textual de la tabla contiene los valores.
    const [{ dump }]: { dump: string }[] = await db.query(
      `SELECT string_agg(t::text, '|') AS dump FROM local_secrets t`,
    );
    expect(dump).not.toContain(SENTINEL_A);
    expect(dump).not.toContain(SENTINEL_B);
  });

  it('si se intercambian las filas de dos servidores, falla en lugar de devolver la clave del otro', async () => {
    await db.query(`
      UPDATE local_secrets a
         SET iv = b.iv, ciphertext = b.ciphertext, auth_tag = b.auth_tag
        FROM local_secrets b
       WHERE a.path <> b.path
    `);
    for (const ref of [REF_A, REF_B]) {
      expect(
        (await check(`${ref}#private_key`)).json<CheckSecretResponse>(),
      ).toMatchObject({ resolves: false, error: 'decryption_failed' });
    }
    // Restaurar escribiendo de nuevo (sin pasar por la caché).
    const secrets = app.get(SecretsService);
    await secrets.store(REF_A, { private_key: SENTINEL_A });
    await secrets.store(REF_B, { private_key: SENTINEL_B });
    expect(
      (await check(`${REF_A}#private_key`)).json<CheckSecretResponse>()
        .resolves,
    ).toBe(true);
  });

  it('con otra clave maestra informa de key_mismatch', async () => {
    await db.query(
      `UPDATE local_secrets SET key_id = '0123456789abcdef' WHERE path = 'e2e/server-b/ssh'`,
    );
    expect(
      (await check(`${REF_B}#private_key`)).json<CheckSecretResponse>(),
    ).toMatchObject({ resolves: false, error: 'key_mismatch' });
  });

  it('borrar invalida la caché: lo leído antes deja de resolver al instante', async () => {
    const secrets = app.get(SecretsService);
    const ref = 'secret://local/e2e/baja/ssh';
    await secrets.store(ref, { private_key: SENTINEL_A });
    expect(await secrets.resolve(`${ref}#private_key`)).toBe(SENTINEL_A); // queda en caché
    expect(await secrets.remove(ref)).toBe(true);
    await expect(secrets.resolve(`${ref}#private_key`)).rejects.toMatchObject({
      code: 'not_found',
    });
    const rows: unknown[] = await db.query(
      `SELECT 1 FROM local_secrets WHERE path = 'e2e/baja/ssh'`,
    );
    expect(rows).toHaveLength(0);
  });

  it('POST /secrets/check tiene límite por usuario (429 con Retry-After)', async () => {
    await app.get(UsersService).create(ADMIN_2.email, ADMIN_2.password);
    await db.query(`UPDATE users SET role = 'admin' WHERE email = $1`, [
      ADMIN_2.email,
    ]);
    const token = await loginToken(app, ADMIN_2.email, ADMIN_2.password);
    const checkAs = (t: string) =>
      request('POST', '/secrets/check', { ref: 'secret://local/x/y#z' }, t);

    for (let i = 0; i < CHECK_LIMIT; i++) {
      expect((await checkAs(token)).statusCode).toBe(200);
    }
    const blocked = await checkAs(token);
    expect(blocked.statusCode).toBe(429);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    // El límite es del usuario: otro admin (misma IP) sigue pudiendo comprobar.
    expect((await checkAs(adminToken)).statusCode).toBe(200);
    // Y solo afecta a check.
    expect(
      (await request('GET', '/secrets/providers', undefined, token)).statusCode,
    ).toBe(200);
  });

  it('publica los endpoints en OpenAPI', async () => {
    const spec = await app.inject({ method: 'GET', url: '/openapi.json' });
    expect(Object.keys(spec.json().paths)).toEqual(
      expect.arrayContaining(['/secrets/providers', '/secrets/check']),
    );
  });

  it('ningún valor ni la clave maestra aparece en respuestas ni en logs', () => {
    const bodies = responses.join('\n');
    const logs = output.join('');
    expect(responses.length).toBeGreaterThan(20);
    for (const text of [bodies, logs]) {
      expect(text).not.toContain(SENTINEL_A);
      expect(text).not.toContain(SENTINEL_B);
      expect(text).not.toContain(MASTER_KEY);
      expect(text).not.toContain(
        Buffer.from(MASTER_KEY, 'base64').toString('hex'),
      );
    }
  });
});
