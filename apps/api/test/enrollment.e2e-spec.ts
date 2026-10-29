import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  Asset,
  DeleteAssetResponse,
  EnrollServerResponse,
  Enrollment,
  IssuedEnrollment,
} from '@infraward/shared-types';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import {
  startWorker,
  stopWorker,
  waitFor,
  type TestWorker,
} from './support/worker.js';

const VIEWER = {
  email: 'viewer-enroll@infraward.test',
  password: 'otra-contraseña-larga',
};

/** Puerto sin nada escuchando: la verificación del worker falla al leer la host key. */
const CLOSED_PORT = 1;

const FP = (c: string) => `SHA256:${c.repeat(43)}`;
const HOST_KEYS = [
  { type: 'ED25519', fingerprint: FP('a') },
  { type: 'RSA', fingerprint: FP('b') },
];

const COMMAND =
  /^curl -fsSL http:\/\/infraward\.test\/enroll\/([A-Za-z0-9_-]{43}) \| sudo bash$/;

function tokenOf(enrollment: IssuedEnrollment): string {
  const match = COMMAND.exec(enrollment.command);
  if (!match) throw new Error(`Comando inesperado: ${enrollment.command}`);
  return match[1];
}

describe('Enrolamiento (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker;
  let adminToken: string;
  let viewerToken: string;
  const output: string[] = [];
  const responses: string[] = [];
  /** Claves privadas y tokens: no pueden aparecer en logs, respuestas (salvo el comando) ni BD. */
  const privateKeys: string[] = [];
  const tokens: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_enrollment', { ENROLL_THROTTLE_LIMIT: '1000' });
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
    worker = await startWorker({ SSH_CONNECT_TIMEOUT: '5' });
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await stopWorker(worker);
    await app?.close();
  });

  async function request(
    method: 'GET' | 'POST' | 'DELETE',
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

  /** Da de alta un servidor y guarda su clave privada para la comprobación de fugas. */
  async function enroll(name: string): Promise<EnrollServerResponse> {
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: CLOSED_PORT,
      name,
    });
    expect(res.statusCode).toBe(201);
    const body = res.json<EnrollServerResponse>();
    privateKeys.push(
      await app
        .get(SecretsService)
        .resolve(body.asset.credentials.sshPrivateKey!),
    );
    tokens.push(tokenOf(body.enrollment));
    return body;
  }

  async function latest(assetId: string): Promise<Enrollment> {
    const res = await request('GET', `/assets/${assetId}/enrollment`);
    expect(res.statusCode).toBe(200);
    return res.json<Enrollment>();
  }

  /** Espera a que el worker termine la verificación (verified o failed). */
  async function settled(assetId: string): Promise<Enrollment> {
    let last: Enrollment | undefined;
    await waitFor(
      async () => {
        last = await latest(assetId);
        return last.status === 'verified' || last.status === 'failed';
      },
      30_000,
      () =>
        `verificación sin terminar: ${JSON.stringify(last)}\n${worker.output.join('')}`,
    );
    return last!;
  }

  const done = (token: string, hostKeys: object[] = HOST_KEYS) =>
    request('POST', `/enroll/${token}/done`, { hostKeys }, null);

  describe('alta', () => {
    let server: EnrollServerResponse;
    let token: string;

    beforeAll(async () => {
      server = await enroll('e2e-srv');
      token = tokenOf(server.enrollment);
    });

    it('crea el asset pendiente con solo la referencia a la clave', () => {
      const { asset, enrollment } = server;
      expect(asset).toMatchObject({
        type: 'server',
        name: 'e2e-srv',
        status: 'pending_enrollment',
        connection: { host: '127.0.0.1', port: CLOSED_PORT, user: 'inventory' },
        credentials: {
          sshPrivateKey: `secret://local/assets/${asset.id}/ssh#privateKey`,
        },
        hostKeyFingerprint: null,
      });
      expect(enrollment).toMatchObject({
        assetId: asset.id,
        method: 'script',
        purpose: 'initial',
        status: 'pending',
        expired: false,
        sshUser: 'inventory',
      });
      expect(enrollment.publicKey).toMatch(
        new RegExp(`^ssh-ed25519 \\S+ inventory@infraward:${asset.id}$`),
      );
      expect(enrollment.manualCommand).toContain(enrollment.publicKey);
      const ttl = Date.parse(enrollment.expiresAt!) - Date.now();
      expect(ttl).toBeGreaterThan(1190_000);
      expect(ttl).toBeLessThanOrEqual(1200_000);
      expect(privateKeys[0]).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
    });

    it('en la BD solo queda el hash del token', async () => {
      const [row] = await db.query<{ token_hash: string }[]>(
        'SELECT token_hash FROM enrollments WHERE id = $1',
        [server.enrollment.id],
      );
      expect(row.token_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(row.token_hash).not.toContain(token);
    });

    it('rechaza hosts y puertos inválidos, y a los viewers', async () => {
      for (const payload of [
        { host: '-oProxyCommand=touch /tmp/x' },
        { host: 'a b' },
        { host: "x';id;'" },
        { host: '192.0.2.1', port: 70000 },
      ]) {
        expect(
          (await request('POST', '/assets/enroll', payload)).statusCode,
        ).toBe(400);
      }
      const res = await request(
        'POST',
        '/assets/enroll',
        { host: '192.0.2.1' },
        viewerToken,
      );
      expect(res.statusCode).toBe(403);
    });

    it('GET /enroll/<token> sirve el script (repetible mientras no se use)', async () => {
      for (let i = 0; i < 2; i++) {
        const res = await request('GET', `/enroll/${token}`, undefined, null);
        expect(res.statusCode).toBe(200);
        expect(res.headers['content-type']).toMatch(/^text\/x-shellscript/);
        expect(res.headers['cache-control']).toBe('no-store');
        expect(res.body).toContain(`'${server.enrollment.publicKey}'`);
        expect(res.body).toContain(`'http://infraward.test'`);
        expect(res.body).not.toContain('__INFRAWARD_');
        expect(res.body).not.toContain('PRIVATE KEY');
        execFileSync('bash', ['-n'], { input: res.body });
      }
    });

    it('token desconocido o mal formado → 404', async () => {
      for (const t of ['nope', randomBytes(32).toString('base64url')]) {
        expect(
          (await request('GET', `/enroll/${t}`, undefined, null)).statusCode,
        ).toBe(404);
        expect((await done(t)).statusCode).toBe(404);
      }
    });

    it('el viewer ve el estado, sin token ni comando, pero no puede regenerarlo', async () => {
      const res = await request(
        'GET',
        `/assets/${server.asset.id}/enrollment`,
        undefined,
        viewerToken,
      );
      expect(res.statusCode).toBe(200);
      expect(res.json()).not.toHaveProperty('command');
      expect(res.body).not.toContain(token);
      const issue = await request(
        'POST',
        `/assets/${server.asset.id}/enrollment/token`,
        undefined,
        viewerToken,
      );
      expect(issue.statusCode).toBe(403);
    });

    it('regenerar el token invalida el anterior', async () => {
      const res = await request(
        'POST',
        `/assets/${server.asset.id}/enrollment/token`,
      );
      expect(res.statusCode).toBe(201);
      const issued = res.json<IssuedEnrollment>();
      expect(issued.id).toBe(server.enrollment.id);
      expect(issued.publicKey).toBe(server.enrollment.publicKey);
      const fresh = tokenOf(issued);
      tokens.push(fresh);
      expect(fresh).not.toBe(token);
      expect(
        (await request('GET', `/enroll/${token}`, undefined, null)).statusCode,
      ).toBe(404);
      expect((await done(token)).statusCode).toBe(404);
      expect(
        (await request('GET', `/enroll/${fresh}`, undefined, null)).statusCode,
      ).toBe(200);
      token = fresh;
    });

    it('un token caducado no sirve', async () => {
      await db.query(
        `UPDATE enrollments SET expires_at = now() - interval '1 second' WHERE id = $1`,
        [server.enrollment.id],
      );
      expect((await latest(server.asset.id)).expired).toBe(true);
      expect(
        (await request('GET', `/enroll/${token}`, undefined, null)).statusCode,
      ).toBe(404);
      expect((await done(token)).statusCode).toBe(404);

      const issued = (
        await request('POST', `/assets/${server.asset.id}/enrollment/token`)
      ).json<IssuedEnrollment>();
      token = tokenOf(issued);
      tokens.push(token);
      expect(issued.expired).toBe(false);
    });

    it('valida las huellas que envía el script', async () => {
      for (const hostKeys of [
        [],
        [{ type: 'ED25519', fingerprint: 'SHA256:corta' }],
        [{ type: 'DSA', fingerprint: FP('a') }],
        Array.from({ length: 11 }, (_, i) => ({
          type: 'RSA',
          fingerprint: FP(String.fromCharCode(97 + i)),
        })),
      ]) {
        expect((await done(token, hostKeys)).statusCode).toBe(400);
      }
    });

    it('/done consume el token una sola vez, aunque lleguen dos a la vez', async () => {
      const results = await Promise.all([done(token), done(token)]);
      expect(results.map((r) => r.statusCode).sort()).toEqual([204, 404]);
      expect((await done(token)).statusCode).toBe(404);
      expect(
        (await request('GET', `/enroll/${token}`, undefined, null)).statusCode,
      ).toBe(404);
    });

    it('/done no activa el asset: encola la verificación, que falla sin SSH', async () => {
      const enrollment = await settled(server.asset.id);
      expect(enrollment).toMatchObject({
        status: 'failed',
        method: 'script',
        reportedHostKeys: HOST_KEYS,
      });
      expect(enrollment.jobId).toBeTruthy();
      expect(enrollment.confirmedAt).toBeTruthy();
      expect(enrollment.error).toMatch(
        /No se pudo leer la host key de 127\.0\.0\.1:1/,
      );
      const asset = (
        await request('GET', `/assets/${server.asset.id}`)
      ).json<Asset>();
      expect(asset.status).toBe('pending_enrollment');
      expect(asset.hostKeyFingerprint).toBeNull();
    });

    it('se puede reintentar la verificación fallida', async () => {
      const res = await request(
        'POST',
        `/assets/${server.asset.id}/enrollment/verify`,
      );
      expect(res.statusCode).toBe(202);
      // La respuesta se lee tras encolar: si el worker ya terminó (aquí falla al instante), trae
      // `failed`. El estado intermedio no está garantizado; el final, sí.
      expect(['confirmed', 'failed']).toContain(res.json<Enrollment>().status);
      expect((await settled(server.asset.id)).status).toBe('failed');
      // Solo se reintenta lo fallido.
      const again = await request(
        'POST',
        `/assets/${server.asset.id}/enrollment/token`,
      );
      expect(again.statusCode).toBe(201);
      tokens.push(tokenOf(again.json<IssuedEnrollment>()));
      expect(
        (await request('POST', `/assets/${server.asset.id}/enrollment/verify`))
          .statusCode,
      ).toBe(409);
    });

    it('alternativa manual: rechaza root y verifica con el usuario indicado (TOFU)', async () => {
      const url = `/assets/${server.asset.id}/enrollment/confirm`;
      for (const sshUser of ['root', 'Root', 'a b', '-x', '']) {
        expect((await request('POST', url, { sshUser })).statusCode).toBe(400);
      }
      expect(
        (await request('POST', url, { sshUser: 'deploy' }, viewerToken))
          .statusCode,
      ).toBe(403);
      const res = await request('POST', url, { sshUser: 'deploy' });
      expect(res.statusCode).toBe(202);
      expect(res.json<Enrollment>()).toMatchObject({
        method: 'manual',
        sshUser: 'deploy',
        reportedHostKeys: [],
      });
      // Como en el reintento: `failed` si el worker ya terminó al leer la respuesta.
      expect(['confirmed', 'failed']).toContain(res.json<Enrollment>().status);
      const asset = (
        await request('GET', `/assets/${server.asset.id}`)
      ).json<Asset>();
      expect(asset.connection?.user).toBe('deploy');
      expect((await settled(server.asset.id)).status).toBe('failed');
      // Sin alta pendiente no hay nada que confirmar.
      expect(
        (await request('POST', url, { sshUser: 'deploy' })).statusCode,
      ).toBe(409);
    });

    it('los enrolamientos se conservan como historial', async () => {
      const [{ count }] = await db.query<{ count: string }[]>(
        'SELECT count(*) FROM enrollments WHERE asset_id = $1',
        [server.asset.id],
      );
      expect(Number(count)).toBe(2);
    });

    it('DELETE retira, borra la clave del proveedor y devuelve el comando de baja', async () => {
      const res = await request('DELETE', `/assets/${server.asset.id}`);
      expect(res.statusCode).toBe(200);
      const body = res.json<DeleteAssetResponse>();
      expect(body.revocations).toEqual([
        {
          assetId: server.asset.id,
          secretRemoved: true,
          command: `sudo sed -i '/ inventory@infraward:${server.asset.id}$/d' ~deploy/.ssh/authorized_keys`,
        },
      ]);
      await expect(
        app
          .get(SecretsService)
          .resolve(server.asset.credentials.sshPrivateKey!),
      ).rejects.toThrow();
      const asset = (
        await request('GET', `/assets/${server.asset.id}`)
      ).json<Asset>();
      expect(asset).toMatchObject({ status: 'retired', credentials: {} });
      expect(
        (await request('POST', `/assets/${server.asset.id}/enrollment/token`))
          .statusCode,
      ).toBe(409);
    });
  });

  it('DELETE ?purge=true con un alta pendiente: revoca, cancela y borra el historial', async () => {
    const server = await enroll('e2e-purge');
    const token = tokenOf(server.enrollment);
    const res = await request(
      'DELETE',
      `/assets/${server.asset.id}?purge=true`,
    );
    expect(res.statusCode).toBe(200);
    const [revocation] = res.json<DeleteAssetResponse>().revocations;
    expect(revocation).toMatchObject({
      assetId: server.asset.id,
      secretRemoved: true,
    });
    // Comando del usuario dedicado: quita la línea y, si no quedan claves, el sudoers y el usuario.
    expect(revocation.command).toContain(
      `inventory@infraward:${server.asset.id}`,
    );
    expect(revocation.command).toContain('userdel -r inventory');
    execFileSync('bash', ['-n', '-c', revocation.command]);
    expect(
      (await request('GET', `/enroll/${token}`, undefined, null)).statusCode,
    ).toBe(404);
    const [{ count }] = await db.query<{ count: string }[]>(
      'SELECT count(*) FROM enrollments WHERE asset_id = $1',
      [server.asset.id],
    );
    expect(Number(count)).toBe(0);
  });

  it('ninguna clave privada ni token aparece en respuestas, logs ni en la BD', async () => {
    const dump = JSON.stringify([
      await db.query('SELECT * FROM assets'),
      await db.query('SELECT * FROM enrollments'),
    ]);
    const logs = output.join('') + worker.output.join('');
    // Los comandos devueltos al emitir el token sí lo llevan: es el único sitio.
    const nonCommandResponses = responses
      .join('\n')
      .replace(
        /curl -fsSL http:\/\/infraward\.test\/enroll\/[A-Za-z0-9_-]{43}/g,
        '',
      );
    expect(privateKeys.length).toBeGreaterThanOrEqual(2);
    for (const key of privateKeys) {
      const body = key.split('\n')[1];
      expect(body.length).toBeGreaterThan(40);
      for (const haystack of [responses.join('\n'), logs, dump]) {
        expect(haystack).not.toContain(body);
      }
    }
    expect(responses.join('\n') + logs + dump).not.toContain('PRIVATE KEY');
    for (const token of tokens) {
      expect(dump).not.toContain(token);
      expect(logs).not.toContain(token);
      // Solo en el comando y dentro del script servido (GET /enroll/<token>).
      expect(nonCommandResponses.split(token).length - 1).toBeLessThanOrEqual(
        2,
      );
    }
  });
});
