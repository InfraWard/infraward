import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import type {
  Asset,
  EnqueueJobResponse,
  EnrollServerResponse,
  JobStatus,
} from '@infraward/shared-types';
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
  email: 'viewer-collect@infraward.test',
  password: 'otra-contraseña-larga',
};

/** Puerto sin nada escuchando: la recolección falla al leer la host key. */
const CLOSED_PORT = 1;
const FP = `SHA256:${'c'.repeat(43)}`;

describe('Recolección (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let worker: TestWorker | undefined;
  let adminToken: string;
  let viewerToken: string;
  const output: string[] = [];
  const responses: string[] = [];
  let privateKey: string;
  /** Asset dado de alta (verificación simulada en la BD) en un puerto cerrado. */
  let asset: Asset;
  let pending: Asset;

  beforeAll(async () => {
    await prepareEnv('e2e_collect');
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

    const enroll = async (name: string) => {
      const res = await request('POST', '/assets/enroll', {
        host: '127.0.0.1',
        port: CLOSED_PORT,
        name,
      });
      expect(res.statusCode).toBe(201);
      return res.json<EnrollServerResponse>().asset;
    };
    asset = await enroll('e2e-collect');
    pending = await enroll('e2e-collect-pending');
    privateKey = await app
      .get(SecretsService)
      .resolve(asset.credentials.sshPrivateKey!);
    // Alta verificada sin servidor real: activo y con huella fijada.
    await db.query(
      `UPDATE assets SET status = 'active', host_key_fingerprint = $2 WHERE id = $1`,
      [asset.id, FP],
    );
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await stopWorker(worker);
    await app?.close();
  });

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

  async function finished(id: string): Promise<JobStatus> {
    let last: JobStatus | undefined;
    await waitFor(
      async () => {
        last = (await request('GET', `/jobs/${id}`)).json<JobStatus>();
        return last.state === 'completed' || last.state === 'failed';
      },
      30_000,
      () =>
        `recolección sin terminar: ${JSON.stringify(last)}\n${worker?.output.join('')}`,
    );
    return last!;
  }

  it('exige token, rol admin, UUID y asset existente', async () => {
    const url = `/assets/${asset.id}/collect`;
    expect((await request('POST', url, undefined, null)).statusCode).toBe(401);
    expect(
      (await request('POST', url, undefined, viewerToken)).statusCode,
    ).toBe(403);
    expect((await request('POST', '/assets/no-uuid/collect')).statusCode).toBe(
      400,
    );
    expect(
      (
        await request(
          'POST',
          '/assets/00000000-0000-4000-8000-000000000000/collect',
        )
      ).statusCode,
    ).toBe(404);
  });

  it('409 si el asset no está dado de alta', async () => {
    const res = await request('POST', `/assets/${pending.id}/collect`);
    expect(res.statusCode).toBe(409);
    expect(res.json<{ message: string }>().message).toMatch(
      /pending_enrollment/,
    );
  });

  it('encola en la cola discovery y deduplica por asset', async () => {
    // Sin worker todavía: el job se queda esperando.
    const first = await request('POST', `/assets/${asset.id}/collect`);
    expect(first.statusCode).toBe(202);
    const job = first.json<EnqueueJobResponse>();
    expect(job).toMatchObject({ name: 'asset.collect', queue: 'collect' });
    const second = await request('POST', `/assets/${asset.id}/collect`);
    expect(second.json<EnqueueJobResponse>().id).toBe(job.id);
    const status = (await request('GET', `/jobs/${job.id}`)).json<JobStatus>();
    expect(status).toMatchObject({ queue: 'collect', state: 'waiting' });

    // El worker la procesa: sin servidor, falla al leer la host key y el asset no cambia.
    worker = await startWorker({ SSH_CONNECT_TIMEOUT: '3' });
    const done = await finished(job.id);
    expect(done.state).toBe('failed');
    expect(done.failedReason).toMatch(
      /^No se pudo leer la host key de 127\.0\.0\.1:1/,
    );
    expect(done.events.at(-1)?.message).toMatch(/^Fallo: /);
    const after = (await request('GET', `/assets/${asset.id}`)).json<Asset>();
    expect(after).toMatchObject({
      status: 'active',
      hostKeyFingerprint: FP,
      facts: {},
      roles: [],
    });
    const snapshots = await request('GET', `/assets/${asset.id}/snapshots`);
    expect(snapshots.json<{ total: number }>().total).toBe(0);

    // Terminado el job, se puede volver a lanzar.
    const again = await request('POST', `/assets/${asset.id}/collect`);
    expect(again.json<EnqueueJobResponse>().id).not.toBe(job.id);
    await finished(again.json<EnqueueJobResponse>().id);
  });

  it('aparece en OpenAPI', async () => {
    const spec = (await app.inject({ url: '/openapi.json' })).json<{
      paths: Record<string, unknown>;
    }>();
    expect(spec.paths['/assets/{id}/collect']).toBeDefined();
  });

  it('la clave privada no aparece en respuestas ni logs (API y worker)', () => {
    expect(privateKey).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
    const body = privateKey.split('\n')[1];
    for (const text of [
      responses.join('\n'),
      output.join(''),
      worker?.output.join('') ?? '',
    ]) {
      expect(text).not.toContain(body);
    }
  });
});
