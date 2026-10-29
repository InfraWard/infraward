import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { SecretsService } from '@infraward/secrets';
import {
  createTestAppRole,
  rootRequest,
  startOpenBaoTestServer,
  type OpenBaoTestServer,
  type TestAppRole,
} from '@infraward/secrets/testing/openbao';
import type {
  AssetTreeSummaryNode,
  CheckSecretResponse,
  DashboardSummary,
  EnrollServerResponse,
  SecretProviderInfo,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';

const SENTINEL_BAO = `centinela-bao-${randomBytes(12).toString('hex')}`;
const SENTINEL_LOCAL = `centinela-local-${randomBytes(12).toString('hex')}`;

/**
 * Convivencia de proveedores (SECRETS_PROVIDERS=openbao,local) con un OpenBao real: la API
 * entra por AppRole, las altas nuevas van a OpenBao (primer proveedor con escritura) y las
 * referencias locales siguen resolviendo. Nada secreto sale en respuestas ni logs.
 */
describe('Secretos con OpenBao y local (e2e)', () => {
  let server: OpenBaoTestServer;
  let role: TestAppRole;
  let app: NestFastifyApplication;
  let adminToken: string;
  const output: string[] = [];
  const responses: string[] = [];

  async function request(
    method: 'GET' | 'POST' | 'DELETE',
    url: string,
    payload?: object,
  ) {
    const res = await app.inject({
      method,
      url,
      payload,
      headers: authHeaders(adminToken),
    });
    responses.push(JSON.stringify(res.headers), res.body);
    return res;
  }

  async function check(ref: string): Promise<CheckSecretResponse> {
    const res = await request('POST', '/secrets/check', { ref });
    expect(res.statusCode).toBe(200);
    return res.json<CheckSecretResponse>();
  }

  /** Lo que hay en OpenBao para una ruta de la app (con el token root del fixture). */
  async function inBao(path: string) {
    try {
      const res = await rootRequest(
        server,
        'GET',
        `${role.kvMount}/data/${role.kvPrefix}/${path}`,
      );
      return (res!.data as { data: Record<string, string> }).data;
    } catch {
      return null;
    }
  }

  beforeAll(async () => {
    server = await startOpenBaoTestServer();
    role = await createTestAppRole(server);
    const secretIdFile = join(
      mkdtempSync(join(tmpdir(), 'infraward-e2e-bao-')),
      'secret-id',
    );
    writeFileSync(secretIdFile, `${role.secretId}\n`, { mode: 0o600 });

    await prepareEnv('e2e_secrets_openbao', {
      SECRETS_PROVIDERS: 'openbao,local',
      OPENBAO_ADDR: server.addr,
      OPENBAO_ROLE_ID: role.roleId,
      OPENBAO_SECRET_ID_FILE: secretIdFile,
      // Vacía para que no la complete el .env de desarrollo (solo una de las dos).
      OPENBAO_SECRET_ID: '',
      OPENBAO_KV_MOUNT: role.kvMount,
      OPENBAO_APPROLE_MOUNT: role.approleMount,
      OPENBAO_KV_PREFIX: role.kvPrefix,
      OPENBAO_SSH_MOUNT: role.sshMount,
      OPENBAO_SSH_ROLE: role.sshRole,
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
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);

    const secrets = app.get(SecretsService);
    await secrets.store('secret://openbao/e2e/bao', {
      private_key: SENTINEL_BAO,
    });
    await secrets.store('secret://local/e2e/local', {
      private_key: SENTINEL_LOCAL,
    });
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await app?.close();
    await role?.cleanup();
    await server?.stop();
  });

  it('/secrets/providers: los dos sanos, con escritura y en el orden configurado', async () => {
    const res = await request('GET', '/secrets/providers');
    expect(res.statusCode).toBe(200);
    expect(res.json<SecretProviderInfo[]>()).toEqual([
      {
        id: 'openbao',
        healthy: true,
        capabilities: ['write', 'ssh_certificates'],
      },
      { id: 'local', healthy: true, capabilities: ['write'] },
    ]);
  });

  it('check resuelve referencias de los dos proveedores sin devolver el valor', async () => {
    expect(await check('secret://openbao/e2e/bao#private_key')).toEqual({
      ref: 'secret://openbao/e2e/bao#private_key',
      provider: 'openbao',
      resolves: true,
    });
    expect(await check('secret://local/e2e/local#private_key')).toMatchObject({
      provider: 'local',
      resolves: true,
    });
    expect(await check('secret://openbao/e2e/nada#x')).toMatchObject({
      resolves: false,
      error: 'not_found',
    });
    expect(await check('secret://openbao/e2e/bao#otro')).toMatchObject({
      resolves: false,
      error: 'field_not_found',
    });
  });

  it('el alta guarda la clave en OpenBao y la purga la borra', async () => {
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 1,
      name: 'e2e-openbao',
      authMode: 'static_key',
    });
    expect(res.statusCode).toBe(201);
    const { asset } = res.json<EnrollServerResponse>();
    const ref = asset.credentials.sshPrivateKey!;
    expect(ref).toBe(`secret://openbao/assets/${asset.id}/ssh#privateKey`);

    const stored = await inBao(`assets/${asset.id}/ssh`);
    expect(stored?.privateKey).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----/);
    expect((await check(ref)).resolves).toBe(true);
    // La clave privada nunca sale de la API.
    expect(responses.join('\n')).not.toContain(stored!.privateKey);

    const purge = await request('DELETE', `/assets/${asset.id}?purge=true`);
    expect(purge.statusCode).toBeLessThan(300);
    expect(await inBao(`assets/${asset.id}/ssh`)).toBeNull();
  });

  it('con CA SSH, el alta es en modo CA por defecto y el panel avisa de la CA desactualizada', async () => {
    const res = await request('POST', '/assets/enroll', {
      host: '127.0.0.1',
      port: 1,
      name: 'e2e-ca',
    });
    expect(res.statusCode).toBe(201);
    const { asset, enrollment } = res.json<EnrollServerResponse>();
    expect(asset.sshAuth).toBe('ca_certificate');
    expect(asset.credentials).toEqual({});
    expect(enrollment.authMode).toBe('ca_certificate');
    expect(enrollment.publicKey).toBeNull();
    expect(enrollment.manualCommand).toBeNull();

    const [current] = await app
      .get(SecretsService)
      .sshCertificates()!
      .sshCaPublicKeys();
    const setTrusted = (trusted: string[]) =>
      app.get(DataSource).query(
        `UPDATE assets SET status = 'active',
                facts = jsonb_build_object('infraward', jsonb_build_object('sshCa', $2::jsonb))
          WHERE id = $1`,
        [asset.id, JSON.stringify({ version: 1, trusted })],
      );
    const outdated = async () => {
      const dashboard = await request('GET', '/dashboard');
      expect(dashboard.statusCode).toBe(200);
      const tree = (await request('GET', '/assets/tree')).json<
        AssetTreeSummaryNode[]
      >();
      return [
        dashboard.json<DashboardSummary>().attention.sshCaOutdated.count,
        tree.find((n) => n.id === asset.id)?.sshCaOutdated,
      ];
    };
    // Confía en otra CA (p. ej. la retirada): desactualizado en el panel y en el árbol.
    await setTrusted([`SHA256:${'x'.repeat(43)}`]);
    expect(await outdated()).toEqual([1, true]);
    // Exactamente la vigente: al día.
    await setTrusted([current.fingerprint]);
    expect(await outdated()).toEqual([0, false]);

    await request('DELETE', `/assets/${asset.id}?purge=true`);
  });

  it('ni respuestas ni logs contienen valores, el token de la app ni el secret_id', async () => {
    const all = `${responses.join('\n')}\n${output.join('\n')}`;
    expect(responses.length).toBeGreaterThan(0);
    for (const secret of [
      SENTINEL_BAO,
      SENTINEL_LOCAL,
      role.secretId,
      'PRIVATE KEY',
    ]) {
      expect(all).not.toContain(secret);
    }
    // Ningún token de servicio de OpenBao (prefijo s. / hvs.) en lo que sale de la API.
    expect(all).not.toMatch(/\b(?:hvs|s)\.[A-Za-z0-9]{20,}/);
  });
});
