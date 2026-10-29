import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SecretError } from '../errors.js';
import { loadOpenBaoConfig } from '../openbao/openbao-config.js';
import {
  createTestAppRole,
  createTestVaultAppRole,
  rootRequest,
  startOpenBaoTestServer,
  type OpenBaoTestServer,
  type TestAppRole,
  type TestVaultAppRole,
} from '../openbao/openbao-test-server.js';
import { OpenBaoSecretProvider } from '../openbao/openbao.provider.js';
import { OpenBaoVaultStore } from './openbao-vault.store.js';
import { createVaultStore } from './vault-config.js';
import { vaultEntryPath } from './vault-store.js';

/**
 * Caja fuerte contra un OpenBao real: versiones de KV v2 con su AppRole y, sobre todo, que la
 * AppRole de la app (la que tiene también el worker) **no puede leerla de ninguna forma**.
 */
describe('OpenBaoVaultStore contra OpenBao', () => {
  let server: OpenBaoTestServer;
  let app: TestAppRole;
  let vault: TestVaultAppRole;
  let store: OpenBaoVaultStore;
  const closers: { close(): Promise<void> }[] = [];
  const SECRET = `root-centinela-${randomBytes(8).toString('hex')}`;
  const PATH = vaultEntryPath('7c1e2d3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f');

  beforeAll(async () => {
    server = await startOpenBaoTestServer();
    app = await createTestAppRole(server);
    vault = await createTestVaultAppRole(server, app);
    store = createVaultStore(
      {
        kind: 'openbao',
        maxVersions: 3,
        openbao: {
          addr: server.addr,
          roleId: vault.roleId,
          secretId: vault.secretId,
          kvMount: app.kvMount,
          approleMount: app.approleMount,
          kvPrefix: vault.kvPrefix,
        },
        appOpenbao: { roleId: app.roleId, kvPrefix: app.kvPrefix },
      },
      () => {
        throw new Error('sin BD');
      },
    ) as OpenBaoVaultStore;
    closers.push(store);
  });

  afterAll(async () => {
    await Promise.all(closers.map((c) => c.close()));
    await app?.cleanup();
    await server?.stop();
  });

  /** Proveedor de la app (la AppRole y la política del worker), apuntando a donde se quiera. */
  function appProvider(kvPrefix: string): OpenBaoSecretProvider {
    const p = new OpenBaoSecretProvider(
      loadOpenBaoConfig({
        addr: server.addr,
        roleId: app.roleId,
        secretId: app.secretId,
        kvMount: app.kvMount,
        approleMount: app.approleMount,
        kvPrefix,
      }),
    );
    closers.push(p);
    return p;
  }

  async function appToken(): Promise<string> {
    const res = await fetch(`${server.addr}/v1/auth/${app.approleMount}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role_id: app.roleId, secret_id: app.secretId }),
    });
    return ((await res.json()) as { auth: { client_token: string } }).auth.client_token;
  }

  it('guarda versiones, lee la actual o una anterior y poda con max_versions', async () => {
    expect(await store.put(PATH, `${SECRET}-1`)).toBe(1);
    expect(await store.put(PATH, `${SECRET}-2`)).toBe(2);
    expect(await store.get(PATH)).toEqual({ value: `${SECRET}-2`, version: 2 });
    expect(await store.get(PATH, 1)).toEqual({ value: `${SECRET}-1`, version: 1 });
    await store.put(PATH, `${SECRET}-3`);
    await store.put(PATH, `${SECRET}-4`);
    expect((await store.versions(PATH)).map((v) => v.version)).toEqual([4, 3, 2]);
    await expect(store.get(PATH, 1)).rejects.toMatchObject({ code: 'not_found' });

    // En OpenBao vive bajo el prefijo de la caja fuerte, con max_versions en su metadata.
    const meta = await rootRequest(
      server,
      'GET',
      `${app.kvMount}/metadata/${vault.kvPrefix}/${PATH}`,
    );
    expect((meta!.data as { max_versions: number }).max_versions).toBe(3);
  });

  it('la AppRole de la app (la del worker) no puede leerla: data, versiones, metadata ni listado', async () => {
    const provider = appProvider(vault.kvPrefix);
    const error = await provider.get(PATH, 'password').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SecretError);
    expect(error).toMatchObject({ code: 'provider_error' });
    expect((error as Error).message).toMatch(/permiso denegado/);
    expect((error as Error).message).not.toContain(SECRET);

    const token = await appToken();
    const base = `${server.addr}/v1/${app.kvMount}`;
    for (const [method, url] of [
      ['GET', `${base}/data/${vault.kvPrefix}/${PATH}`],
      ['GET', `${base}/data/${vault.kvPrefix}/${PATH}?version=1`],
      ['GET', `${base}/metadata/${vault.kvPrefix}/${PATH}`],
      ['LIST', `${base}/metadata/${vault.kvPrefix}/entries`],
      ['GET', `${base}/metadata/${vault.kvPrefix}?list=true`],
      ['POST', `${base}/data/${vault.kvPrefix}/${PATH}`],
      ['DELETE', `${base}/metadata/${vault.kvPrefix}/${PATH}`],
    ] as const) {
      const res = await fetch(url, {
        method,
        headers: { 'X-Vault-Token': token, 'Content-Type': 'application/json' },
        body: method === 'POST' ? JSON.stringify({ data: { password: 'x' } }) : undefined,
      });
      expect({ method, url, status: res.status }).toEqual({ method, url, status: 403 });
      expect(await res.text()).not.toContain(SECRET);
    }
    // Sigue intacta.
    expect((await store.get(PATH)).value).toBe(`${SECRET}-4`);
  });

  it('la AppRole de la caja fuerte no alcanza los secretos de la app', async () => {
    await appProvider(app.kvPrefix).set('assets/a/ssh', { private_key: 'clave-app' });
    const intruder = new OpenBaoSecretProvider(
      loadOpenBaoConfig({
        addr: server.addr,
        roleId: vault.roleId,
        secretId: vault.secretId,
        kvMount: app.kvMount,
        approleMount: app.approleMount,
        kvPrefix: app.kvPrefix,
      }),
    );
    closers.push(intruder);
    await expect(intruder.get('assets/a/ssh', 'private_key')).rejects.toMatchObject({
      code: 'provider_error',
    });
  });

  it('destroy borra todas las versiones', async () => {
    expect(await store.destroy(PATH)).toBe(true);
    expect(await store.destroy(PATH)).toBe(false);
    expect(await store.versions(PATH)).toEqual([]);
    await expect(store.get(PATH)).rejects.toMatchObject({ code: 'not_found' });
    expect(await store.healthCheck()).toBe(true);
  });
});
