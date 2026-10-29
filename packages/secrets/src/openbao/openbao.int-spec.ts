import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SecretError } from '../errors.js';
import { LocalSecretProvider } from '../local/local.provider.js';
import { loadMasterKey } from '../local/master-key.js';
import { SecretsService } from '../secrets.service.js';
import { MemoryLocalSecretStore } from '../testing.js';
import { loadOpenBaoConfig, type OpenBaoSource } from './openbao-config.js';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSshKeyPair, sshPublicKeyFingerprint } from '../ssh-keys.js';
import {
  addTestSshIssuer,
  createTestAppRole,
  lookupAccessor,
  rootRequest,
  startOpenBaoTestServer,
  type OpenBaoTestServer,
  type TestAppRole,
} from './openbao-test-server.js';
import { OpenBaoSecretProvider } from './openbao.provider.js';

/** Integración contra un OpenBao real: KV v2, AppRole, política, renovación y revocación. */
describe('OpenBaoSecretProvider contra OpenBao', () => {
  let server: OpenBaoTestServer;
  let role: TestAppRole;
  const providers: OpenBaoSecretProvider[] = [];
  const VALUE = `valor-${randomBytes(8).toString('hex')}`;

  function provider(
    r: TestAppRole = role,
    extra: OpenBaoSource = {},
  ): OpenBaoSecretProvider {
    const p = new OpenBaoSecretProvider(
      loadOpenBaoConfig({
        addr: server.addr,
        roleId: r.roleId,
        secretId: r.secretId,
        kvMount: r.kvMount,
        approleMount: r.approleMount,
        kvPrefix: r.kvPrefix,
        sshMount: r.sshMount,
        sshRole: r.sshRole,
        ...extra,
      }),
    );
    providers.push(p);
    return p;
  }

  beforeAll(async () => {
    server = await startOpenBaoTestServer();
    role = await createTestAppRole(server);
  });

  afterAll(async () => {
    await Promise.all(providers.map((p) => p.close()));
    await role?.cleanup();
    await server?.stop();
  });

  it('guarda, lee por campo y borra bajo el prefijo con la política mínima', async () => {
    const p = provider();
    await p.set('assets/a/ssh', { private_key: VALUE, public_key: 'pub' });

    // Lo que hay en OpenBao (leído con el token root del fixture).
    const raw = await rootRequest(
      server,
      'GET',
      `${role.kvMount}/data/infraward/assets/a/ssh`,
    );
    expect((raw!.data as { data: object }).data).toEqual({
      private_key: VALUE,
      public_key: 'pub',
    });

    expect(await p.get('assets/a/ssh', 'private_key')).toBe(VALUE);
    await expect(p.get('assets/a/ssh')).rejects.toMatchObject({
      code: 'field_not_found',
    });
    expect(await p.delete('assets/a/ssh')).toBe(true);
    expect(await p.delete('assets/a/ssh')).toBe(false);
    await expect(p.get('assets/a/ssh', 'private_key')).rejects.toMatchObject({
      code: 'not_found',
    });
    expect(await p.healthCheck()).toBe(true);
  });

  it('última versión borrada (soft delete) ⇒ not_found', async () => {
    const p = provider();
    await p.set('borrable', { x: '1' });
    await rootRequest(
      server,
      'DELETE',
      `${role.kvMount}/data/infraward/borrable`,
    );
    await expect(p.get('borrable', 'x')).rejects.toMatchObject({
      code: 'not_found',
    });
  });

  it('fuera del prefijo permitido la política lo deniega ⇒ provider_error', async () => {
    const p = provider(role, { kvPrefix: 'otro' });
    const error = await p.get('x', 'y').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SecretError);
    expect(error).toMatchObject({ code: 'provider_error' });
    expect((error as Error).message).toMatch(/permiso denegado/);
  });

  it('renueva el token antes de caducar y vuelve a entrar al llegar a token_max_ttl', async () => {
    const short = await createTestAppRole(server, {
      tokenTtl: '3s',
      tokenMaxTtl: '8s',
    });
    try {
      const p = provider(short);
      await p.set('renovable', { v: VALUE });
      const first = p.tokenAccessor!;
      const issued = await lookupAccessor(server, first);
      expect(issued?.ttl).toBeLessThanOrEqual(3);

      // A los ~2 s (2/3 de 3 s) se renueva: mismo token, con fecha de renovación.
      await sleep(2_600);
      expect(p.tokenAccessor).toBe(first);
      expect(
        (await lookupAccessor(server, first))?.last_renewal_time,
      ).toBeTruthy();

      // Cerca de los 8 s de max TTL la renovación ya no alarga: nuevo login.
      await sleep(5_500);
      expect(p.tokenAccessor).not.toBe(first);

      // Pasado el max TTL del primer token se sigue leyendo sin errores.
      await sleep(3_000);
      expect(await lookupAccessor(server, first)).toBeNull();
      expect(await p.get('renovable', 'v')).toBe(VALUE);
    } finally {
      await short.cleanup();
    }
  });

  it('se recupera si revocan el token desde fuera', async () => {
    const p = provider();
    await p.set('revocado', { v: VALUE });
    const before = p.tokenAccessor!;
    await rootRequest(server, 'POST', 'auth/token/revoke-accessor', {
      accessor: before,
    });
    expect(await p.get('revocado', 'v')).toBe(VALUE);
    expect(p.tokenAccessor).not.toBe(before);
  });

  it('secret_id inválido: salud false y login rechazado', async () => {
    const p = provider({ ...role, secretId: 'no-vale' });
    expect(await p.healthCheck()).toBe(false);
    await expect(p.get('x', 'y')).rejects.toThrow(/login AppRole rechazado/);
  });

  it('close revoca el token de la app', async () => {
    const p = provider();
    expect(await p.healthCheck()).toBe(true);
    const accessor = p.tokenAccessor!;
    expect(await lookupAccessor(server, accessor)).not.toBeNull();
    await p.close();
    expect(await lookupAccessor(server, accessor)).toBeNull();
  });

  it('convive con el proveedor local en SecretsService (openbao,local)', async () => {
    const local = new LocalSecretProvider(
      new MemoryLocalSecretStore(),
      loadMasterKey({ key: randomBytes(32).toString('base64') }),
    );
    const service = new SecretsService([provider(), local], 0);
    await service.store('secret://openbao/conv/a', { k: 'de-openbao' });
    await service.store('secret://local/conv/a', { k: 'de-local' });
    expect(await service.resolve('secret://openbao/conv/a#k')).toBe(
      'de-openbao',
    );
    expect(await service.resolve('secret://local/conv/a#k')).toBe('de-local');
    const info = await service.describeProviders();
    expect(info).toEqual([
      {
        id: 'openbao',
        healthy: true,
        capabilities: ['write', 'ssh_certificates'],
      },
      { id: 'local', healthy: true, capabilities: ['write'] },
    ]);
  });

  describe('CA SSH (motor ssh en modo CA)', () => {
    /** `ssh-keygen -Lf` del certificado: tipo, key_id, principales, validez y extensiones. */
    function inspectCert(cert: string): string {
      const dir = mkdtempSync(join(tmpdir(), 'iw-cert-'));
      try {
        const file = join(dir, 'id-cert.pub');
        writeFileSync(file, cert);
        return execFileSync('ssh-keygen', ['-Lf', file]).toString();
      } finally {
        rmSync(dir, { recursive: true });
      }
    }

    it('firma una clave efímera: certificado de usuario, un principal, key_id, TTL y sin extensiones', async () => {
      const p = provider();
      const { publicKey } = generateSshKeyPair('efimera');
      const cert = await p.signSshKey({
        publicKey,
        principal: 'inventory',
        keyId: 'infraward:asset=a1:job=j1',
        ttlSeconds: 120,
      });
      const info = inspectCert(cert);
      expect(info).toMatch(
        /Type: ssh-ed25519-cert-v01@openssh.com user certificate/,
      );
      expect(info).toContain('Key ID: "infraward:asset=a1:job=j1"');
      expect(info).toMatch(/Principals: \n\s+inventory\n/);
      expect(info).toMatch(/Extensions: \(none\)/);
      expect(info).toMatch(/Critical Options: \(none\)/);
      // Validez: 30 s hacia atrás (not_before_duration) + 120 s.
      const [, from, to] = /Valid: from (\S+) to (\S+)/.exec(info)!;
      const seconds = (Date.parse(to) - Date.parse(from)) / 1000;
      expect(seconds).toBeGreaterThanOrEqual(149);
      expect(seconds).toBeLessThanOrEqual(151);
      // La CA que firma es la activa.
      const [active] = await p.sshCaPublicKeys();
      expect(info).toContain(`Signing CA: ED25519 ${active.fingerprint}`);
    });

    it('el rol no permite otro principal ⇒ provider_error', async () => {
      const p = provider();
      const { publicKey } = generateSshKeyPair('efimera');
      await expect(
        p.signSshKey({
          publicKey,
          principal: 'root',
          keyId: 'x',
          ttlSeconds: 60,
        }),
      ).rejects.toMatchObject({ code: 'provider_error' });
    });

    it('la política de la app no deja tocar la CA (config, emisores, otros roles)', async () => {
      const p = provider();
      const token = await (
        p as unknown as { tokens: { token(): Promise<string> } }
      ).tokens.token();
      const call = (method: string, path: string, body?: unknown) =>
        fetch(`${server.addr}/v1/${path}`, {
          method,
          headers: {
            'X-Vault-Token': token,
            'Content-Type': 'application/json',
          },
          body: body === undefined ? undefined : JSON.stringify(body),
        }).then((r) => r.status);
      expect(
        await call('POST', `${role.sshMount}/issuers/import/malo`, {
          generate_signing_key: true,
        }),
      ).toBe(403);
      expect(
        await call('POST', `${role.sshMount}/config/issuers`, {
          default: 'ca-1',
        }),
      ).toBe(403);
      expect(await call('GET', `${role.sshMount}/config/ca`)).toBe(403);
      expect(
        await call('POST', `${role.sshMount}/roles/inventory`, {
          allowed_users: 'root',
        }),
      ).toBe(403);
      expect(await call('DELETE', `${role.sshMount}/issuer/ca-1`)).toBe(403);
    });

    it('con dos emisores devuelve las dos claves y marca la activa', async () => {
      const r = await createTestAppRole(server);
      try {
        const p = provider(r);
        const [first] = await p.sshCaPublicKeys();
        const next = await addTestSshIssuer(server, r.sshMount, 'ca-2', false);
        const keys = await p.sshCaPublicKeys();
        expect(keys).toHaveLength(2);
        expect(keys[0]).toEqual({ ...first, active: true });
        expect(keys[1].fingerprint).toBe(sshPublicKeyFingerprint(next));
        expect(keys[1].active).toBe(false);
      } finally {
        await r.cleanup();
      }
    });
  });
});
