import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { SecretsService } from '@infraward/secrets';
import { CollectionError } from '../collect/ansible-runner.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { SshIdentities } from './ssh-identity.js';

const REF = 'secret://local/assets/a1/ssh#privateKey';
const TRACE = { assetId: 'a1', jobId: 'job-9' };

function setup(withCa: boolean) {
  const signSshKey = vi.fn(() =>
    Promise.resolve('ssh-ed25519-cert-v01@openssh.com AAAA'),
  );
  const secrets = {
    resolve: vi.fn(() => Promise.resolve('clave-estatica')),
    sshCertificates: () => (withCa ? { id: 'openbao', signSshKey } : undefined),
  };
  const values: Partial<EnvironmentVariables> = {
    SSH_CERT_TTL: 300,
    SSH_CERT_RENEW_MARGIN: 60,
  };
  const config = {
    get: (k: keyof EnvironmentVariables) => values[k],
  } as unknown as ConfigService<EnvironmentVariables, true>;
  return {
    identities: new SshIdentities(secrets as unknown as SecretsService, config),
    secrets,
    signSshKey,
  };
}

describe('SshIdentities', () => {
  it('clave estática: resuelta sin caché', async () => {
    const t = setup(true);
    await expect(
      t.identities.resolve({ auth: 'static_key', keyRef: REF }, TRACE),
    ).resolves.toEqual({ kind: 'key', privateKey: 'clave-estatica' });
    expect(t.secrets.resolve).toHaveBeenCalledWith(REF, { fresh: true });
    expect(t.signSshKey).not.toHaveBeenCalled();
  });

  it('modo CA: firma con el principal inventory, key_id del asset y el job, y el TTL configurado', async () => {
    const t = setup(true);
    const identity = await t.identities.resolve(
      { auth: 'ca_certificate', keyRef: null },
      TRACE,
    );
    expect(identity).toMatchObject({
      kind: 'certificate',
      ttlSeconds: 300,
      renewMarginSeconds: 60,
    });
    if (identity.kind !== 'certificate') throw new Error('no es CA');
    await identity.sign('ssh-ed25519 AAAAefimera');
    expect(t.signSshKey).toHaveBeenCalledWith({
      publicKey: 'ssh-ed25519 AAAAefimera',
      principal: 'inventory',
      keyId: 'infraward:asset=a1:job=job-9',
      ttlSeconds: 300,
    });
    // Ni la clave estática (aunque la hubiera) se lee.
    expect(t.secrets.resolve).not.toHaveBeenCalled();
  });

  it('modo CA sin proveedor capaz: la clave estática si la hay; si no, o en estricto, error', async () => {
    const t = setup(false);
    await expect(
      t.identities.resolve({ auth: 'ca_certificate', keyRef: REF }, TRACE),
    ).resolves.toEqual({ kind: 'key', privateKey: 'clave-estatica' });
    await expect(
      t.identities.resolve({ auth: 'ca_certificate', keyRef: null }, TRACE),
    ).rejects.toThrow(CollectionError);
    await expect(
      t.identities.resolve({ auth: 'ca_certificate', keyRef: REF }, TRACE, {
        strict: true,
      }),
    ).rejects.toThrow(/ningún proveedor de secretos activo tiene CA SSH/);
  });

  it('al firmar solo se loguea el key_id: ni el certificado ni la clave', async () => {
    const logged = [
      vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined),
      vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined),
    ];
    try {
      const t = setup(true);
      const identity = await t.identities.resolve(
        { auth: 'ca_certificate', keyRef: REF },
        TRACE,
      );
      if (identity.kind !== 'certificate') throw new Error('no es CA');
      await identity.sign('ssh-ed25519 AAAAclave-efimera-centinela');
      const text = JSON.stringify(logged.map((l) => l.mock.calls));
      expect(text).toContain('infraward:asset=a1:job=job-9');
      expect(text).not.toContain('cert-v01');
      expect(text).not.toContain('clave-efimera-centinela');
      expect(text).not.toContain('clave-estatica');
    } finally {
      logged.forEach((l) => l.mockRestore());
    }
  });
});
