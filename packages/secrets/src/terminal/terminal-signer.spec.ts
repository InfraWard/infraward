import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { generateSshKeyPair } from '../ssh-keys.js';
import { FakeOpenBao } from '../testing.js';
import { createTerminalSigner } from './terminal-signer.js';

const ADDR = 'http://127.0.0.1:8200';

describe('createTerminalSigner', () => {
  it('sin AppRole de la terminal: no hay firmante (terminal no disponible)', () => {
    expect(createTerminalSigner({ openbao: { addr: ADDR } })).toBeNull();
  });

  it('se niega a usar la AppRole o el rol de firma de la app (los tiene el worker)', () => {
    const secretId = 'secret-id-centinela';
    expect(() =>
      createTerminalSigner({
        openbao: { addr: ADDR, roleId: 'rol-app', secretId },
        appOpenbao: { roleId: 'rol-app' },
      }),
    ).toThrow(/TERMINAL_OPENBAO_ROLE_ID: la terminal necesita su propia AppRole/);
    const sameRole = () =>
      createTerminalSigner({
        openbao: { addr: ADDR, roleId: 'rol-terminal', secretId, sshRole: 'inventory' },
      });
    expect(sameRole).toThrow(/TERMINAL_OPENBAO_SSH_ROLE/);
    expect(sameRole).not.toThrow(/centinela/);
  });

  it('firma con su rol (infraward-operator) y siempre con permit-pty', async () => {
    const bao = new FakeOpenBao();
    const signer = createTerminalSigner(
      { openbao: { addr: ADDR, roleId: bao.roleId, secretId: bao.secretId } },
      bao.fetch,
    )!;
    const { publicKey } = generateSshKeyPair('efimera');
    await signer.sign({
      publicKey,
      principal: 'infraward-operators',
      keyId: 'infraward:session=s:user=ana@example.com:asset=a',
      ttlSeconds: 120,
    });
    expect(bao.calls.some((c) => c.includes('infraward-ssh/sign/infraward-operator'))).toBe(true);
    expect(bao.sshSignRequests).toEqual([
      {
        public_key: publicKey.split(' ').slice(0, 2).join(' '),
        valid_principals: 'infraward-operators',
        key_id: 'infraward:session=s:user=ana@example.com:asset=a',
        ttl: '120s',
        cert_type: 'user',
        extensions: { 'permit-pty': '' },
      },
    ]);
    await signer.close();
  });
});
