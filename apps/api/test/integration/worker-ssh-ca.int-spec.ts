import { loadOpenBaoConfig, OpenBaoSecretProvider } from '@infraward/secrets';
import {
  createTestAppRole,
  startOpenBaoTestServer,
  type OpenBaoTestServer,
  type TestAppRole,
} from '@infraward/secrets/testing/openbao';
import {
  SSH_CA_CONFIG_VERSION,
  SUDOERS_VERSION,
} from '@infraward/shared-types';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { embeddedCommand, keyComment } from '../../src/enrollment/commands.js';
import { EnrollScriptTemplate } from '../../src/enrollment/script-template.js';
import { startSshd, type TestSshd } from './support/sshd.js';

/** Cliente SSH del worker compilado (como los e2e usan worker/dist/main.js). */
const WORKER_SSH = resolve(
  import.meta.dirname,
  '../../../worker/dist/ssh/ssh-client.js',
);

interface HostExec {
  run(argv: string[]): Promise<{ code: number | null; stdout: string }>;
}
interface WorkerSshClient {
  scanHostKeys(host: string, port: number): Promise<unknown[]>;
  session<T>(
    target: { host: string; port: number; user: string },
    identity: unknown,
    hostKey: unknown,
    fn: (host: HostExec) => Promise<T>,
  ): Promise<T>;
}

/**
 * El `SshClient` real del worker en modo CA contra un sshd real: clave efímera, certificado de
 * OpenBao, una sola autenticación por job (ControlMaster), firma nueva solo si al abrir una
 * conexión queda menos del margen, y ningún proceso ni fichero al terminar.
 */
describe('Worker: SshClient en modo CA (integración)', () => {
  let sshd: TestSshd;
  let bao: OpenBaoTestServer;
  let role: TestAppRole;
  let provider: OpenBaoSecretProvider;
  let ssh: WorkerSshClient;
  let tmp: string;
  const assetId = randomUUID();

  const target = () => ({
    host: sshd.host,
    port: sshd.port,
    user: 'inventory',
  });
  const accepted = (keyId: string) =>
    sshd
      .logs()
      .split('\n')
      .filter((l) => l.includes('Accepted') && l.includes(`ID ${keyId} `))
      .length;
  const sshProcessesInTmp = () =>
    execFileSync('ps', ['-ax', '-o', 'command'])
      .toString()
      .split('\n')
      .filter((l) => l.includes(tmp) && /\bssh\b/.test(l));

  function identity(keyId: string, ttlSeconds: number, margin: number) {
    const signed: string[] = [];
    return {
      signed,
      identity: {
        kind: 'certificate',
        ttlSeconds,
        renewMarginSeconds: margin,
        sign: async (publicKey: string) => {
          signed.push(publicKey);
          return provider.signSshKey({
            publicKey,
            principal: 'inventory',
            keyId,
            ttlSeconds,
          });
        },
      },
    };
  }

  beforeAll(async () => {
    [sshd, bao] = await Promise.all([startSshd(), startOpenBaoTestServer()]);
    role = await createTestAppRole(bao);
    provider = new OpenBaoSecretProvider(
      loadOpenBaoConfig({
        addr: bao.addr,
        roleId: role.roleId,
        secretId: role.secretId,
        kvMount: role.kvMount,
        approleMount: role.approleMount,
        kvPrefix: role.kvPrefix,
        sshMount: role.sshMount,
        sshRole: role.sshRole,
      }),
    );
    const script = EnrollScriptTemplate.load().render({
      mode: 'embedded',
      apiUrl: '',
      token: '',
      authMode: 'ca_certificate',
      publicKey: '',
      keyComment: keyComment(assetId),
      sudoersVersion: SUDOERS_VERSION,
      caKeys: (await provider.sshCaPublicKeys()).map((k) => k.publicKey),
      caVersion: SSH_CA_CONFIG_VERSION,
      issuedAt: Math.floor(Date.now() / 1000),
    });
    const r = await sshd.root(embeddedCommand(script));
    expect(r.code, r.stderr).toBe(0);

    tmp = mkdtempSync(join(tmpdir(), 'iw-worker-'));
    const { SshClient, execFileRunner } = (await import(WORKER_SSH)) as {
      SshClient: new (config: unknown, run: unknown) => WorkerSshClient;
      execFileRunner: unknown;
    };
    const values: Record<string, unknown> = {
      WORKER_TMP_DIR: tmp,
      SSH_CONNECT_TIMEOUT: 10,
    };
    ssh = new SshClient({ get: (k: string) => values[k] }, execFileRunner);
  });

  afterAll(async () => {
    await provider?.close();
    await role?.cleanup();
    await Promise.all([sshd?.stop(), bao?.stop()]);
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  it('un job con varios comandos autentica una sola vez, con el key_id del job', async () => {
    const keyId = `infraward:asset=${assetId}:job=${randomUUID()}`;
    const { identity: id, signed } = identity(keyId, 120, 30);
    const [hostKey] = await ssh.scanHostKeys(sshd.host, sshd.port);
    const outputs = await ssh.session(target(), id, hostKey, async (host) => [
      (await host.run(['id', '-un'])).stdout.trim(),
      (await host.run(['uname', '-s'])).stdout.trim(),
      (await host.run(['cat', '/etc/infraward/ssh-ca-version'])).stdout.trim(),
    ]);
    expect(outputs).toEqual([
      'inventory',
      'Linux',
      String(SSH_CA_CONFIG_VERSION),
    ]);
    expect(signed).toHaveLength(1);
    expect(await sshd.waitForLog(`ID ${keyId} `)).toBe(true);
    await sleep(300);
    expect(accepted(keyId)).toBe(1);
    // Nada queda: ni el directorio con la clave efímera ni el maestro.
    expect(readdirSync(tmp)).toEqual([]);
    expect(sshProcessesInTmp()).toEqual([]);
  });

  it('pasado el margen, la siguiente conexión lleva un certificado nuevo de la misma clave', async () => {
    const keyId = `infraward:asset=${assetId}:job=${randomUUID()}`;
    // TTL 40 s y margen 30 s: a los 11 s ya hay que firmar otro antes de conectar.
    const { identity: id, signed } = identity(keyId, 40, 30);
    const [hostKey] = await ssh.scanHostKeys(sshd.host, sshd.port);
    await ssh.session(target(), id, hostKey, async (host) => {
      await host.run(['true']);
      await sleep(11_000);
      expect((await host.run(['id', '-un'])).stdout.trim()).toBe('inventory');
    });
    expect(signed).toHaveLength(2);
    expect(signed[0]).toBe(signed[1]);
    expect(readdirSync(tmp)).toEqual([]);
    expect(sshProcessesInTmp()).toEqual([]);
  });

  it('si el job falla, también se cierra el maestro y se borra todo', async () => {
    const keyId = `infraward:asset=${assetId}:job=${randomUUID()}`;
    const { identity: id } = identity(keyId, 120, 30);
    const [hostKey] = await ssh.scanHostKeys(sshd.host, sshd.port);
    await expect(
      ssh.session(target(), id, hostKey, async (host) => {
        await host.run(['true']);
        throw new Error('fallo del job');
      }),
    ).rejects.toThrow('fallo del job');
    expect(readdirSync(tmp)).toEqual([]);
    expect(sshProcessesInTmp()).toEqual([]);
  });
});
