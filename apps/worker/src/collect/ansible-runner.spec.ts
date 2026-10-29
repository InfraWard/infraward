import type { ConfigService } from '@nestjs/config';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { ScannedHostKey } from '../ssh/host-keys.js';
import {
  SshClient,
  type ProcessOptions,
  type ProcessResult,
  type ProcessRunner,
} from '../ssh/ssh-client.js';
import {
  AnsibleRunner,
  CollectionError,
  describeFailure,
} from './ansible-runner.js';

const KEY =
  '-----BEGIN OPENSSH PRIVATE KEY-----\nclave-centinela\n-----END OPENSSH PRIVATE KEY-----\n';
const HOST_KEY: ScannedHostKey = {
  keyType: 'ssh-ed25519',
  blob: 'AAAAC3NzaC1lZDI1NTE5AAAAIA==',
  type: 'ED25519',
  fingerprint: `SHA256:${'a'.repeat(43)}`,
};
const IDENTITY = { kind: 'key' as const, privateKey: KEY };
const TARGET = { host: '192.0.2.10', port: 2222, user: 'inventory' };
const RAW = { facts: { machine_id: 'abc' }, which: [], sudo: [] };

interface Call {
  file: string;
  args: string[];
  timeoutMs: number;
  options?: ProcessOptions;
  inventory: Record<string, unknown>;
  dirMode: number;
  keyMode: number;
}

describe('AnsibleRunner', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'ansible-runner-'));
  });
  afterEach(() => rmSync(tmp, { recursive: true, force: true }));

  function runner(
    respond: (call: Call, output: string) => ProcessResult,
    extra: Partial<EnvironmentVariables> = {},
  ) {
    const values: Partial<EnvironmentVariables> = {
      WORKER_TMP_DIR: tmp,
      SSH_CONNECT_TIMEOUT: 7,
      ANSIBLE_PLAYBOOK_BIN: '/opt/ansible/bin/ansible-playbook',
      ANSIBLE_DIR: '/srv/infraward/ansible',
      COLLECT_TIMEOUT: 120,
      ...extra,
    };
    const config = {
      get: (k: keyof EnvironmentVariables) => values[k],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    const calls: Call[] = [];
    const sshCalls: string[][] = [];
    const run: ProcessRunner = (file, args, timeoutMs, options) => {
      // Maestro del job (`-N -f`) y su control (`-O check|exit`).
      if (file === 'ssh') {
        sshCalls.push(args);
        return Promise.resolve({ stdout: '', stderr: '', code: 0 });
      }
      const inventoryFile = args[args.indexOf('-i') + 1];
      const inventory = JSON.parse(
        readFileSync(inventoryFile, 'utf8'),
      ) as Record<string, unknown>;
      const vars = JSON.parse(args[args.indexOf('-e') + 1]) as {
        infraward_output: string;
      };
      const dir = join(inventoryFile, '..');
      const call: Call = {
        file,
        args,
        timeoutMs,
        options,
        inventory,
        dirMode: statSync(dir).mode & 0o777,
        keyMode: statSync(join(dir, 'id')).mode & 0o777,
      };
      calls.push(call);
      return Promise.resolve(respond(call, vars.infraward_output));
    };
    const ssh = new SshClient(config, run);
    return { runner: new AnsibleRunner(config, ssh, run), calls, sshCalls };
  }

  const ok = (_c: Call, output: string): ProcessResult => {
    writeFileSync(output, JSON.stringify(RAW));
    return { stdout: 'PLAY RECAP', stderr: '', code: 0 };
  };

  it('lanza el playbook con la host key fijada y la clave solo por ruta, y lo borra todo', async () => {
    const { runner: r, calls } = runner(ok);
    await expect(r.collect(TARGET, IDENTITY, HOST_KEY)).resolves.toEqual(RAW);

    const [call] = calls;
    expect(call.file).toBe('/opt/ansible/bin/ansible-playbook');
    expect(call.args.at(-1)).toBe('/srv/infraward/ansible/collect/collect.yml');
    expect(call.timeoutMs).toBe(120_000);
    expect(call.dirMode).toBe(0o700);
    expect(call.keyMode).toBe(0o600);
    const host = (
      call.inventory as {
        all: { hosts: { target: Record<string, string | number> } };
      }
    ).all.hosts.target;
    expect(host).toMatchObject({
      ansible_host: '192.0.2.10',
      ansible_port: 2222,
      ansible_user: 'inventory',
    });
    const sshArgs = String(host.ansible_ssh_common_args);
    expect(sshArgs).toContain('StrictHostKeyChecking=yes');
    expect(sshArgs).not.toMatch(/StrictHostKeyChecking=(no|accept-new)/);
    expect(sshArgs).toContain('IdentityAgent=none');
    expect(sshArgs).toMatch(/UserKnownHostsFile=\S+known_hosts/);
    expect(call.options?.env).toMatchObject({
      ANSIBLE_CONFIG: '/srv/infraward/ansible/collect/ansible.cfg',
      LC_ALL: 'C.UTF-8',
    });
    // La clave nunca va en argumentos, inventario ni entorno: solo su ruta.
    const visible = JSON.stringify([call.args, call.inventory, call.options]);
    expect(visible).not.toContain('clave-centinela');
    // Nada queda en el tmpfs.
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('una sola autenticación: abre el maestro antes de Ansible, que lo reutiliza, y lo cierra', async () => {
    const { runner: r, calls, sshCalls } = runner(ok);
    await r.collect(TARGET, IDENTITY, HOST_KEY);
    const [master, check, exit] = sshCalls;
    expect(sshCalls).toHaveLength(3);
    expect(master.join(' ')).toMatch(
      /-o ControlMaster=yes -o ControlPersist=\d+ /,
    );
    expect(master).toEqual(expect.arrayContaining(['-N', '-f']));
    const controlPath = /ControlPath=(\S+)/.exec(master.join(' '))![1];
    expect(check.join(' ')).toContain(`ControlPath=${controlPath} -O check`);
    expect(exit.join(' ')).toContain(`ControlPath=${controlPath} -O exit`);
    // Ansible usa el mismo socket con ControlMaster=auto.
    const host = (
      calls[0].inventory as {
        all: { hosts: { target: Record<string, string> } };
      }
    ).all.hosts.target;
    expect(host.ansible_ssh_common_args).toContain('ControlMaster=auto');
    expect(host.ansible_ssh_common_args).toContain(
      `ControlPath=${controlPath}`,
    );
  });

  it('modo CA: clave efímera y certificado en el tmpfs, firmado antes de conectar, y nada queda', async () => {
    const signed: string[] = [];
    const { runner: r, calls, sshCalls } = runner(ok);
    const identity = {
      kind: 'certificate' as const,
      ttlSeconds: 300,
      renewMarginSeconds: 60,
      sign: (publicKey: string) => {
        signed.push(publicKey);
        return Promise.resolve('ssh-ed25519-cert-v01@openssh.com AAAAcert');
      },
    };
    await r.collect(TARGET, identity, HOST_KEY);
    // Una firma (al abrir el maestro) para una clave ed25519 efímera.
    expect(signed).toHaveLength(1);
    expect(signed[0]).toMatch(/^ssh-ed25519 \S+ infraward-efimera$/);
    expect(sshCalls[0].join(' ')).toMatch(/CertificateFile=\S+id-cert\.pub/);
    const host = (
      calls[0].inventory as {
        all: { hosts: { target: Record<string, string> } };
      }
    ).all.hosts.target;
    expect(host.ansible_ssh_common_args).toMatch(
      /CertificateFile=\S+id-cert\.pub/,
    );
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('CT por pct exec: conexión infraward_pct contra el nodo, sin sudo y modo pct', async () => {
    const { runner: r, calls } = runner(ok);
    await r.collect(TARGET, IDENTITY, HOST_KEY, { kind: 'pct', vmid: 105 });
    const [call] = calls;
    const host = (
      call.inventory as {
        all: { hosts: { target: Record<string, unknown> } };
      }
    ).all.hosts.target;
    // Se conecta al nodo (TARGET) con su host key fijada; el CT solo es el vmid.
    expect(host).toMatchObject({
      ansible_host: '192.0.2.10',
      ansible_connection: 'infraward_pct',
      infraward_pct_vmid: 105,
      ansible_ssh_use_tty: false,
    });
    expect(String(host.ansible_ssh_common_args)).toContain(
      'StrictHostKeyChecking=yes',
    );
    expect(JSON.parse(call.args[call.args.indexOf('-e') + 1])).toMatchObject({
      infraward_via: 'pct',
      infraward_query_prefix: [],
    });
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('servidor: modo ssh con sudo -n por -e (gana a los vars del play)', async () => {
    const { runner: r, calls } = runner(ok);
    await r.collect(TARGET, IDENTITY, HOST_KEY);
    const [call] = calls;
    expect(JSON.parse(call.args[call.args.indexOf('-e') + 1])).toMatchObject({
      infraward_via: 'ssh',
      infraward_query_prefix: [
        'sudo',
        '-n',
        '/usr/local/libexec/infraward/infraward-query',
      ],
    });
    expect(JSON.stringify(call.inventory)).not.toContain('infraward_pct');
  });

  it('ninguna variable de -e pisa un register del playbook real (las -e ganan a todo)', async () => {
    const playbook = readFileSync(
      new URL('../../../../ansible/collect/collect.yml', import.meta.url),
      'utf8',
    );
    const registered = [...playbook.matchAll(/^\s*register:\s*(\w+)/gm)].map(
      (m) => m[1],
    );
    expect(registered.length).toBeGreaterThan(3);
    const { runner: r, calls } = runner(ok);
    await r.collect(TARGET, IDENTITY, HOST_KEY);
    await r.collect(TARGET, IDENTITY, HOST_KEY, { kind: 'pct', vmid: 100 });
    for (const call of calls) {
      const keys = Object.keys(
        JSON.parse(call.args[call.args.indexOf('-e') + 1]) as object,
      );
      expect(keys.filter((k) => registered.includes(k))).toEqual([]);
    }
  });

  it('rechaza un vmid no válido sin lanzar Ansible', async () => {
    const { runner: r, calls } = runner(ok);
    await expect(
      r.collect(TARGET, IDENTITY, HOST_KEY, { kind: 'pct', vmid: 7 }),
    ).rejects.toThrow('vmid de CT no válido');
    expect(calls).toEqual([]);
  });

  it('fallo de Ansible: error con mensaje acotado y tmpfs borrado', async () => {
    const { runner: r } = runner(() => ({
      stdout:
        'fatal: [target]: UNREACHABLE! => {"changed": false, "msg": "Task failed: Failed to connect to the host via ssh: inventory@192.0.2.10: Permission denied (publickey).", "unreachable": true}\n',
      stderr: '',
      code: 4,
    }));
    await expect(r.collect(TARGET, IDENTITY, HOST_KEY)).rejects.toThrow(
      new CollectionError(
        'El servidor rechazó la clave de InfraWard (Permission denied)',
      ),
    );
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('tiempo agotado: error y tmpfs borrado', async () => {
    const { runner: r } = runner(() => ({
      stdout: '',
      stderr: '',
      code: null,
    }));
    await expect(r.collect(TARGET, IDENTITY, HOST_KEY)).rejects.toThrow(
      'La recolección superó el tiempo máximo',
    );
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('sin fichero de resultado o con JSON roto: error', async () => {
    const { runner: missing } = runner(() => ({
      stdout: '',
      stderr: '',
      code: 0,
    }));
    await expect(missing.collect(TARGET, IDENTITY, HOST_KEY)).rejects.toThrow(
      'Ansible terminó sin dejar el resultado',
    );
    const { runner: broken } = runner((_c, output) => {
      writeFileSync(output, '{roto');
      return { stdout: '', stderr: '', code: 0 };
    });
    await expect(broken.collect(TARGET, IDENTITY, HOST_KEY)).rejects.toThrow(
      'no es JSON válido',
    );
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('rechaza host o usuario que Ansible podría interpretar como plantilla', async () => {
    const { runner: r, calls } = runner(ok);
    await expect(
      r.collect(
        { ...TARGET, host: '{{ lookup("pipe","id") }}' },
        IDENTITY,
        HOST_KEY,
      ),
    ).rejects.toThrow(CollectionError);
    await expect(
      r.collect({ ...TARGET, user: 'a b' }, IDENTITY, HOST_KEY),
    ).rejects.toThrow(CollectionError);
    expect(calls).toEqual([]);
    expect(existsSync(tmp) && readdirSync(tmp)).toEqual([]);
  });
});

describe('describeFailure', () => {
  const fatal = (msg: string): ProcessResult => ({
    stdout: `TASK [x]\nfatal: [target]: FAILED! => ${JSON.stringify({ changed: false, msg })}\nPLAY RECAP`,
    stderr: '',
    code: 2,
  });

  it('traduce los casos conocidos', () => {
    expect(describeFailure(fatal('Host key verification failed.'))).toMatch(
      /posible suplantación/,
    );
    expect(
      describeFailure(
        fatal('The module interpreter /usr/bin/python3 was not found'),
      ),
    ).toMatch(/python3/);
  });

  it('errores de un CT por pct exec', () => {
    const via = { kind: 'pct' as const, vmid: 100 };
    expect(
      describeFailure(fatal("CT 100 not running - can't execute"), via),
    ).toBe('El CT 100 no está en marcha');
    expect(
      describeFailure(fatal('/bin/sh: 1: /usr/bin/python3: not found'), via),
    ).toMatch(/python3 dentro del CT 100/);
    expect(describeFailure(fatal('sudo: a password is required'), via)).toMatch(
      /no permite pct exec/,
    );
  });

  it('recorta el mensaje genérico y sin fatal da el código', () => {
    const long = describeFailure(fatal('x'.repeat(1000)));
    expect(long.length).toBeLessThan(400);
    expect(describeFailure({ stdout: 'nada', stderr: '', code: 5 })).toBe(
      'Fallo en la recolección (código 5)',
    );
  });
});
