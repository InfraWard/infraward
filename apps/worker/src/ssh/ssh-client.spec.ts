import type { ConfigService } from '@nestjs/config';
import {
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
import type { ScannedHostKey } from './host-keys.js';
import {
  spawnStreamer,
  SshClient,
  SshError,
  type ProcessResult,
  type ProcessRunner,
  type ProcessStreamer,
} from './ssh-client.js';

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

/** Maestro del job (`-N -f`) y su control (`-O`): aquí siempre bien; el resto, a `run`. */
const isControl = (args: string[]) =>
  args.includes('-N') || args.includes('-O');
function withMaster(run: ProcessRunner): ProcessRunner {
  return (file, args, timeoutMs, options) =>
    isControl(args)
      ? Promise.resolve({ stdout: '', stderr: '', code: 0 })
      : run(file, args, timeoutMs, options);
}

describe('SshClient', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'ssh-client-'));
  });
  afterEach(() => rmSync(tmp, { recursive: true, force: true }));

  function client(run: ProcessRunner, streamer?: ProcessStreamer) {
    const values: Partial<EnvironmentVariables> = {
      WORKER_TMP_DIR: tmp,
      SSH_CONNECT_TIMEOUT: 7,
    };
    const config = {
      get: (k: keyof EnvironmentVariables) => values[k],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    return new SshClient(config, withMaster(run), streamer);
  }

  it('fija la host key, usa la clave desde un fichero 600 y lo borra al terminar', async () => {
    let seen:
      | {
          args: string[];
          keyMode: number;
          dirMode: number;
          key: string;
          known: string;
        }
      | undefined;
    const run: ProcessRunner = (file, args) => {
      expect(file).toBe('ssh');
      const keyFile = args[args.indexOf('-i') + 1];
      const known = args
        .find((a) => a.startsWith('UserKnownHostsFile='))!
        .split('=')[1];
      seen = {
        args,
        keyMode: statSync(keyFile).mode & 0o777,
        dirMode: statSync(join(keyFile, '..')).mode & 0o777,
        key: readFileSync(keyFile, 'utf8'),
        known: readFileSync(known, 'utf8'),
      };
      return Promise.resolve({ stdout: '1001\n1\n', stderr: '', code: 0 });
    };
    const out = await client(run).exec(TARGET, IDENTITY, HOST_KEY, 'id -u');
    expect(out).toBe('1001\n1\n');
    expect(seen!.keyMode).toBe(0o600);
    expect(seen!.dirMode).toBe(0o700);
    expect(seen!.key).toBe(KEY);
    expect(seen!.known).toBe(
      `[192.0.2.10]:2222 ssh-ed25519 ${HOST_KEY.blob}\n`,
    );
    const opts = seen!.args.join(' ');
    expect(opts).toContain('StrictHostKeyChecking=yes');
    expect(opts).not.toMatch(/StrictHostKeyChecking=(no|accept-new)/);
    expect(opts).toContain('BatchMode=yes');
    expect(opts).toContain('HostKeyAlgorithms=ssh-ed25519');
    expect(opts).toContain('ConnectTimeout=7');
    // El host va tras `--`: nunca se interpreta como opción.
    expect(seen!.args.slice(-3)).toEqual(['--', '192.0.2.10', 'id -u']);
    // La clave nunca va en los argumentos.
    expect(opts).not.toContain('clave-centinela');
    expect(readdirSync(tmp)).toEqual([]);
  });

  /** Runner que simula ssh: escribe `log` en el fichero de `-E` (lo que ssh dice de sí mismo). */
  function fakeSsh(result: ProcessResult, log = ''): ProcessRunner {
    return (_file, args) => {
      if (log) writeFileSync(args[args.indexOf('-E') + 1], log);
      return Promise.resolve(result);
    };
  }

  it('si ssh falla, borra la clave y da un error sin secretos', async () => {
    const run = fakeSsh(
      { stdout: '', stderr: '', code: 255 },
      'Warning: algo\ninventory@192.0.2.10: Permission denied (publickey).\n',
    );
    const error = await client(run)
      .exec(TARGET, IDENTITY, HOST_KEY, 'id -u')
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SshError);
    expect((error as Error).message).toBe(
      'Fallo al conectar por SSH con inventory@192.0.2.10:2222: inventory@192.0.2.10: Permission denied (publickey).',
    );
    expect((error as Error).message).not.toContain('clave-centinela');
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('los mensajes de ssh van a un log aparte (-E) con LogLevel=ERROR', async () => {
    let args: string[] = [];
    const run: ProcessRunner = (_file, a) => {
      args = a;
      return Promise.resolve({ stdout: '', stderr: '', code: 0 });
    };
    await client(run).exec(TARGET, IDENTITY, HOST_KEY, 'true');
    const log = args[args.indexOf('-E') + 1];
    expect(log).toMatch(/infraward-ssh-[^/]+\/ssh-[0-9a-f-]+\.log$/);
    expect(args.join(' ')).toContain('LogLevel=ERROR');
  });

  describe('session: código 255', () => {
    async function run255(log: string) {
      const run = fakeSsh(
        {
          stdout: '',
          stderr: 'ipcc_send_rec[1] failed: Unknown error -1\n',
          code: 255,
        },
        log,
      );
      return client(run).session(TARGET, IDENTITY, HOST_KEY, (host) =>
        host.query({ name: 'pve-cluster-status' }),
      );
    }

    it('sin log de ssh es el código del comando remoto: se devuelve tal cual', async () => {
      const result = await run255('');
      expect(result.code).toBe(255);
      expect(result.stderr).toContain('ipcc_send_rec');
      expect(readdirSync(tmp)).toEqual([]);
    });

    it('con log de ssh es un fallo de conexión', async () => {
      const error = await run255(
        'ssh: connect to host 192.0.2.10 port 2222: Connection refused\n',
      ).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SshError);
      expect((error as Error).message).toBe(
        'Fallo al conectar por SSH con inventory@192.0.2.10:2222: ssh: connect to host 192.0.2.10 port 2222: Connection refused',
      );
      expect(readdirSync(tmp)).toEqual([]);
    });
  });

  it('exec: un comando remoto que falla no se presenta como fallo de conexión', async () => {
    const run = fakeSsh({
      stdout: '',
      stderr: 'sudo: a password is required\n',
      code: 1,
    });
    await expect(
      client(run).exec(TARGET, IDENTITY, HOST_KEY, 'sudo -n true'),
    ).rejects.toThrow(
      'El comando remoto falló en inventory@192.0.2.10:2222: sudo: a password is required',
    );
  });

  describe('session: streamToFile', () => {
    it('vuelca a disco con la conexión fijada, compresión y sudo -n por el ayudante', async () => {
      let args: string[] = [];
      const streamer: ProcessStreamer = (_file, a, dest) => {
        args = a;
        writeFileSync(dest, 'tar');
        return Promise.resolve({ code: 0, bytes: 3, stderr: '', limit: null });
      };
      const dest = join(tmp, 'image.tar');
      const result = await client(
        () => Promise.reject(new Error('no se usa')),
        streamer,
      ).session(TARGET, IDENTITY, HOST_KEY, (host) =>
        host.streamToFile(
          { name: 'docker-save', args: [`sha256:${'a'.repeat(64)}`] },
          dest,
          { maxBytes: 10, timeoutMs: 1000 },
        ),
      );
      expect(result).toEqual({ code: 0, bytes: 3, stderr: '', limit: null });
      const opts = args.join(' ');
      expect(opts).toContain('Compression=yes');
      expect(opts).toContain('StrictHostKeyChecking=yes');
      expect(args.at(-1)).toBe(
        `sudo -n /usr/local/libexec/infraward/infraward-query docker-save sha256:${'a'.repeat(64)}`,
      );
    });

    it('255 con log de ssh es un fallo de conexión', async () => {
      const streamer: ProcessStreamer = (_file, a) => {
        writeFileSync(
          a[a.indexOf('-E') + 1],
          'Host key verification failed.\n',
        );
        return Promise.resolve({
          code: 255,
          bytes: 0,
          stderr: '',
          limit: null,
        });
      };
      await expect(
        client(() => Promise.reject(new Error('no')), streamer).session(
          TARGET,
          IDENTITY,
          HOST_KEY,
          (host) =>
            host.streamToFile(
              { name: 'docker-save', args: [`sha256:${'b'.repeat(64)}`] },
              join(tmp, 'x.tar'),
              { maxBytes: 10, timeoutMs: 1000 },
            ),
        ),
      ).rejects.toThrow(SshError);
      // El material (clave) se borra; el fichero de salida es del llamante.
      expect(readdirSync(tmp)).toEqual([]);
    });
  });

  describe('spawnStreamer (procesos reales)', () => {
    const node = process.execPath;

    it('escribe la salida en el fichero (600) sin pasar por memoria', async () => {
      const dest = join(tmp, 'ok.bin');
      const result = await spawnStreamer(
        node,
        [
          '-e',
          'process.stdout.write("x".repeat(300000)); process.stderr.write("aviso")',
        ],
        dest,
        { maxBytes: 1_000_000, timeoutMs: 10_000 },
      );
      expect(result).toEqual({
        code: 0,
        bytes: 300000,
        stderr: 'aviso',
        limit: null,
      });
      expect(statSync(dest).size).toBe(300000);
      expect(statSync(dest).mode & 0o777).toBe(0o600);
    });

    it('al pasar de maxBytes mata el proceso y lo indica', async () => {
      const result = await spawnStreamer(
        node,
        ['-e', 'setInterval(() => process.stdout.write("x".repeat(65536)), 1)'],
        join(tmp, 'big.bin'),
        { maxBytes: 200_000, timeoutMs: 10_000 },
      );
      expect(result.limit).toBe('size');
      expect(result.code).toBeNull();
      expect(result.bytes).toBeGreaterThan(200_000);
    });

    it('al agotar el tiempo mata el proceso y lo indica', async () => {
      const started = Date.now();
      const result = await spawnStreamer(
        node,
        ['-e', 'setTimeout(() => {}, 60000)'],
        join(tmp, 'slow.bin'),
        { maxBytes: 1000, timeoutMs: 300 },
      );
      expect(result).toMatchObject({ limit: 'time', code: null });
      expect(Date.now() - started).toBeLessThan(5000);
    });

    it('no pisa un fichero existente', async () => {
      const dest = join(tmp, 'existe');
      writeFileSync(dest, 'previo');
      await expect(
        spawnStreamer(node, ['-e', ''], dest, {
          maxBytes: 10,
          timeoutMs: 1000,
        }),
      ).rejects.toThrow(/EEXIST/);
      expect(readFileSync(dest, 'utf8')).toBe('previo');
    });
  });

  it('scanHostKeys falla con un mensaje claro si no hay host keys', async () => {
    const run: ProcessRunner = (file, args) => {
      expect(file).toBe('ssh-keyscan');
      expect(args.slice(-2)).toEqual(['--', '192.0.2.10']);
      return Promise.resolve({ stdout: '', stderr: '', code: 1 });
    };
    await expect(client(run).scanHostKeys('192.0.2.10', 22)).rejects.toThrow(
      'No se pudo leer la host key de 192.0.2.10:22 (código 1)',
    );
  });

  describe('ControlMaster y modo CA', () => {
    function rawClient(run: ProcessRunner) {
      const values: Partial<EnvironmentVariables> = {
        WORKER_TMP_DIR: tmp,
        SSH_CONNECT_TIMEOUT: 7,
      };
      const config = {
        get: (k: keyof EnvironmentVariables) => values[k],
      } as unknown as ConfigService<EnvironmentVariables, true>;
      return new SshClient(config, run);
    }

    it('abre el maestro antes del primer comando, los comandos lo reutilizan y al final se cierra', async () => {
      const calls: { args: string[]; background?: boolean }[] = [];
      const run: ProcessRunner = (_f, args, _t, options) => {
        calls.push({ args, background: options?.background });
        return Promise.resolve({ stdout: 'ok', stderr: '', code: 0 });
      };
      await rawClient(run).session(TARGET, IDENTITY, HOST_KEY, async (host) => {
        await host.run(['uname']);
        await host.run(['id']);
      });
      const kinds = calls.map((c) =>
        c.args.includes('-N')
          ? 'maestro'
          : c.args.includes('-O')
            ? `-O ${c.args[c.args.indexOf('-O') + 1]}`
            : c.args.at(-1),
      );
      expect(kinds).toEqual(['maestro', 'uname', 'id', '-O check', '-O exit']);
      // El maestro va en segundo plano (sin tuberías heredadas) y con ControlMaster=yes delante.
      expect(calls[0].background).toBe(true);
      expect(calls[0].args.slice(0, 4)).toEqual([
        '-o',
        'ControlMaster=yes',
        '-o',
        expect.stringMatching(/^ControlPersist=\d+$/),
      ]);
      const socket = /ControlPath=(\S+)/.exec(calls[0].args.join(' '))![1];
      // En el tmpfs del job o, si la ruta no cabe en un socket unix, en un directorio corto aparte.
      expect(socket).toMatch(/(infraward-ssh-[^/]+|^\/tmp\/iw-[^/]+)\/cm$/);
      expect(socket.length).toBeLessThanOrEqual(80);
      expect(calls[1].args.join(' ')).toContain(
        `ControlMaster=auto -o ControlPath=${socket}`,
      );
      expect(readdirSync(tmp)).toEqual([]);
    });

    it('si el maestro no autentica: SshError, no se ejecuta nada y no queda nada', async () => {
      const commands: string[][] = [];
      const run: ProcessRunner = (_f, args) => {
        if (args.includes('-N')) {
          writeFileSync(
            args[args.indexOf('-E') + 1],
            'inventory@192.0.2.10: Permission denied (publickey).\n',
          );
          return Promise.resolve({ stdout: '', stderr: '', code: 255 });
        }
        if (!args.includes('-O')) commands.push(args);
        return Promise.resolve({ stdout: '', stderr: '', code: 0 });
      };
      const error = await rawClient(run)
        .exec(TARGET, IDENTITY, HOST_KEY, 'id -u')
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SshError);
      expect((error as Error).message).toContain(
        'Permission denied (publickey)',
      );
      expect(commands).toEqual([]);
      expect(readdirSync(tmp)).toEqual([]);
    });

    it('modo CA: clave efímera y certificado; solo se vuelve a firmar si queda menos del margen', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      try {
        const seen: { cert: string; key: string }[] = [];
        const run: ProcessRunner = (_f, args) => {
          if (!args.includes('-O')) {
            const cert = /CertificateFile=(\S+)/.exec(args.join(' '))![1];
            seen.push({
              cert: readFileSync(cert, 'utf8'),
              key: readFileSync(args[args.indexOf('-i') + 1], 'utf8'),
            });
          }
          return Promise.resolve({ stdout: '', stderr: '', code: 0 });
        };
        let n = 0;
        const signed: string[] = [];
        const identity = {
          kind: 'certificate' as const,
          ttlSeconds: 300,
          renewMarginSeconds: 60,
          sign: (publicKey: string) => {
            signed.push(publicKey);
            return Promise.resolve(
              `ssh-ed25519-cert-v01@openssh.com CERT${++n}`,
            );
          },
        };
        await rawClient(run).session(
          TARGET,
          identity,
          HOST_KEY,
          async (host) => {
            await host.run(['a']); // Recién firmado al abrir el maestro: no firma.
            vi.advanceTimersByTime(239_000); // Quedan 61 s: aún vale.
            await host.run(['b']);
            vi.advanceTimersByTime(2_000); // Quedan 59 s: firma otro para la misma clave.
            await host.run(['c']);
          },
        );
        expect(signed).toHaveLength(2);
        expect(signed[0]).toBe(signed[1]);
        expect(signed[0]).toMatch(/^ssh-ed25519 \S+ infraward-efimera$/);
        expect(seen.map((s) => s.cert.trim())).toEqual([
          'ssh-ed25519-cert-v01@openssh.com CERT1',
          'ssh-ed25519-cert-v01@openssh.com CERT1',
          'ssh-ed25519-cert-v01@openssh.com CERT1',
          'ssh-ed25519-cert-v01@openssh.com CERT2',
        ]);
        expect(seen[0].key).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----/);
        expect(readdirSync(tmp)).toEqual([]);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});
