import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { StartedTestContainer } from 'testcontainers';

/** Servidores de prueba: Debian 13 con sudo clásico y Ubuntu 26.04 con sudo-rs. */
const VARIANTS = {
  debian: {
    dir: resolve(import.meta.dirname, '../fixtures/sshd'),
    image: 'localhost/infraward-test-sshd:1',
  },
  'sudo-rs': {
    dir: resolve(import.meta.dirname, '../fixtures/sshd-sudo-rs'),
    image: 'localhost/infraward-test-sshd-sudo-rs:1',
  },
} as const;
export type SshdVariant = keyof typeof VARIANTS;

export interface CommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Servidor SSH real (en un contenedor) contra el que se ejecuta el script de alta. */
export interface TestSshd {
  host: string;
  port: number;
  /** Ejecuta un comando como root dentro del servidor (`bash -c`). */
  root(command: string): Promise<CommandResult>;
  /** Ejecuta un argv tal cual (sin shell) dentro del servidor, como root. */
  exec(argv: string[]): Promise<CommandResult>;
  /** Log de sshd hasta ahora (lo que en un servidor iría a auth.log). */
  logs(): string;
  /** Espera (máx. `timeoutMs`) a que el log contenga `text`; devuelve si apareció. */
  waitForLog(text: string, timeoutMs?: number): Promise<boolean>;
  stop(): Promise<void>;
}

export async function startSshd(
  variant: SshdVariant = 'debian',
): Promise<TestSshd> {
  const { dir: FIXTURE_DIR, image: IMAGE } = VARIANTS[variant];
  // Ryuk no funciona con Podman rootless; el contenedor se para en stop().
  process.env.TESTCONTAINERS_RYUK_DISABLED ??= 'true';
  const { GenericContainer, Wait } = await import('testcontainers');
  await GenericContainer.fromDockerfile(FIXTURE_DIR, 'Containerfile')
    .withCache(true)
    .build(IMAGE, { deleteOnExit: false });
  const container: StartedTestContainer = await new GenericContainer(IMAGE)
    .withExposedPorts(22)
    .withWaitStrategy(Wait.forLogMessage(/Server listening on/))
    .start();
  let log = '';
  const stream = await container.logs();
  stream.on('data', (chunk: Buffer | string) => (log += chunk.toString()));
  return {
    host: container.getHost(),
    port: container.getMappedPort(22),
    async root(command) {
      const r = await container.exec(['bash', '-c', command]);
      return { code: r.exitCode, stdout: r.stdout, stderr: r.stderr };
    },
    async exec(argv) {
      const r = await container.exec(argv);
      return { code: r.exitCode, stdout: r.stdout, stderr: r.stderr };
    },
    logs: () => log,
    async waitForLog(text, timeoutMs = 5000) {
      const until = Date.now() + timeoutMs;
      while (!log.includes(text) && Date.now() < until)
        await new Promise((r) => setTimeout(r, 50));
      return log.includes(text);
    },
    async stop() {
      stream.destroy();
      await container.stop();
    },
  };
}

/**
 * Conecta con el `ssh` del sistema como lo haría el worker (solo esa identidad, sin agente ni
 * contraseña) y ejecuta `command`. `certificate` = ruta de un certificado para la clave.
 */
export async function sshAs(
  sshd: Pick<TestSshd, 'host' | 'port'>,
  user: string,
  privateKey: string,
  command: string,
  options: { certificate?: string } = {},
): Promise<CommandResult> {
  const dir = await mkdtemp(join(tmpdir(), 'infraward-int-ssh-'));
  try {
    const keyFile = join(dir, 'id');
    await writeFile(keyFile, privateKey, { mode: 0o600 });
    const args = [
      '-F',
      '/dev/null',
      '-i',
      keyFile,
      '-o',
      'IdentitiesOnly=yes',
      '-o',
      'IdentityAgent=none',
      '-o',
      'BatchMode=yes',
      '-o',
      'PasswordAuthentication=no',
      '-o',
      'StrictHostKeyChecking=no',
      '-o',
      'UserKnownHostsFile=/dev/null',
      '-o',
      'LogLevel=ERROR',
      '-o',
      'ConnectTimeout=10',
      '-p',
      String(sshd.port),
    ];
    if (options.certificate) {
      const certFile = join(dir, 'id-cert.pub');
      await writeFile(certFile, options.certificate, { mode: 0o600 });
      args.push('-o', `CertificateFile=${certFile}`);
    }
    args.push(`${user}@${sshd.host}`, command);
    return await new Promise((done) =>
      execFile('ssh', args, { timeout: 30_000 }, (error, stdout, stderr) =>
        done({
          code:
            error === null
              ? 0
              : typeof error.code === 'number'
                ? error.code
                : null,
          stdout,
          stderr,
        }),
      ),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
