import type { ConfigService } from '@nestjs/config';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { ScannedHostKey } from './host-keys.js';
import type { PtyProcess } from './pty-bridge.js';
import { SshClient, SshError, type ProcessRunner } from './ssh-client.js';

const HOST_KEY: ScannedHostKey = {
  keyType: 'ssh-ed25519',
  blob: 'AAAAC3NzaC1lZDI1NTE5AAAAIA==',
  type: 'ED25519',
  fingerprint: `SHA256:${'a'.repeat(43)}`,
};
const TARGET = { host: '192.0.2.10', port: 2222, user: 'infraward-admin' };

/**
 * `ssh` falso en el PATH: guarda sus argumentos junto a sí mismo (solo recibe PATH y TERM),
 * escribe el tamaño del PTY, repite lo que se le escribe y sale con 7.
 */
const FAKE_SSH = `#!/bin/sh
printf '%s\\n' "$@" > "$(dirname "$0")/args"
env > "$(dirname "$0")/env"
stty size
IFS= read -r line
echo "eco:$line"
sleep 0.3
stty size
exit 7
`;

describe('SshClient.interactive', () => {
  let tmp: string;
  let bin: string;
  const path = process.env.PATH;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'ssh-pty-'));
    bin = mkdtempSync(join(tmpdir(), 'ssh-pty-bin-'));
    writeFileSync(join(bin, 'ssh'), FAKE_SSH);
    chmodSync(join(bin, 'ssh'), 0o755);
    process.env.PATH = `${bin}:${path}`;
    process.env.CENTINELA_ENV = 'no-debe-pasar';
  });
  afterEach(() => {
    process.env.PATH = path;
    delete process.env.CENTINELA_ENV;
    rmSync(tmp, { recursive: true, force: true });
    rmSync(bin, { recursive: true, force: true });
  });

  function client() {
    const values: Partial<EnvironmentVariables> = { WORKER_TMP_DIR: tmp, SSH_CONNECT_TIMEOUT: 7 };
    const config = {
      get: (k: keyof EnvironmentVariables) => values[k],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    return new SshClient(config, (() => Promise.reject(new Error('sin run'))) as ProcessRunner);
  }

  it('ssh -tt sin maestro, host key fijada, certificado de la persona y el comando entrecomillado', async () => {
    const signed: string[] = [];
    let pty!: PtyProcess;
    let output = '';
    const result = await client().interactive(
      TARGET,
      {
        kind: 'certificate',
        sign: (publicKey) => {
          signed.push(publicKey);
          return Promise.resolve('ssh-ed25519-cert-v01@openssh.com AAAA certificado');
        },
        ttlSeconds: 60,
        renewMarginSeconds: 0,
      },
      HOST_KEY,
      { command: ['sudo', '-n', 'pct', 'enter', '101'], cols: 100, rows: 30 },
      (p) => {
        pty = p;
        p.onData((d) => {
          output += d.toString();
          if (output.includes('30 100') && !output.includes('eco:')) {
            p.resize(132, 40);
            p.write('hola\r');
          }
        });
      },
    );
    expect(pty).toBeDefined();
    expect(result).toEqual({ exitCode: 7, connectError: null });
    expect(output).toContain('eco:hola');
    expect(output).toContain('40 132');
    expect(signed).toHaveLength(1);
    expect(signed[0]).toMatch(/^ssh-ed25519 /);

    const args = readFileSync(join(bin, 'args'), 'utf8').trim().split('\n');
    const opts = args.filter((_, i) => args[i - 1] === '-o');
    expect(opts).toContain('ControlMaster=no');
    expect(opts).toContain('ControlPath=none');
    expect(opts).toContain('StrictHostKeyChecking=yes');
    expect(opts).toContain('BatchMode=yes');
    expect(opts).toContain('IdentityAgent=none');
    expect(opts.some((o) => o.startsWith('CertificateFile='))).toBe(true);
    expect(args).toContain('-tt');
    expect(args.slice(-5)).toEqual(['-l', 'infraward-admin', '--', '192.0.2.10', 'sudo -n pct enter 101']);
    // Ni clave ni certificado sobreviven a la sesión.
    expect(readdirSync(tmp)).toEqual([]);
    // Entorno mínimo: ni el agente SSH ni nada más del proceso; el TERM de xterm.js.
    const env = readFileSync(join(bin, 'env'), 'utf8');
    expect(env).not.toContain('SSH_AUTH_SOCK');
    expect(env).not.toContain('CENTINELA_ENV');
    expect(env).toContain('TERM=xterm-256color');
  });

  it('nunca con el usuario de inventario', async () => {
    await expect(
      client().interactive(
        { ...TARGET, user: 'inventory' },
        { kind: 'key', privateKey: 'x' },
        HOST_KEY,
        { command: null, cols: 80, rows: 24 },
        () => undefined,
      ),
    ).rejects.toThrow(SshError);
  });
});
