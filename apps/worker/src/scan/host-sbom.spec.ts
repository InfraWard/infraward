import type { HostCommandResult } from '@infraward/connectors';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  StreamingHostExec,
  StreamLimits,
  StreamResult,
} from '../ssh/ssh-client.js';
import { copyPackageDatabases, pruneDpkgStatus } from './host-sbom.js';
import { SkipScan } from './scan-errors.js';

/** Host falso: un sistema de ficheros en memoria que entienden `ls -1d --` y `cat --`. */
function fakeHost(
  files: Record<string, string | null>,
  options: { lsStderr?: string; lsCode?: number } = {},
) {
  const argvs: string[][] = [];
  const host: StreamingHostExec = {
    run: (argv): Promise<HostCommandResult> => {
      argvs.push(argv);
      const paths = argv.slice(3);
      const present = paths.filter((p) => p in files);
      return Promise.resolve({
        code: options.lsCode ?? (present.length < paths.length ? 2 : 0),
        stdout: present.map((p) => `${p}\n`).join(''),
        stderr: options.lsStderr ?? '',
      });
    },
    query: () => Promise.reject(new Error('sin sudo')),
    streamToFile: () => Promise.reject(new Error('sin sudo')),
    streamArgvToFile: (
      argv: string[],
      dest: string,
      limits: StreamLimits,
    ): Promise<StreamResult> => {
      argvs.push(argv);
      const content = files[argv[2]];
      if (content === null || content === undefined) {
        writeFileSync(dest, 'a medias');
        return Promise.resolve({
          code: 1,
          bytes: 8,
          stderr: 'cat: Permission denied',
          limit: null,
        });
      }
      if (content.length > limits.maxBytes)
        return Promise.resolve({
          code: null,
          bytes: limits.maxBytes,
          stderr: '',
          limit: 'size',
        });
      writeFileSync(dest, content);
      return Promise.resolve({
        code: 0,
        bytes: content.length,
        stderr: '',
        limit: null,
      });
    },
  };
  return { host, argvs };
}

const LIMITS = { maxBytes: 1024, timeoutMs: 10_000 };

describe('copyPackageDatabases', () => {
  let dest: string;
  beforeEach(() => {
    dest = mkdtempSync(join(tmpdir(), 'host-sbom-'));
  });
  afterEach(() => rmSync(dest, { recursive: true, force: true }));

  it('lista los candidatos y copia con cat, sin sudo, solo los que existen, como ficheros normales', async () => {
    const { host, argvs } = fakeHost({
      '/etc/os-release': 'ID=debian\n',
      '/usr/lib/os-release': 'ID=debian\n',
      '/etc/debian_version': '13.1\n',
      '/var/lib/dpkg/status': 'Package: bash\nVersion: 5.2\n',
      '/etc/shadow': 'root:secreto',
    });
    const copy = await copyPackageDatabases(host, dest, LIMITS);
    expect(copy.files).toEqual([
      'etc/os-release',
      'usr/lib/os-release',
      'etc/debian_version',
      'var/lib/dpkg/status',
    ]);
    expect(copy.unreadable).toEqual([]);
    expect(argvs[0].slice(0, 3)).toEqual(['ls', '-1d', '--']);
    expect(argvs[0]).not.toContain('/etc/shadow');
    expect(argvs.slice(1)).toEqual(
      copy.files.map((f) => ['cat', '--', `/${f}`]),
    );
    expect(argvs.flat()).not.toContain('sudo');
    expect(readFileSync(join(dest, 'var/lib/dpkg/status'), 'utf8')).toContain(
      'bash',
    );
    expect(lstatSync(join(dest, 'etc/os-release')).isFile()).toBe(true);
    expect(existsSync(join(dest, 'etc/shadow'))).toBe(false);
  });

  it('ignora lo que `ls` devuelva fuera de la lista', async () => {
    const { host, argvs } = fakeHost({ '/var/lib/dpkg/status': 'x' });
    const run = host.run.bind(host);
    host.run = async (argv) => {
      const r = await run(argv);
      return { ...r, stdout: `${r.stdout}/etc/shadow\n/../../etc/passwd\n` };
    };
    const copy = await copyPackageDatabases(host, dest, LIMITS);
    expect(copy.files).toEqual(['var/lib/dpkg/status']);
    expect(argvs.slice(1)).toEqual([['cat', '--', '/var/lib/dpkg/status']]);
  });

  it('un fichero que no se puede leer no deja nada a medias; sin ninguna BD de paquetes, se omite', async () => {
    const { host } = fakeHost({
      '/etc/os-release': 'ID=rhel\n',
      '/var/lib/rpm/rpmdb.sqlite': null,
    });
    const error = await copyPackageDatabases(host, dest, LIMITS).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(SkipScan);
    expect((error as Error).message).toBe(
      'No se pudo leer ninguna BD de paquetes (/var/lib/rpm/rpmdb.sqlite)',
    );
    expect(existsSync(join(dest, 'var/lib/rpm/rpmdb.sqlite'))).toBe(false);
  });

  it('sin BDs de paquetes reconocidas (solo os-release), se omite con el motivo', async () => {
    const { host } = fakeHost({ '/etc/os-release': 'ID=nixos\n' });
    await expect(copyPackageDatabases(host, dest, LIMITS)).rejects.toThrow(
      'Ninguna BD de paquetes reconocida (dpkg, apk o rpm)',
    );
  });

  it('el límite de bytes es para el total de la copia', async () => {
    const { host } = fakeHost({
      '/etc/os-release': 'x'.repeat(600),
      '/var/lib/dpkg/status': 'y'.repeat(600),
    });
    await expect(copyPackageDatabases(host, dest, LIMITS)).rejects.toThrow(
      /superan HOST_SBOM_MAX_SIZE/,
    );
  });

  it('en un CT con el nodo sin sudoers v4, el motivo lo dice', async () => {
    const { host } = fakeHost(
      {},
      { lsCode: 1, lsStderr: 'sudo: a password is required\n' },
    );
    await expect(copyPackageDatabases(host, dest, LIMITS)).rejects.toThrow(
      /sudo no permite leer el CT desde el nodo/,
    );
  });

  it('quita de dpkg los paquetes sin ficheros instalados (config-files), como Ansible y dpkg -l', async () => {
    const status = [
      'Package: bash\nStatus: install ok installed\nVersion: 5.2.37-2',
      // Real en un CT de Proxmox: desinstalado, solo queda su configuración (`ic`).
      'Package: ifupdown\nStatus: install ok config-files\nVersion: 0.8.44+deb13u1',
      'Package: vim\nStatus: hold ok installed\nVersion: 2:9.1',
      'Package: viejo\nStatus: deinstall ok config-files\nVersion: 1',
    ].join('\n\n');
    expect(pruneDpkgStatus(status)).toBe(
      [
        'Package: bash\nStatus: install ok installed\nVersion: 5.2.37-2',
        'Package: vim\nStatus: hold ok installed\nVersion: 2:9.1',
      ].join('\n\n'),
    );
    const { host } = fakeHost({ '/var/lib/dpkg/status': `${status}\n` });
    await copyPackageDatabases(host, dest, LIMITS);
    expect(
      readFileSync(join(dest, 'var/lib/dpkg/status'), 'utf8'),
    ).not.toContain('ifupdown');
  });
});
