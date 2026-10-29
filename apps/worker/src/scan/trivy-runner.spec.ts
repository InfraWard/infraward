import type { ConfigService } from '@nestjs/config';
import type { Job } from 'bullmq';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { ProcessRunner } from '../ssh/ssh-client.js';
import { TrivyError } from './trivy-report.js';
import { TrivyRunner } from './trivy-runner.js';
import { runInJobContext } from '../jobs/job-context.js';
import type { DistributedLock } from '../redis/distributed-lock.js';

const NGINX = readFileSync(
  new URL('./fixtures/nginx-1.25.json', import.meta.url),
  'utf8',
);

describe('TrivyRunner', () => {
  let cache: string;
  let work: string;

  beforeEach(() => {
    cache = mkdtempSync(join(tmpdir(), 'trivy-cache-'));
    work = mkdtempSync(join(tmpdir(), 'trivy-work-'));
  });
  afterEach(() => {
    rmSync(cache, { recursive: true, force: true });
    rmSync(work, { recursive: true, force: true });
  });

  /** Lock en memoria con la semántica del de Redis: uno a la vez, los demás esperan. */
  function fakeLocks() {
    const held = new Set<string>();
    const tryAcquire = (name: string) => {
      if (held.has(name)) return null;
      held.add(name);
      return {
        key: name,
        token: 't',
        lost: new AbortController().signal,
        release: () => Promise.resolve(void held.delete(name)),
      };
    };
    return {
      held,
      tryAcquire: (name: string) => Promise.resolve(tryAcquire(name)),
      acquire: async (name: string) => {
        for (;;) {
          const lock = tryAcquire(name);
          if (lock) return lock;
          await new Promise((done) => setTimeout(done, 5));
        }
      },
    };
  }

  function runner(run: ProcessRunner, locks = fakeLocks()) {
    const values: Partial<EnvironmentVariables> = {
      TRIVY_BIN: 'trivy',
      TRIVY_CACHE_DIR: cache,
      TRIVY_DB_MAX_AGE: 12,
      TRIVY_SCAN_TIMEOUT: 60,
    };
    const config = {
      get: (k: keyof EnvironmentVariables) => values[k],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    return new TrivyRunner(config, run, locks as unknown as DistributedLock);
  }

  const metadata = (dir: string, kind: string, downloadedAt: Date) => {
    mkdirSync(join(dir, kind), { recursive: true });
    writeFileSync(
      join(dir, kind, 'metadata.json'),
      JSON.stringify({
        UpdatedAt: '2026-10-09T19:06:47Z',
        DownloadedAt: downloadedAt.toISOString(),
      }),
    );
  };

  /** Una generación publicada a mano (como la dejaría otra réplica). */
  const publish = (name: string, downloadedAt = new Date()) => {
    const dir = join(cache, name);
    metadata(dir, 'db', downloadedAt);
    metadata(dir, 'java-db', downloadedAt);
    rmSync(join(cache, 'current'), { force: true });
    symlinkSync(name, join(cache, 'current'));
    return dir;
  };

  /** Trivy falso: las descargas escriben los metadatos en su --cache-dir; el escaneo, el informe. */
  function fakeTrivy(delayMs = 20) {
    const calls: string[][] = [];
    const run: ProcessRunner = async (_file, args) => {
      calls.push(args);
      await new Promise((done) => setTimeout(done, delayMs));
      const dir = args[args.indexOf('--cache-dir') + 1];
      if (args[1] === '--download-db-only') metadata(dir, 'db', new Date());
      if (args[1] === '--download-java-db-only')
        metadata(dir, 'java-db', new Date());
      const output = args.indexOf('--output');
      if (output > 0) writeFileSync(args[output + 1], NGINX);
      return { code: 0, stdout: '', stderr: '' };
    };
    return { run, calls };
  }

  /** Ejecuta `fn` como un job; al terminar suelta sus recursos, como la envoltura real. */
  const inJob = async <T>(id: string, fn: () => Promise<T>) => {
    const context = {
      job: { id } as Job,
      token: 't',
      worker: 'worker-1',
      signal: new AbortController().signal,
      attempt: null,
      leases: [] as { release(): Promise<void> }[],
    };
    try {
      return await runInJobContext(context as never, fn);
    } finally {
      await Promise.all(context.leases.map((l) => l.release()));
    }
  };

  it('descarga en una generación nueva y la publica en `current`, una sola vez aunque se pida a la vez', async () => {
    const { run, calls } = fakeTrivy();
    const locks = fakeLocks();
    // Dos réplicas con la misma caché: el lock de Redis las serializa.
    const [a, b] = [runner(run, locks), runner(run, locks)];
    const dates = await Promise.all([a.ensureDb(), b.ensureDb()]);
    expect(dates[0]).toEqual(new Date('2026-10-09T19:06:47Z'));
    expect(calls.map((c) => c[1])).toEqual([
      '--download-db-only',
      '--download-java-db-only',
    ]);
    const generation = calls[0]![3]!;
    expect(basename(generation)).toMatch(/^gen-/);
    expect(calls[0]).toEqual([
      'image',
      '--download-db-only',
      '--cache-dir',
      generation,
      '--quiet',
    ]);
    expect(readlinkSync(join(cache, 'current'))).toBe(basename(generation));
    expect(locks.held.size).toBe(0);
  });

  it('no descarga si son recientes; sí si una tiene más de TRIVY_DB_MAX_AGE horas', async () => {
    const { run, calls } = fakeTrivy();
    const first = publish('gen-a');
    await runner(run).ensureDb();
    expect(calls).toEqual([]);

    metadata(first, 'java-db', new Date(Date.now() - 13 * 3600_000));
    await runner(run).ensureDb();
    expect(calls).toHaveLength(2);
    expect(readlinkSync(join(cache, 'current'))).not.toBe('gen-a');
    // La sustituida se conserva (otros escaneos pueden estar usándola) y queda marcada.
    expect(existsSync(join(first, '.superseded'))).toBe(true);
  });

  it('con force descarga aunque esté fresca; dos a la vez (dos réplicas), una sola descarga', async () => {
    const { run, calls } = fakeTrivy();
    publish('gen-a');
    const locks = fakeLocks();
    await runner(run, locks).ensureDb();
    expect(calls).toEqual([]);
    await runner(run, locks).ensureDb(true);
    expect(calls).toHaveLength(2);
    expect(readlinkSync(join(cache, 'current'))).toMatch(/^gen-2/);
    // La segunda espera al lock y ve que la otra publicó después de pedirla: no repite.
    await Promise.all([
      runner(run, locks).ensureDb(true),
      runner(run, locks).ensureDb(true),
    ]);
    expect(calls).toHaveLength(4);
  });

  it('un job sigue con la generación que abrió aunque otra réplica publique otra a mitad', async () => {
    publish('gen-a', new Date(Date.now() - 13 * 3600_000));
    const offline = runner(() =>
      Promise.resolve({ code: 1, stdout: '', stderr: 'sin red' }),
    );
    const { run, calls } = fakeTrivy();
    const other = runner(run);
    await inJob('scan-1', async () => {
      // Sin red: el escaneo sigue con la BD que hay (gen-a)…
      await offline.ensureDb().catch(() => undefined);
      // …mientras otra réplica descarga y publica una nueva.
      await other.ensureDb();
      expect(readlinkSync(join(cache, 'current'))).not.toBe('gen-a');
      await other.evaluate(join(work, 'x.json'), work, 1000);
    });
    const evaluated = calls.at(-1)!;
    expect(evaluated[0]).toBe('sbom');
    expect(evaluated[evaluated.indexOf('--cache-dir') + 1]).toBe(
      realpathSync(join(cache, 'gen-a')),
    );
  });

  it('cada job usa su generación; al descargar se borran las a medias, las viejas sin lectores y la caché antigua', async () => {
    const old = publish('gen-old', new Date(Date.now() - 13 * 3600_000));
    mkdirSync(join(cache, 'gen-partial'));
    mkdirSync(join(cache, 'db'));
    const { run, calls } = fakeTrivy();
    const trivy = runner(run);
    const args = await inJob('scan-1', async () => {
      // Sin red: el job sigue con la generación vieja.
      await runner(() =>
        Promise.resolve({ code: 1, stdout: '', stderr: 'x' }),
      )
        .ensureDb()
        .catch(() => undefined);
      return null;
    });
    expect(args).toBeNull();
    await trivy.ensureDb();
    expect(existsSync(join(cache, 'gen-partial'))).toBe(false);
    expect(existsSync(join(cache, 'db'))).toBe(false);
    // Recién sustituida: se conserva hasta 2 × TRIVY_SCAN_TIMEOUT.
    expect(existsSync(old)).toBe(true);
    const past = new Date(Date.now() - 3 * 60_000);
    utimesSync(join(old, '.superseded'), past, past);
    // Otra descarga (la nueva caduca a mano): ahora sí se borra la vieja.
    const current = realpathSync(join(cache, 'current'));
    metadata(current, 'db', new Date(Date.now() - 13 * 3600_000));
    await trivy.ensureDb();
    expect(existsSync(old)).toBe(false);
    expect(existsSync(current)).toBe(true);
    expect(calls).toHaveLength(4);
  });

  it('una generación con lectores vivos no se borra aunque esté vieja', async () => {
    const old = publish('gen-old', new Date(Date.now() - 13 * 3600_000));
    const { run } = fakeTrivy();
    const trivy = runner(run);
    await inJob('scan-1', async () => {
      await runner(() => Promise.resolve({ code: 1, stdout: '', stderr: 'x' }))
        .ensureDb()
        .catch(() => undefined);
      expect(readdirSync(join(old, '.readers'))).toEqual(['worker-1-scan-1']);
      await trivy.ensureDb();
      const past = new Date(Date.now() - 3 * 60_000);
      utimesSync(join(old, '.superseded'), past, past);
      const current = realpathSync(join(cache, 'current'));
      metadata(current, 'db', new Date(Date.now() - 13 * 3600_000));
      await trivy.ensureDb();
      expect(existsSync(old)).toBe(true);
    });
  });

  it('si la descarga falla, error claro, sin generación a medias y `current` intacto', async () => {
    publish('gen-a', new Date(Date.now() - 13 * 3600_000));
    const run: ProcessRunner = () =>
      Promise.resolve({
        code: 1,
        stdout: '',
        stderr: 'FATAL\tdb download error: TOOMANYREQUESTS\n',
      });
    const locks = fakeLocks();
    await expect(runner(run, locks).ensureDb()).rejects.toThrow(
      new TrivyError(
        'No se pudo descargar la base de datos de Trivy (código 1): FATAL\tdb download error: TOOMANYREQUESTS',
      ),
    );
    expect(readlinkSync(join(cache, 'current'))).toBe('gen-a');
    expect(readdirSync(cache).filter((n) => n.startsWith('gen-'))).toEqual([
      'gen-a',
    ]);
    expect(locks.held.size).toBe(0);
  });

  const OFFLINE = () => [
    '--cache-dir',
    realpathSync(join(cache, 'current')),
    '--cache-backend',
    'memory',
    '--skip-db-update',
    '--skip-java-db-update',
    '--offline-scan',
    '--quiet',
  ];

  it('genera el SBOM de una imagen o de un rootfs sin escáneres, sin tocar la BD ni la red', async () => {
    publish('gen-a');
    const calls: string[][] = [];
    let env: Record<string, string> | undefined;
    const trivy = runner((_file, args, timeout, options) => {
      calls.push(args);
      env = options?.env;
      expect(timeout).toBe(5000);
      writeFileSync(
        args[args.indexOf('--output') + 1],
        '{"bomFormat":"CycloneDX"}',
      );
      return Promise.resolve({ code: 0, stdout: '', stderr: '' });
    });
    const tar = join(work, 'image.tar');
    await expect(trivy.sbom({ image: tar }, work, 5000)).resolves.toBe(
      '{"bomFormat":"CycloneDX"}',
    );
    await trivy.sbom({ rootfs: join(work, 'rootfs') }, work, 5000);
    const output = join(work, 'sbom.trivy.json');
    expect(calls).toEqual([
      [
        'image',
        '--input',
        tar,
        ...OFFLINE(),
        '--format',
        'cyclonedx',
        '--output',
        output,
      ],
      [
        'rootfs',
        join(work, 'rootfs'),
        ...OFFLINE(),
        '--format',
        'cyclonedx',
        '--output',
        output,
      ],
    ]);
    // Sin --scanners: con CycloneDX, Trivy no busca vulnerabilidades ni secretos.
    expect(calls.flat()).not.toContain('--scanners');
    expect(env).toEqual({ HOME: work, TMPDIR: work });
  });

  it('evalúa un SBOM con trivy sbom offline y normaliza el informe', async () => {
    publish('gen-a');
    const { run, calls } = fakeTrivy();
    const sbom = join(work, 'sbom.json');
    const scan = await runner(run).evaluate(sbom, work, 5000);
    expect(scan !== 'timeout' && scan.vulnerabilities).toHaveLength(3);
    expect(calls[0]).toEqual([
      'sbom',
      sbom,
      ...OFFLINE(),
      '--scanners',
      'vuln',
      '--format',
      'json',
      '--output',
      join(work, 'report.json'),
    ]);
  });

  it('tiempo agotado ⇒ "timeout"; otro fallo ⇒ TrivyError', async () => {
    const timeout = runner(() =>
      Promise.resolve({ code: null, stdout: '', stderr: '' }),
    );
    await expect(timeout.evaluate('x.json', work, 10)).resolves.toBe('timeout');
    await expect(timeout.sbom({ image: 'x.tar' }, work, 10)).resolves.toBe(
      'timeout',
    );
    const failing = runner(() =>
      Promise.resolve({ code: 1, stdout: '', stderr: 'unable to open x.tar' }),
    );
    await expect(failing.evaluate('x.json', work, 10)).rejects.toThrow(
      'Trivy falló (código 1): unable to open x.tar',
    );
    await expect(failing.sbom({ image: 'x.tar' }, work, 10)).rejects.toThrow(
      'Trivy falló al generar el SBOM (código 1): unable to open x.tar',
    );
  });
});
