import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'node:crypto';
import {
  mkdir,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  utimes,
  writeFile,
} from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { currentJob, throwIfAborted } from '../jobs/job-context.js';
import { DistributedLock } from '../redis/distributed-lock.js';
import {
  PROCESS_RUNNER,
  type ProcessResult,
  type ProcessRunner,
} from '../ssh/ssh-client.js';
import { MAX_SBOM_BYTES } from './sbom.js';
import {
  parseTrivyReport,
  TrivyError,
  type TrivyScan,
} from './trivy-report.js';

/** Tiempo máximo de la descarga de las bases de datos. */
const DB_DOWNLOAD_TIMEOUT_MS = 20 * 60 * 1000;
/** Enlace a la generación vigente de las BDs dentro de la caché. */
export const TRIVY_CURRENT = 'current';
const GENERATION_PREFIX = 'gen-';
/** Marca de una generación sustituida por otra (su fecha cuenta para borrarla). */
const SUPERSEDED = '.superseded';
/** Ejecuciones que leen una generación: un fichero por job, renovado mientras corre. */
const READERS = '.readers';
const READER_TTL_MS = 2 * 60_000;

/**
 * Trivy en el worker (DESIGN §9, §20). Las bases de datos (vulnerabilidades y Java) viven en una
 * caché **compartida por todas las réplicas** (`TRIVY_CACHE_DIR`, mismo volumen), en
 * generaciones: `gen-<fecha>-<id>/` con `db/` y `java-db/`, y el enlace `current` a la vigente.
 * Se descarga como mucho cada `TRIVY_DB_MAX_AGE` horas, bajo un lock de Redis (una réplica a la
 * vez), en una generación nueva que se publica de golpe cambiando `current` (rename atómico).
 * Cada job usa la generación que abrió al empezar hasta terminar (la anota en `.readers/`), así
 * que nadie lee nunca una BD a medio escribir; las sustituidas se borran cuando nadie las lee y
 * llevan más de 2 × `TRIVY_SCAN_TIMEOUT` sustituidas. Los escaneos no tocan la BD
 * (`--skip-db-update`) y usan la caché de capas en memoria, así que pueden ir en paralelo; con
 * `--offline-scan` Trivy no consulta nada fuera.
 */
@Injectable()
export class TrivyRunner {
  private readonly logger = new Logger(TrivyRunner.name);
  readonly cacheDir: string;
  private readonly bin: string;
  private readonly maxAgeMs: number;
  private readonly retentionMs: number;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    @Inject(PROCESS_RUNNER) private readonly run: ProcessRunner,
    private readonly locks: DistributedLock,
  ) {
    this.bin = config.get('TRIVY_BIN', { infer: true });
    this.cacheDir =
      config.get('TRIVY_CACHE_DIR', { infer: true }) ??
      join(homedir(), '.cache', 'infraward', 'trivy');
    this.maxAgeMs = config.get('TRIVY_DB_MAX_AGE', { infer: true }) * 3_600_000;
    this.retentionMs =
      2 * (config.get('TRIVY_SCAN_TIMEOUT', { infer: true }) ?? 900) * 1000;
  }

  /**
   * Descarga las bases de datos si faltan o son viejas (con `force`, aunque no lo sean) y fija
   * para el job en curso la generación vigente. Devuelve la fecha de la de vulnerabilidades.
   */
  async ensureDb(force = false): Promise<Date | null> {
    try {
      if (force || !(await this.fresh(await this.currentGeneration())))
        await this.update(force);
    } finally {
      // Aunque la descarga falle (sin red), el job sigue con la generación que haya.
      const generation = await this.currentGeneration();
      if (generation) await this.pin(generation);
    }
    return this.dbUpdatedAt();
  }

  /** Fecha de la BD de vulnerabilidades que usa el job en curso (null si no hay). */
  async dbUpdatedAt(): Promise<Date | null> {
    const generation = await this.generationInUse();
    return generation
      ? ((await this.metadata(generation, 'db'))?.updatedAt ?? null)
      : null;
  }

  /** Ruta de la generación vigente (sigue el enlace `current`), o null si aún no hay ninguna. */
  async currentGeneration(): Promise<string | null> {
    try {
      return await realpath(join(this.cacheDir, TRIVY_CURRENT));
    } catch {
      return null;
    }
  }

  /**
   * Genera el SBOM CycloneDX (solo inventario: con `--format cyclonedx` y sin `--scanners`, Trivy
   * no busca vulnerabilidades ni secretos) del tar de `docker save` o de la copia de las BDs de
   * paquetes de un servidor. `workDir` es el directorio del job (temporales e informe). Devuelve
   * el JSON o `'timeout'` si se agota el tiempo.
   */
  async sbom(
    target: { image: string } | { rootfs: string },
    workDir: string,
    timeoutMs: number,
  ): Promise<string> {
    const output = join(workDir, 'sbom.trivy.json');
    const args =
      'image' in target
        ? ['image', '--input', target.image]
        : ['rootfs', target.rootfs];
    const result = await this.run(
      this.bin,
      [
        ...args,
        ...this.offline(await this.cacheInUse()),
        '--format',
        'cyclonedx',
        '--output',
        output,
      ],
      timeoutMs,
      { env: { HOME: workDir, TMPDIR: workDir } },
    );
    if (result.code === null) return 'timeout';
    if (result.code !== 0)
      throw new TrivyError(`Trivy falló al generar el SBOM${lastLine(result)}`);
    if ((await stat(output)).size > MAX_SBOM_BYTES)
      throw new TrivyError('SBOM demasiado grande: no se guarda');
    return readFile(output, 'utf8');
  }

  /**
   * Evalúa un SBOM guardado con `trivy sbom` (DESIGN §9): offline, con la BD de la caché y sin
   * conectarse a ninguna máquina. Lo usan el escaneo y la re-evaluación periódica, así que los dos
   * dan los mismos fingerprints. Devuelve `'timeout'` si se agota el tiempo.
   */
  async evaluate(
    sbomFile: string,
    workDir: string,
    timeoutMs: number,
  ): Promise<TrivyScan | 'timeout'> {
    const report = join(workDir, 'report.json');
    const result = await this.run(
      this.bin,
      [
        'sbom',
        sbomFile,
        ...this.offline(await this.cacheInUse()),
        '--scanners',
        'vuln',
        '--format',
        'json',
        '--output',
        report,
      ],
      timeoutMs,
      { env: { HOME: workDir, TMPDIR: workDir } },
    );
    if (result.code === null) return 'timeout';
    if (result.code !== 0)
      throw new TrivyError(`Trivy falló${lastLine(result)}`);
    return parseTrivyReport(await readFile(report, 'utf8'));
  }

  /** Sin tocar la BD ni la red; caché de capas en memoria (escaneos en paralelo). */
  private offline(cacheDir: string): string[] {
    return [
      '--cache-dir',
      cacheDir,
      '--cache-backend',
      'memory',
      '--skip-db-update',
      '--skip-java-db-update',
      '--offline-scan',
      '--quiet',
    ];
  }

  /** Generación del job en curso o, si no fijó ninguna, la vigente. */
  private async generationInUse(): Promise<string | null> {
    return currentJob()?.trivyCache ?? (await this.currentGeneration());
  }

  /** `--cache-dir` de un análisis (sin generación aún, la raíz: Trivy dirá que falta la BD). */
  private async cacheInUse(): Promise<string> {
    return (await this.generationInUse()) ?? this.cacheDir;
  }

  /**
   * El job en curso usará `generation` hasta terminar: lo anota en `<generación>/.readers/` (un
   * fichero que se renueva con el resto de sus recursos) para que no se borre mientras tanto.
   */
  private async pin(generation: string): Promise<void> {
    const context = currentJob();
    // Una vez por job: la primera que abre es la que usa hasta el final.
    if (!context || context.trivyCache) return;
    context.trivyCache = generation;
    const dir = join(generation, READERS);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const file = join(dir, `${context.worker}-${context.job.id ?? 'job'}`);
    await writeFile(file, '', { mode: 0o600 });
    context.leases.push({
      renew: async () => {
        const now = new Date();
        await utimes(file, now, now).catch(() => undefined);
      },
      release: () => rm(file, { force: true }),
    });
  }

  private async fresh(
    generation: string | null,
    maxAgeMs = this.maxAgeMs,
  ): Promise<boolean> {
    if (!generation) return false;
    const now = Date.now();
    for (const kind of ['db', 'java-db'] as const) {
      const meta = await this.metadata(generation, kind);
      if (!meta?.downloadedAt) return false;
      if (now - meta.downloadedAt.getTime() > maxAgeMs) return false;
    }
    return true;
  }

  private async metadata(
    generation: string,
    kind: 'db' | 'java-db',
  ): Promise<{ updatedAt: Date | null; downloadedAt: Date | null } | null> {
    try {
      const meta = JSON.parse(
        await readFile(join(generation, kind, 'metadata.json'), 'utf8'),
      ) as { UpdatedAt?: string; DownloadedAt?: string };
      const date = (v?: string) =>
        v && !Number.isNaN(Date.parse(v)) ? new Date(v) : null;
      return {
        updatedAt: date(meta.UpdatedAt),
        downloadedAt: date(meta.DownloadedAt),
      };
    } catch {
      return null;
    }
  }

  /**
   * Descarga una generación nueva bajo el lock `trivy-db` (las demás réplicas esperan y, al
   * tenerlo, ven que ya está fresca) y la publica cambiando `current` de golpe.
   */
  private async update(force: boolean): Promise<void> {
    const requestedAt = Date.now();
    await mkdir(this.cacheDir, { recursive: true, mode: 0o700 });
    const lock = await this.locks.acquire('trivy-db', {
      waitMs: DB_DOWNLOAD_TIMEOUT_MS + 60_000,
      signal: currentJob()?.signal,
    });
    throwIfAborted();
    if (!lock)
      throw new TrivyError(
        'Otra réplica lleva demasiado tiempo descargando la base de datos de Trivy',
      );
    const generation = join(
      this.cacheDir,
      `${GENERATION_PREFIX}${new Date().toISOString().replace(/[-:.]/g, '')}-${randomUUID().slice(0, 8)}`,
    );
    let published = false;
    try {
      // Otra réplica pudo descargarla mientras esperábamos el lock (forzada: estrictamente
      // después de pedirla; en el mismo milisegundo no cuenta).
      const current = await this.currentGeneration();
      if (
        force
          ? await this.fresh(current, Date.now() - requestedAt - 1)
          : await this.fresh(current)
      )
        return;
      this.logger.log(
        `Descargando las bases de datos de Trivy en ${generation}`,
      );
      await mkdir(generation, { mode: 0o700 });
      for (const flag of ['--download-db-only', '--download-java-db-only']) {
        const result = await this.run(
          this.bin,
          ['image', flag, '--cache-dir', generation, '--quiet'],
          DB_DOWNLOAD_TIMEOUT_MS,
          { env: { HOME: generation } },
        );
        throwIfAborted();
        if (result.code !== 0)
          throw new TrivyError(
            `No se pudo descargar la base de datos de Trivy${lastLine(result)}`,
          );
      }
      if (!(await this.fresh(generation)))
        throw new TrivyError(
          'La descarga de la base de datos de Trivy no dejó sus metadatos',
        );
      if (lock.lost.aborted)
        throw new TrivyError(
          'Se perdió el lock de la descarga de la BD de Trivy: no se publica',
        );
      const previous = await this.currentGeneration();
      // rename atómico sobre el enlace: quien resuelva `current` ve la vieja o la nueva, entera.
      const link = join(this.cacheDir, `.${TRIVY_CURRENT}-${randomUUID()}`);
      await symlink(basename(generation), link);
      await rename(link, join(this.cacheDir, TRIVY_CURRENT));
      published = true;
      if (previous && previous !== generation)
        await writeFile(join(previous, SUPERSEDED), '', { mode: 0o600 });
      this.logger.log(`Bases de datos de Trivy publicadas: ${basename(generation)}`);
      await this.cleanup(generation);
    } finally {
      if (!published) await rm(generation, { recursive: true, force: true });
      await lock.release();
    }
  }

  /**
   * Con el lock de descarga: borra las generaciones a medias (de una descarga que murió), las
   * sustituidas que nadie lee y llevan más que la retención, y la caché anterior a las
   * generaciones (`db/` y `java-db/` en la raíz).
   */
  private async cleanup(current: string): Promise<void> {
    const now = Date.now();
    for (const entry of await readdir(this.cacheDir, { withFileTypes: true })) {
      const path = join(this.cacheDir, entry.name);
      if (path === current) continue;
      if (entry.name.startsWith(`.${TRIVY_CURRENT}-`)) {
        await rm(path, { force: true });
        continue;
      }
      if (['db', 'java-db', '.infraward-db.lock'].includes(entry.name)) {
        await rm(path, { recursive: true, force: true });
        continue;
      }
      if (!entry.isDirectory() || !entry.name.startsWith(GENERATION_PREFIX))
        continue;
      const superseded = await stat(join(path, SUPERSEDED)).catch(() => null);
      if (superseded) {
        if (now - superseded.mtimeMs < this.retentionMs) continue;
        if (await this.hasReaders(path, now)) continue;
      }
      // Sin marca y sin ser la vigente: una descarga a medias (con el lock nadie más descarga).
      await rm(path, { recursive: true, force: true });
      this.logger.log(`Generación de la BD de Trivy borrada: ${entry.name}`);
    }
  }

  private async hasReaders(generation: string, now: number): Promise<boolean> {
    const dir = join(generation, READERS);
    for (const name of await readdir(dir).catch(() => [] as string[])) {
      const info = await stat(join(dir, name)).catch(() => null);
      if (info && now - info.mtimeMs < READER_TTL_MS) return true;
    }
    return false;
  }
}

function lastLine(result: ProcessResult): string {
  if (result.code === null) return ' (tiempo agotado)';
  const line = result.stderr
    .split('\n')
    .map((l) => l.trim())
    .findLast(Boolean);
  return ` (código ${result.code})${line ? `: ${line.slice(0, 300)}` : ''}`;
}
