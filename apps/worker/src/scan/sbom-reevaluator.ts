import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { scanEnabledSql } from '@infraward/domain';
import type {
  SbomReevaluateJobData,
  SbomReevaluateJobResult,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { reportProgress } from '../jobs/progress.js';
import {
  applyEvaluation,
  loadSbomJson,
  markEvaluationError,
  type StoredSbom,
} from './sbom-store.js';
import { ScanError } from './scan-errors.js';
import { ScanScheduler } from './scan-scheduler.js';
import { TrivyError } from './trivy-report.js';
import { TrivyRunner } from './trivy-runner.js';
import { makeWorkDir, scanBaseDir } from './work-dirs.js';
import { assertFence } from '../jobs/fence.js';
import { isInterruption, throwIfAborted } from '../jobs/job-context.js';

/**
 * Re-evaluación periódica (`sbom.reevaluate`, DESIGN §9): actualiza la BD de Trivy y evalúa con
 * `trivy sbom` todos los SBOMs guardados de assets no retirados, **sin conectarse a ninguna
 * máquina** (no usa SSH). Sincroniza los findings de cada asset: los nuevos se abren y los que
 * desaparecen pasan a `fixed`. Un SBOM que falla no para al resto. Al final arranca el relleno de
 * SBOMs de las imágenes escaneadas antes de que existieran.
 */
@Injectable()
export class SbomReevaluator {
  private readonly logger = new Logger(SbomReevaluator.name);
  private readonly scanBase: string;
  private readonly timeoutMs: number;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly trivy: TrivyRunner,
    private readonly scheduler: ScanScheduler,
  ) {
    this.scanBase = scanBaseDir(config);
    this.timeoutMs = config.get('TRIVY_SCAN_TIMEOUT', { infer: true }) * 1000;
  }

  async run(
    job: Job<SbomReevaluateJobData, SbomReevaluateJobResult>,
  ): Promise<SbomReevaluateJobResult> {
    const downloadDb = job.data?.downloadDb === true;
    await reportProgress(
      job,
      2,
      downloadDb
        ? 'Descargando la base de datos de Trivy'
        : 'Actualizando la base de datos de Trivy',
    );
    let dbUpdateError: string | null = null;
    try {
      await this.trivy.ensureDb(downloadDb);
    } catch (error) {
      if (!(error instanceof TrivyError)) throw error;
      // Sin red: se evalúa con la BD que haya.
      dbUpdateError = error.message;
      this.logger.warn(`${error.message}: se evalúa con la BD de la caché`);
    }
    const dbUpdatedAt = await this.trivy.dbUpdatedAt();
    if (!dbUpdatedAt)
      throw new ScanError(
        `Sin base de datos de Trivy en la caché${dbUpdateError ? `: ${dbUpdateError}` : ''}`,
      );

    const sboms: { id: string; asset_id: string; content_sha256: string }[] =
      await this.db.query(
        `SELECT s.id, s.asset_id, s.content_sha256 FROM sboms s
           JOIN assets a ON a.id = s.asset_id
          WHERE a.status <> 'retired' AND ${scanEnabledSql('a')}
          ORDER BY s.asset_id`,
      );
    const result: SbomReevaluateJobResult = {
      sboms: sboms.length,
      evaluated: 0,
      superseded: 0,
      failed: 0,
      findingsCreated: 0,
      findingsFixed: 0,
      dbUpdatedAt: dbUpdatedAt.toISOString(),
      dbUpdateError,
      backfillQueued: 0,
    };
    const dir = await makeWorkDir(this.scanBase, 'reevaluate-');
    try {
      for (const [i, row] of sboms.entries()) {
        // Lo que se lanza tras un aborto ya no se mata: el bucle para aquí.
        throwIfAborted();
        const sbom: StoredSbom = {
          id: row.id,
          assetId: row.asset_id,
          contentSha256: row.content_sha256,
        };
        await reportProgress(
          job,
          5 + Math.floor((85 * i) / sboms.length),
          `Evaluando SBOM ${i + 1} de ${sboms.length}`,
        );
        const outcome = await this.evaluate(sbom, dir, dbUpdatedAt);
        if (outcome === 'superseded') result.superseded++;
        else if (outcome === 'failed') result.failed++;
        else {
          result.evaluated++;
          result.findingsCreated += outcome.created;
          result.findingsFixed += outcome.fixed;
        }
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }

    await reportProgress(job, 95, 'Encolando el relleno de SBOMs de imágenes');
    result.backfillQueued = await this.scheduler.startBackfill(job.id);
    const summary = `${result.evaluated} de ${result.sboms} SBOMs evaluados: ${result.findingsCreated} findings nuevos y ${result.findingsFixed} corregidos${result.failed ? `, ${result.failed} con error` : ''}`;
    this.logger.log(
      `Re-evaluación: ${summary}; ${result.backfillQueued} rellenos encolados`,
    );
    await reportProgress(job, 100, summary);
    return result;
  }

  /** Evalúa un SBOM; los errores se anotan en el SBOM y no paran al resto. */
  private async evaluate(
    sbom: StoredSbom,
    dir: string,
    dbUpdatedAt: Date,
  ): Promise<{ created: number; fixed: number } | 'superseded' | 'failed'> {
    const file = join(dir, `${sbom.id}.json`);
    try {
      const json = await loadSbomJson(this.db, sbom.id);
      if (json === null) return 'superseded';
      await writeFile(file, json, { mode: 0o600 });
      const scan = await this.trivy.evaluate(file, dir, this.timeoutMs);
      if (scan === 'timeout')
        throw new ScanError(
          `Tiempo agotado tras ${this.timeoutMs / 1000} s (TRIVY_SCAN_TIMEOUT)`,
        );
      const synced = await this.db.transaction(async (m) => {
        await assertFence(m);
        return applyEvaluation(m, sbom, scan, dbUpdatedAt);
      });
      return synced ?? 'superseded';
    } catch (error) {
      // Parada de la réplica: no se anota como error del SBOM; la re-evaluación vuelve a la cola.
      if (isInterruption(error)) throw error;
      const known = error instanceof ScanError || error instanceof TrivyError;
      const message = known
        ? (error as Error).message
        : 'Error interno al evaluar el SBOM';
      if (known) this.logger.warn(`SBOM del asset ${sbom.assetId}: ${message}`);
      else
        this.logger.error(
          `SBOM del asset ${sbom.assetId}: ${(error as Error).name}`,
        );
      await markEvaluationError(this.db, sbom.id, message).catch(
        () => undefined,
      );
      return 'failed';
    } finally {
      await rm(file, { force: true });
      await rm(join(dir, 'report.json'), { force: true });
    }
  }
}
