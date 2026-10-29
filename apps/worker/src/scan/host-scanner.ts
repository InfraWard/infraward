import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { Asset, policyValues } from '@infraward/domain';
import {
  HOST_SBOM_ASSET_TYPES,
  scanDisabledReason,
  type HostScanJobData,
  type HostScanJobResult,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DataSource } from 'typeorm';
import { CollectionError } from '../collect/ansible-runner.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { AssetRoutes, type AssetRoute } from '../jobs/asset-routes.js';
import { assertFence } from '../jobs/fence.js';
import { HostSlots } from '../jobs/host-slots.js';
import { isInterruption } from '../jobs/job-context.js';
import { reportProgress } from '../jobs/progress.js';
import { selectHostKey } from '../ssh/host-keys.js';
import { throughPct } from '../ssh/pct.js';
import { SshClient } from '../ssh/ssh-client.js';
import { SshIdentities } from '../ssh/ssh-identity.js';
import { copyPackageDatabases } from './host-sbom.js';
import { parseCycloneDx } from './sbom.js';
import {
  applyEvaluation,
  findSbom,
  loadSbomJson,
  saveSbom,
} from './sbom-store.js';
import { ScanError, SkipScan } from './scan-errors.js';
import { TrivyRunner } from './trivy-runner.js';
import { makeWorkDir, scanBaseDir } from './work-dirs.js';

const HOST_TYPES = new Set<string>(HOST_SBOM_ASSET_TYPES);

/**
 * SBOM de un servidor o CT (`host.scan`, DESIGN §9). Trivy nunca se ejecuta en el servidor: el
 * worker copia por SSH, sin sudo (en un CT, con `pct-exec` desde el nodo), solo la identificación
 * del sistema y las BDs de paquetes del SO a un directorio del job, genera el SBOM con
 * `trivy rootfs` sobre esa copia, lo evalúa con `trivy sbom` y borra el directorio siempre. Los
 * findings van en el propio asset. No cubre librerías de lenguajes sueltas en el disco.
 */
@Injectable()
export class HostScanner {
  private readonly logger = new Logger(HostScanner.name);
  private readonly scanBase: string;
  private readonly maxBytes: number;
  private readonly timeoutMs: number;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly ssh: SshClient,
    private readonly routes: AssetRoutes,
    private readonly trivy: TrivyRunner,
    private readonly identities: SshIdentities,
    @Optional() private readonly slots?: HostSlots,
  ) {
    this.scanBase = scanBaseDir(config);
    this.maxBytes = config.get('HOST_SBOM_MAX_SIZE', { infer: true });
    this.timeoutMs = config.get('TRIVY_SCAN_TIMEOUT', { infer: true }) * 1000;
  }

  async scan(
    job: Job<HostScanJobData, HostScanJobResult>,
  ): Promise<HostScanJobResult> {
    const { assetId, force = false } = job.data;
    const asset = await this.db.getRepository(Asset).findOneBy({ id: assetId });
    if (!asset) throw new ScanError('El asset no existe');
    if (
      !HOST_TYPES.has(asset.type) ||
      (asset.type === 'server' && !asset.connection)
    )
      throw new ScanError(
        'Solo se genera el SBOM de servidores con conexión y de CT',
      );

    let dir: string | undefined;
    try {
      if (asset.status !== 'active')
        throw new SkipScan(`El asset está en estado ${asset.status}`);
      if (!policyValues(asset.effectivePolicy).scanEnabled)
        throw new SkipScan(scanDisabledReason(asset.effectivePolicy));
      let route: AssetRoute;
      try {
        route = await this.routes.route(asset);
      } catch (error) {
        if (error instanceof CollectionError) throw new SkipScan(error.message);
        throw error;
      }
      const pinned = route.pinned;
      if (!pinned)
        throw new SkipScan('Sin host key fijada: recógelo antes de escanearlo');

      await reportProgress(job, 5, 'Preparando la base de datos de Trivy');
      const dbUpdatedAt = await this.trivy.ensureDb();
      // Prioridad baja frente al límite por host (un CT cuenta contra su nodo).
      await this.slots?.acquire(route.host.id, route.host.name, 'scan');
      dir = await makeWorkDir(this.scanBase, 'host-');
      const rootfs = join(dir, 'rootfs');
      await mkdir(rootfs, { mode: 0o700 });
      const deadline = Date.now() + this.timeoutMs;

      await reportProgress(
        job,
        15,
        route.via
          ? `Copiando las BDs de paquetes del CT ${route.via.vmid} desde el nodo`
          : 'Copiando las BDs de paquetes',
      );
      const { connection: target, via } = route;
      const scanned = await this.ssh.scanHostKeys(target.host, target.port);
      const hostKey = selectHostKey(scanned, pinned, []);
      const identity = await this.identities.resolve(route, {
        assetId,
        jobId: job.id,
      });
      const copy = await this.ssh.session(
        target,
        identity,
        hostKey,
        (node) =>
          copyPackageDatabases(
            via ? throughPct(node, via.vmid) : node,
            rootfs,
            {
              maxBytes: this.maxBytes,
              timeoutMs: this.timeoutMs,
            },
          ),
        this.timeoutMs / 1000,
      );

      await reportProgress(job, 45, 'Generando el SBOM con Trivy (rootfs)');
      const raw = await this.trivy.sbom({ rootfs }, dir, this.left(deadline));
      if (raw === 'timeout') throw this.timeout();
      const parsed = parseCycloneDx(raw);
      if (!parsed.os && parsed.packages.length === 0)
        throw new SkipScan(
          `Trivy no reconoció el sistema ni ningún paquete (${copy.files.join(', ')})`,
        );

      const existing = await findSbom(this.db, assetId);
      const unchanged = existing?.packagesSha256 === parsed.packagesSha256;
      if (
        existing &&
        unchanged &&
        !force &&
        existing.evaluatedAt &&
        sameDate(existing.dbUpdatedAt, dbUpdatedAt)
      ) {
        await reportProgress(
          job,
          100,
          'Sin cambios: mismos paquetes y misma base de datos de Trivy',
        );
        return this.result(assetId, 'scanned', null, {
          unchanged,
          cached: true,
          packageCount: existing.packageCount,
          vulnerabilityCount: null,
          synced: { created: 0, fixed: 0 },
        });
      }
      // Con los mismos paquetes se evalúa el SBOM guardado (no se reescribe).
      const json =
        existing && unchanged
          ? ((await loadSbomJson(this.db, existing.id)) ?? parsed.json)
          : parsed.json;
      const sbomFile = join(dir, 'sbom.json');
      await writeFile(sbomFile, json, { mode: 0o600 });

      await reportProgress(job, 70, 'Evaluando el SBOM');
      const scan = await this.trivy.evaluate(
        sbomFile,
        dir,
        this.left(deadline),
      );
      if (scan === 'timeout') throw this.timeout();

      await reportProgress(job, 90, 'Guardando el SBOM y los findings');
      const synced = await this.db.transaction(async (m) => {
        await assertFence(m);
        const stored =
          existing && unchanged
            ? existing
            : await saveSbom(m, assetId, parsed, 'rootfs');
        return (
          (await applyEvaluation(m, stored, scan, dbUpdatedAt)) ?? {
            created: 0,
            fixed: 0,
          }
        );
      });
      const note = copy.unreadable.length
        ? ` (sin permiso de lectura: ${copy.unreadable.join(', ')})`
        : '';
      this.logger.log(
        `SBOM de ${assetId}: ${parsed.packages.length} paquetes, ${scan.vulnerabilities.length} vulnerabilidades, ${synced.created} findings nuevos, ${synced.fixed} corregidos${note}`,
      );
      await reportProgress(
        job,
        100,
        `SBOM con ${parsed.packages.length} paquetes y ${scan.vulnerabilities.length} vulnerabilidades${note}`,
      );
      return this.result(assetId, 'scanned', null, {
        unchanged,
        cached: false,
        packageCount: parsed.packages.length,
        vulnerabilityCount: scan.vulnerabilities.length,
        synced,
      });
    } catch (error) {
      if (!(error instanceof SkipScan) || isInterruption(error)) throw error;
      this.logger.warn(`SBOM de ${assetId} no generado: ${error.message}`);
      await reportProgress(job, 100, `No escaneado: ${error.message}`);
      return this.result(assetId, 'skipped', error.message, {
        unchanged: false,
        cached: false,
        packageCount: 0,
        vulnerabilityCount: null,
        synced: { created: 0, fixed: 0 },
      });
    } finally {
      if (dir) await rm(dir, { recursive: true, force: true });
    }
  }

  private left(deadline: number): number {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw this.timeout();
    return remaining;
  }

  private timeout(): SkipScan {
    return new SkipScan(
      `Tiempo agotado tras ${this.timeoutMs / 1000} s (TRIVY_SCAN_TIMEOUT)`,
    );
  }

  private result(
    assetId: string,
    status: HostScanJobResult['status'],
    reason: string | null,
    r: {
      unchanged: boolean;
      cached: boolean;
      packageCount: number;
      vulnerabilityCount: number | null;
      synced: { created: number; fixed: number };
    },
  ): HostScanJobResult {
    return {
      assetId,
      status,
      reason,
      unchanged: r.unchanged,
      cached: r.cached,
      packageCount: r.packageCount,
      vulnerabilityCount: r.vulnerabilityCount,
      findingsCreated: r.synced.created,
      findingsFixed: r.synced.fixed,
    };
  }
}

function sameDate(a: Date | null, b: Date | null): boolean {
  return (a?.getTime() ?? null) === (b?.getTime() ?? null);
}
