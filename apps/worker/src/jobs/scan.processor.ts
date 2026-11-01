import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  IMAGE_ID,
  isSudoDenial,
  type PrivilegedQuery,
} from '@infraward/connectors';
import { Asset, ContainerImage, policyValues } from '@infraward/domain';
import { SecretError, SecretsService } from '@infraward/secrets';
import {
  JOB_NAMES,
  scanDisabledReason,
  SUDOERS_CAPABILITIES,
  sudoersAllows,
  type CollectedFacts,
  type HostScanJobData,
  type HostScanJobResult,
  type ImageScanJobData,
  type ImageScanJobResult,
  type ImageScanStatus,
  type SbomReevaluateJobData,
  type SbomReevaluateJobResult,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DataSource } from 'typeorm';
import { CollectionError } from '../collect/ansible-runner.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { ImageArchiveError, verifyImageArchive } from '../scan/image-archive.js';
import { HostScanner } from '../scan/host-scanner.js';
import { parseCycloneDx } from '../scan/sbom.js';
import { SbomReevaluator } from '../scan/sbom-reevaluator.js';
import { applyEvaluation, findSbom, saveSbom } from '../scan/sbom-store.js';
import { ScanError, SkipScan } from '../scan/scan-errors.js';
import { imageMetaOf, ScanScheduler } from '../scan/scan-scheduler.js';
import { TrivyError } from '../scan/trivy-report.js';
import { TrivyRunner } from '../scan/trivy-runner.js';
import { HostKeyMismatchError, selectHostKey } from '../ssh/host-keys.js';
import { throughPct } from '../ssh/pct.js';
import {
  PROCESS_RUNNER,
  SshClient,
  SshError,
  type ProcessRunner,
} from '../ssh/ssh-client.js';
import { SshIdentities } from '../ssh/ssh-identity.js';
import { AssetRoutes, type AssetRoute } from './asset-routes.js';
import { PrioritizeTrigger } from '../intel/prioritize-trigger.js';
import { reportProgress } from './progress.js';
import { assertFence } from './fence.js';
import { HostSlots } from './host-slots.js';
import { isInterruption } from './job-context.js';
import { makeWorkDir, scanBaseDir } from '../scan/work-dirs.js';

export { ScanError } from '../scan/scan-errors.js';

/** Versión del sudoers que permite `docker save` (consulta `docker-save` del ayudante). */
export const DOCKER_SAVE_SUDOERS_VERSION =
  SUDOERS_CAPABILITIES['docker.save'].version;

export const KNOWN_SCAN_ERRORS = [
  ScanError,
  TrivyError,
  CollectionError,
  SshError,
  HostKeyMismatchError,
  SecretError,
];

/** Versión del sudoers que permite `podman save` (consulta `podman-save` del ayudante). */
export const PODMAN_SAVE_SUDOERS_VERSION = SUDOERS_CAPABILITIES.podman.version;

/** Host desde el que se saca la imagen con `docker save` o `podman save`. */
interface ImageSource {
  host: Asset;
  route: AssetRoute & { pinned: string };
  /**
   * Consultas que la sacan, por orden: `docker-save` en un host Docker; en uno de Podman,
   * `podman-save` como root y en el almacén de cada usuario rootless con contenedores en el host
   * (antes los que usan esta imagen). Se prueba la siguiente si una falla (no la tiene).
   */
  saves: PrivilegedQuery[];
}

/**
 * Consumidor de la cola `scan` (DESIGN §9):
 * - `image.scan` escanea una imagen por su image ID: la saca de un host Docker con `docker save`
 *   (por SSH con el ayudante de root o, en un CT, con `pct exec` desde el nodo) directamente a
 *   disco en un directorio propio del job, genera su SBOM con Trivy en el worker, lo evalúa con
 *   `trivy sbom` y borra el directorio siempre. En los servidores no se deja nada. El SBOM, sus
 *   paquetes y los findings se guardan una vez, en el asset `image`; los contenedores llegan a
 *   ellos con `instance_of`.
 * - `host.scan`: SBOM de un servidor o CT (`HostScanner`).
 * - `sbom.reevaluate`: re-evaluación periódica de los SBOMs guardados (`SbomReevaluator`).
 */
@Injectable()
export class ScanProcessor {
  private readonly logger = new Logger(ScanProcessor.name);
  private readonly scanBase: string;
  private readonly maxBytes: number;
  private readonly timeoutMs: number;

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly ssh: SshClient,
    private readonly routes: AssetRoutes,
    private readonly scheduler: ScanScheduler,
    private readonly trivy: TrivyRunner,
    @Inject(PROCESS_RUNNER) private readonly run: ProcessRunner,
    private readonly identities: SshIdentities,
    private readonly hosts: HostScanner,
    private readonly reevaluator: SbomReevaluator,
    @Optional() private readonly prioritize?: PrioritizeTrigger,
    @Optional() private readonly slots?: HostSlots,
  ) {
    this.scanBase = scanBaseDir(config);
    this.maxBytes = config.get('TRIVY_MAX_IMAGE_SIZE', { infer: true });
    this.timeoutMs = config.get('TRIVY_SCAN_TIMEOUT', { infer: true }) * 1000;
  }

  async process(job: Job): Promise<unknown> {
    const result = await this.dispatch(job);
    // Findings nuevos o cerrados: la prioridad se recalcula (salvo el job del scheduler).
    if (!job.repeatJobKey) await this.prioritize?.request(job.name);
    return result;
  }

  private async dispatch(job: Job): Promise<unknown> {
    switch (job.name) {
      case JOB_NAMES.imageScan:
        return this.imageScan(job as Job<ImageScanJobData, ImageScanJobResult>);
      case JOB_NAMES.hostScan: {
        const { assetId } = job.data as HostScanJobData;
        return this.guard(job, `SBOM de ${assetId}`, () =>
          this.hosts.scan(job as Job<HostScanJobData, HostScanJobResult>),
        );
      }
      case JOB_NAMES.sbomReevaluate:
        // El del job scheduler (id `repeat:…`) solo encola la re-evaluación con un UUID, como la
        // manual: así queda en la Actividad y no se solapan dos (deduplicadas).
        if (job.repeatJobKey)
          return { queued: await this.scheduler.enqueueReevaluation() };
        return this.guard(job, 'Re-evaluación de los SBOMs', () =>
          this.reevaluator.run(
            job as Job<SbomReevaluateJobData, SbomReevaluateJobResult>,
          ),
        );
      default:
        throw new Error(
          `Job desconocido en la cola ${job.queueName}: ${job.name}`,
        );
    }
  }

  /**
   * Ejecuta el job y, si falla, deja en el log y en el job un mensaje apto para mostrarse: el de
   * un error conocido o uno genérico (de un error ajeno, solo el tipo y la traza).
   */
  private async guard<T>(
    job: Job,
    label: string,
    fn: () => Promise<T>,
    onError?: (message: string) => Promise<void>,
  ): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      // Host ocupado, parada de la réplica o ejecución sustituida: no es un fallo del escaneo.
      if (isInterruption(error)) throw error;
      const known = KNOWN_SCAN_ERRORS.some((type) => error instanceof type);
      const message = known
        ? (error as Error).message
        : 'Error interno durante el escaneo';
      if (known) {
        this.logger.warn(`${label}: ${message}`);
      } else {
        // Tipo y traza, nunca el mensaje: un error ajeno podría llevar datos sensibles.
        const { name, stack } = error as Error;
        const frames = stack?.split('\n').slice(1).join('\n') ?? '';
        this.logger.error(`${label}: ${name}\n${frames}`);
      }
      await onError?.(message).catch(() => undefined);
      await reportProgress(job, 100, `Fallo: ${message}`);
      throw new Error(message, { cause: error });
    }
  }

  private async imageScan(
    job: Job<ImageScanJobData, ImageScanJobResult>,
  ): Promise<ImageScanJobResult> {
    const { imageId, backfillHostId } = job.data;
    let interrupted = false;
    try {
      return await this.guard(
        job,
        `Escaneo de ${imageId}`,
        () => this.scan(job),
        (message) =>
          IMAGE_ID.test(imageId)
            ? this.mark(imageId, 'failed', message)
            : Promise.resolve(),
      );
    } catch (error) {
      interrupted = isInterruption(error);
      throw error;
    } finally {
      // Relleno: si no ha quedado SBOM, no se reintenta solo; y sigue con la siguiente del host.
      // Si el job vuelve a la cola (host ocupado, parada), el relleno sigue siendo este.
      if (backfillHostId && IMAGE_ID.test(imageId) && !interrupted)
        await this.scheduler
          .afterBackfill(imageId, backfillHostId, job.id)
          .catch((error: unknown) =>
            this.logger.warn(
              `Relleno de SBOMs tras ${imageId}: ${(error as Error).name}`,
            ),
          );
    }
  }

  private async scan(
    job: Job<ImageScanJobData, ImageScanJobResult>,
  ): Promise<ImageScanJobResult> {
    const { imageId, force = false, backfillHostId } = job.data;
    if (!IMAGE_ID.test(imageId)) throw new ScanError('Image ID no válido');
    const containers = await this.scheduler.containers({ imageId });
    const image = containers.length
      ? await this.scheduler.register(
          imageMetaOf(containers[0].docker),
          containers,
        )
      : await this.db.getRepository(ContainerImage).findOneBy({ imageId });
    if (!image) throw new ScanError('La imagen no está en el inventario');

    // Política de inventario (§10): con el escaneo desactivado no se toca nada (ni el estado).
    const asset = await this.db
      .getRepository(Asset)
      .findOneBy({ id: image.assetId });
    if (asset && !policyValues(asset.effectivePolicy).scanEnabled) {
      const reason = scanDisabledReason(asset.effectivePolicy);
      this.logger.log(`Imagen ${imageId}: ${reason}`);
      await reportProgress(job, 100, `No escaneada: ${reason}`);
      return {
        ...this.result(image, true, containers.length, { created: 0, fixed: 0 }),
        scanReason: reason,
      };
    }

    // Ya escaneada y con SBOM: no se vuelve a analizar (la re-evaluación periódica la mantiene
    // al día). Una escaneada antes de los SBOMs sí se escanea, para tenerlo.
    if (
      image.scanStatus === 'scanned' &&
      !force &&
      (await findSbom(this.db, image.assetId))
    ) {
      this.logger.log(
        `Imagen ${imageId} ya escaneada: no se vuelve a analizar`,
      );
      await reportProgress(job, 100, 'Imagen ya escaneada');
      return this.result(image, true, containers.length, {
        created: 0,
        fixed: 0,
      });
    }

    let dir: string | undefined;
    try {
      // Hosts que la tienen (`stores`), aunque ningún contenedor la use (imágenes sin uso).
      const hostIds = await this.scheduler.hostsOf(imageId);
      // El relleno va de un host en un host: primero el suyo.
      if (backfillHostId && hostIds.includes(backfillHostId))
        hostIds.sort(
          (a, b) => Number(b === backfillHostId) - Number(a === backfillHostId),
        );
      if (hostIds.length === 0)
        throw new SkipScan('Ningún host del inventario tiene esta imagen');
      const size = Math.max(
        0,
        ...containers.map((c) => c.docker.imageSizeBytes ?? 0),
        await this.imageSize(image.assetId),
      );
      if (size > this.maxBytes)
        throw new SkipScan(
          `Supera TRIVY_MAX_IMAGE_SIZE (${gib(size)} > ${gib(this.maxBytes)})`,
        );
      await reportProgress(job, 5, 'Preparando la base de datos de Trivy');
      const dbUpdatedAt = await this.trivy.ensureDb();
      const source = await this.source(hostIds, imageId);
      // Prioridad baja frente al límite por host: tope propio para escaneos y rellenos.
      await this.slots?.acquire(
        source.route.host.id,
        source.route.host.name,
        'scan',
      );
      dir = await makeWorkDir(this.scanBase, 'scan-');
      const tar = join(dir, 'image.tar');
      const deadline = Date.now() + this.timeoutMs;

      await reportProgress(
        job,
        15,
        `Descargando la imagen de ${source.host.name} con ${saveCommand(source.saves[0])}`,
      );
      await this.save(source, imageId, tar, job.id);

      await reportProgress(job, 55, 'Generando el SBOM con Trivy');
      const raw = await this.trivy.sbom(
        { image: tar },
        dir,
        this.left(deadline),
      );
      if (raw === 'timeout') throw this.timeout();
      const parsed = parseCycloneDx(raw);
      // Se evalúa lo mismo que se guarda: la re-evaluación dará los mismos fingerprints.
      const sbomFile = join(dir, 'sbom.json');
      await writeFile(sbomFile, parsed.json, { mode: 0o600 });

      await reportProgress(job, 70, 'Evaluando el SBOM');
      const scan = await this.trivy.evaluate(
        sbomFile,
        dir,
        this.left(deadline),
      );
      if (scan === 'timeout') throw this.timeout();
      const configDigest = parsed.imageId ?? scan.configDigest;
      await this.verifyIdentity(imageId, configDigest, tar);
      await rm(tar, { force: true });

      await reportProgress(job, 90, 'Guardando el SBOM y los findings');
      const saved = await this.db.transaction(async (m) => {
        await assertFence(m);
        await m.update(
          ContainerImage,
          { imageId },
          {
            scanStatus: 'scanned',
            scanReason: null,
            scannedAt: new Date(),
            scanSource: 'docker_save',
            sourceAssetId: source.host.id,
            configDigest,
            trivyVersion: parsed.trivyVersion ?? scan.trivyVersion,
            dbUpdatedAt,
            vulnerabilityCount: scan.vulnerabilities.length,
            sbomBackfillFailedAt: null,
          },
        );
        const stored = await saveSbom(m, image.assetId, parsed, 'docker_save');
        return (
          (await applyEvaluation(m, stored, scan, dbUpdatedAt)) ?? {
            created: 0,
            fixed: 0,
          }
        );
      });
      this.logger.log(
        `Imagen ${imageId} escaneada: ${parsed.packages.length} paquetes, ${scan.vulnerabilities.length} vulnerabilidades, ${containers.length} contenedores, ${saved.created} findings nuevos`,
      );
      await reportProgress(job, 100, 'Escaneo completado');
      const updated = await this.db
        .getRepository(ContainerImage)
        .findOneByOrFail({ imageId });
      return this.result(updated, false, containers.length, saved);
    } catch (error) {
      if (!(error instanceof SkipScan) || isInterruption(error)) throw error;
      this.logger.warn(`Imagen ${imageId} no escaneada: ${error.message}`);
      await this.mark(imageId, 'skipped', error.message);
      await reportProgress(job, 100, `No escaneada: ${error.message}`);
      const skipped = await this.db
        .getRepository(ContainerImage)
        .findOneByOrFail({ imageId });
      return this.result(skipped, false, containers.length, {
        created: 0,
        fixed: 0,
      });
    } finally {
      if (dir) await rm(dir, { recursive: true, force: true });
    }
  }

  /** Tamaño en el host guardado en la ficha de la imagen (`facts.image.sizeBytes`). */
  private async imageSize(assetId: string): Promise<number> {
    const [row]: { size: string | null }[] = await this.db.query(
      `SELECT facts->'image'->>'sizeBytes' AS size FROM assets WHERE id = $1`,
      [assetId],
    );
    const size = Number(row?.size);
    return Number.isSafeInteger(size) && size > 0 ? size : 0;
  }

  /**
   * Elige un host desde el que hacer `docker save`: un CT (por `pct exec`, root sin sudoers) o un
   * servidor con el sudoers que lo permite (v2). Siempre con la huella fijada.
   */
  private async source(
    hostIds: string[],
    imageId: string,
  ): Promise<ImageSource> {
    const reasons: string[] = [];
    for (const hostId of hostIds) {
      const host = await this.db.getRepository(Asset).findOneBy({ id: hostId });
      if (host?.status !== 'active') continue;
      let route: AssetRoute;
      try {
        route = await this.routes.route(host);
      } catch (error) {
        if (!(error instanceof CollectionError)) throw error;
        reasons.push(`${host.name}: ${error.message}`);
        continue;
      }
      if (!route.pinned) {
        reasons.push(`${host.name}: sin host key fijada`);
        continue;
      }
      const version = (
        host.facts.infraward as CollectedFacts['infraward'] | undefined
      )?.sudoersVersion;
      const via = route.via ? 'pct' : 'ssh';
      const candidates = await this.saveQueries(host, imageId);
      const saves = candidates.filter((q) =>
        sudoersAllows(
          q.name === 'podman-save' ? 'podman' : 'docker.save',
          version ?? null,
          via,
        ),
      );
      if (saves.length === 0) {
        const podman = candidates[0]?.name === 'podman-save';
        reasons.push(
          `${host.name}: sudoers desactualizado (v${version ?? '?'} < v${podman ? PODMAN_SAVE_SUDOERS_VERSION : DOCKER_SAVE_SUDOERS_VERSION}): vuelve a ejecutar el script de alta para permitir ${podman ? 'podman' : 'docker'} save`,
        );
        continue;
      }
      return { host, route: { ...route, pinned: route.pinned }, saves };
    }
    throw new SkipScan(
      reasons[0] ?? 'Ningún host activo con la imagen desde el que descargarla',
    );
  }

  /**
   * Cómo sacar la imagen de un host (ver `ImageSource.saves`). Sin rol de Docker ni de Podman
   * (puesto o quitado a mano), `docker save`, como siempre.
   */
  private async saveQueries(
    host: Asset,
    imageId: string,
  ): Promise<PrivilegedQuery[]> {
    const saves: PrivilegedQuery[] = [];
    const podman = host.roles.includes('podman-host');
    if (host.roles.includes('docker-host') || !podman)
      saves.push({ name: 'docker-save', args: [imageId] });
    if (!podman) return saves;
    saves.push({ name: 'podman-save', args: ['root', imageId] });
    const rows: { uid: number }[] = await this.db.query(
      `SELECT (a.facts->'docker'->>'rootlessUid')::int AS uid
         FROM assets a
         JOIN asset_relations r ON r.child_id = a.id AND r.type = 'contains'
        WHERE r.parent_id = $1 AND a.type = 'container' AND a.status = 'active'
          AND a.facts->'docker'->>'engine' = 'podman'
          AND a.facts->'docker'->>'rootlessUid' ~ '^[1-9][0-9]{0,9}$'
        GROUP BY 1
        ORDER BY bool_or(a.facts->'docker'->>'imageId' = $2) DESC, 1`,
      [host.id, imageId],
    );
    for (const { uid } of rows)
      saves.push({ name: 'podman-save', args: [String(uid), imageId] });
    return saves;
  }

  /**
   * `docker save` (o `podman save`) del host directamente a disco, con los límites de tamaño y
   * tiempo. Con varias formas de sacarla (Podman: root y usuarios rootless), la primera que
   * funcione; si ninguna, el error de la primera.
   */
  private async save(
    source: ImageSource,
    imageId: string,
    tar: string,
    jobId: string | undefined,
  ) {
    let first: Error | undefined;
    for (const query of source.saves) {
      await rm(tar, { force: true });
      try {
        await this.saveWith(source, query, tar, jobId);
        // Del almacén de un usuario rootless, el tar lo da un servicio suyo: config y capas tienen
        // que ser los del image ID (Trivy solo comprueba el config).
        if (isRootlessSave(query))
          await verifyImageArchive(tar, imageId).catch((error: unknown) => {
            if (!(error instanceof ImageArchiveError)) throw error;
            throw new ScanError(`${saveCommand(query)}: ${error.message}; no se usa`);
          });
        return;
      } catch (error) {
        // Límites, sudo y fallos de conexión cortan (SkipScan y demás); un save que falla (no
        // tiene la imagen) prueba el siguiente.
        if (!(error instanceof ScanError)) throw error;
        first ??= error;
      }
    }
    throw first ?? new ScanError(`No se pudo sacar ${imageId} de ${source.host.name}`);
  }

  /** Una forma de sacar la imagen (`docker save` o `podman save` de un ámbito). */
  private async saveWith(
    source: ImageSource,
    query: PrivilegedQuery,
    tar: string,
    jobId: string | undefined,
  ) {
    const { connection: target, via, pinned } = source.route;
    const scanned = await this.ssh.scanHostKeys(target.host, target.port);
    const hostKey = selectHostKey(scanned, pinned, []);
    const identity = await this.identities.resolve(source.route, {
      assetId: source.host.id,
      jobId,
    });
    const result = await this.ssh.session(
      target,
      identity,
      hostKey,
      (node) =>
        (via ? throughPct(node, via.vmid) : node).streamToFile(
          query,
          tar,
          { maxBytes: this.maxBytes, timeoutMs: this.timeoutMs },
        ),
      this.timeoutMs / 1000,
    );
    if (result.limit === 'size')
      throw new SkipScan(
        `Supera TRIVY_MAX_IMAGE_SIZE (más de ${gib(this.maxBytes)} transferidos)`,
      );
    if (result.limit === 'time') throw this.timeout();
    if (result.code !== 0) {
      const stderr = result.stderr.trim();
      const command = saveCommand(query);
      if (isSudoDenial(stderr, result.code))
        throw new SkipScan(
          `sudo no permite ${command} en ${source.host.name}: hace falta el sudoers v${query.name === 'podman-save' ? PODMAN_SAVE_SUDOERS_VERSION : DOCKER_SAVE_SUDOERS_VERSION} (vuelve a ejecutar el script de alta)`,
        );
      const line = stderr.split('\n').at(-1)?.slice(0, 300);
      throw new ScanError(
        `${command} falló (código ${result.code})${line ? `: ${line}` : ''}`,
      );
    }
  }

  /**
   * Lo analizado es la imagen pedida: Trivy da el digest del config, que con el almacén clásico
   * es el image ID; con el de containerd, el image ID es el del índice que referencia `index.json`.
   */
  private async verifyIdentity(
    imageId: string,
    configDigest: string | null,
    tar: string,
  ) {
    if (configDigest === imageId) return;
    const index = await this.run('tar', ['-xOf', tar, 'index.json'], 30_000);
    let digests: string[] = [];
    try {
      const parsed = JSON.parse(index.stdout) as {
        manifests?: { digest?: unknown }[];
      };
      digests = (parsed.manifests ?? [])
        .map((m) => m.digest)
        .filter((d): d is string => typeof d === 'string');
    } catch {
      // sin index.json
    }
    if (index.code !== 0 || !digests.includes(imageId))
      throw new ScanError(
        'La imagen descargada no coincide con el image ID pedido: no se guarda',
      );
  }

  /** Tiempo que queda hasta `deadline` (o el error de tiempo agotado). */
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

  /**
   * Marca la imagen como no escaneada o fallida. Si ya tenía un escaneo válido (re-escaneo
   * forzado), lo conserva como `scanned` y solo anota el motivo del último intento.
   */
  private async mark(imageId: string, status: ImageScanStatus, reason: string) {
    const repo = this.db.getRepository(ContainerImage);
    const current = await repo.findOneBy({ imageId });
    if (current?.scanStatus === 'scanned') {
      await repo.update(
        { imageId },
        {
          scanReason: `Último re-escaneo no completado: ${reason}`.slice(
            0,
            500,
          ),
        },
      );
      return;
    }
    await repo.update(
      { imageId },
      { scanStatus: status, scanReason: reason.slice(0, 500) },
    );
  }

  private result(
    image: ContainerImage,
    cached: boolean,
    containers: number,
    synced: { created: number; fixed: number },
  ): ImageScanJobResult {
    return {
      imageId: image.imageId,
      scanStatus: image.scanStatus,
      scanReason: image.scanReason,
      cached,
      vulnerabilityCount: image.vulnerabilityCount,
      containers,
      findingsCreated: synced.created,
      findingsFixed: synced.fixed,
    };
  }
}

/** `154 MiB`, `4.66 GiB`. */
function gib(bytes: number): string {
  return bytes >= 1024 ** 3
    ? `${(bytes / 1024 ** 3).toFixed(2)} GiB`
    : `${Math.round(bytes / 1024 ** 2)} MiB`;
}

/** `podman save` del almacén de un usuario rootless (no de root). */
function isRootlessSave(query: PrivilegedQuery): boolean {
  return query.name === 'podman-save' && query.args?.[0] !== 'root';
}

/** `docker save`, `podman save` o `podman save` de un usuario rootless (para los mensajes). */
function saveCommand(query: PrivilegedQuery | undefined): string {
  if (query?.name !== 'podman-save') return 'docker save';
  const scope = query.args?.[0];
  return scope && scope !== 'root' ? `podman save (uid ${scope})` : 'podman save';
}
