import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { IMAGE_ID, type HostImage } from '@infraward/connectors';
import {
  ContainerImage,
  recomputePolicies,
  scanAutomaticSql,
  scansAutomatically,
} from '@infraward/domain';
import {
  hostScanDeduplicationId,
  JOB_NAMES,
  QUEUE_NAMES,
  SBOM_REEVALUATE_ID,
  scanDeduplicationId,
  type DockerContainerFacts,
  type HostScanJobData,
  type ImageScanJobData,
  type SbomReevaluateJobData,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import { DataSource, type EntityManager } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { JobQueues } from '../jobs/job-queues.js';
import { recordQueued } from '../jobs/job-runs.js';
import { WorkerRedis } from '../redis/redis.js';
import { retireSubtrees } from '../inventory/maintenance.js';

/** Contenedor activo con su imagen. */
export interface ImageContainer {
  id: string;
  docker: DockerContainerFacts;
}

/** Contenedor con el host Docker del que cuelga. */
export interface HostedContainer extends ImageContainer {
  hostId: string;
}

/** Lo que se registra de una imagen (de un contenedor o de `docker images`). */
export interface ImageMeta {
  imageId: string;
  repoTags: string[];
  repoDigests: string[];
  platform: string | null;
  sizeBytes: number | null;
}

/** Prioridad de BullMQ de los escaneos de imágenes sin uso (menor número = antes). */
export const UNUSED_IMAGE_SCAN_PRIORITY = 100;
/** Prioridad del relleno de SBOMs (imágenes escaneadas antes de los SBOMs): lo último. */
export const BACKFILL_SCAN_PRIORITY = 200;

/**
 * Vida del lock de relleno de un host sin noticias de su escaneo (la réplica murió antes de
 * encolar el siguiente). Cada escaneo del relleno lo renueva al terminar.
 */
const BACKFILL_LOCK_MS = 6 * 3600_000;

export function imageMetaOf(docker: DockerContainerFacts): ImageMeta {
  return {
    imageId: docker.imageId,
    repoTags: docker.repoTags,
    repoDigests: docker.repoDigests,
    platform: docker.platform,
    sizeBytes: docker.imageSizeBytes,
  };
}

function hostImageMeta(image: HostImage): ImageMeta {
  return {
    imageId: image.imageId,
    repoTags: image.repoTags,
    repoDigests: image.repoDigests,
    platform: image.platform,
    sizeBytes: image.size,
  };
}

/**
 * Registra las imágenes de los contenedores y decide qué escanear tras descubrirlos (DESIGN §9).
 * Cada imagen es un asset `image` (clave natural = image ID) con su ficha en `container_images`;
 * sus contenedores la enlazan con `instance_of` y sus findings se guardan una sola vez, en la
 * imagen. Las ya escaneadas no se vuelven a analizar; el resto se encola en la cola `scan`
 * (deduplicado por imagen).
 */
@Injectable()
export class ScanScheduler {
  private readonly logger = new Logger(ScanScheduler.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly queues: JobQueues,
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly redis: WorkerRedis,
  ) {}

  private get sbomQueue() {
    return this.queues.get(QUEUE_NAMES.sbom);
  }

  /** Contenedores activos de un host (hijos `contains`) o, sin host, todos los de una imagen. */
  async containers(filter: {
    hostId?: string;
    imageId?: string;
  }): Promise<HostedContainer[]> {
    const rows: {
      id: string;
      docker: DockerContainerFacts;
      host_id: string;
    }[] = await this.db.query(
      `SELECT a.id, a.facts->'docker' AS docker, r.parent_id AS host_id
         FROM assets a
         JOIN asset_relations r ON r.child_id = a.id AND r.type = 'contains'
        WHERE a.type = 'container' AND a.status = 'active'
          AND ($1::uuid IS NULL OR r.parent_id = $1)
          AND ($2::text IS NULL OR a.facts @> jsonb_build_object('docker', jsonb_build_object('imageId', $2::text)))`,
      [filter.hostId ?? null, filter.imageId ?? null],
    );
    return rows
      .filter(
        (r) =>
          typeof r.docker?.imageId === 'string' &&
          IMAGE_ID.test(r.docker.imageId),
      )
      .map((r) => ({ id: r.id, docker: r.docker, hostId: r.host_id }));
  }

  /**
   * Tras descubrir un host Docker (DESIGN §8, §9, §10): registra sus imágenes —las de sus
   * contenedores y, con `hostImages`, también las que no usa nadie—, mantiene `stores` host →
   * imagen y el estado de cada imagen (`missing` cuando ya no la tiene ningún host, `retired`
   * tras `RECONCILE_RETIRE_AFTER` descubrimientos completos de ese host sin volver, `active` al
   * reaparecer) y encola el escaneo de las que no están escaneadas si su política lo permite
   * (escaneo activado y periódico): las que no usa ningún contenedor activo, con prioridad baja.
   * Devuelve los ids de los escaneos encolados.
   */
  async afterDiscovery(
    hostId: string,
    hostImages: { images: HostImage[]; complete: boolean } | undefined,
    parentJobId?: string,
  ): Promise<string[]> {
    const byImage = new Map<string, ImageContainer[]>();
    const metas = new Map<string, ImageMeta>();
    for (const c of await this.containers({ hostId })) {
      const list = byImage.get(c.docker.imageId) ?? [];
      list.push(c);
      byImage.set(c.docker.imageId, list);
      metas.set(c.docker.imageId, imageMetaOf(c.docker));
    }
    for (const image of hostImages?.images ?? [])
      if (IMAGE_ID.test(image.imageId))
        metas.set(image.imageId, hostImageMeta(image));

    const registered: ContainerImage[] = [];
    for (const [imageId, meta] of metas)
      registered.push(await this.register(meta, byImage.get(imageId) ?? []));
    const gone = await this.syncStores(
      hostId,
      [...metas.keys()],
      hostImages?.complete === true,
    );
    if (gone.missing > 0 || gone.retired > 0)
      this.logger.log(
        `Host ${hostId}: ${gone.missing} imágenes ya no están en ningún host (missing), ${gone.retired} retiradas`,
      );

    const queued: string[] = [];
    const used = await this.inUse(registered.map((i) => i.assetId));
    const automatic = await this.automatic(registered.map((i) => i.assetId));
    for (const image of registered) {
      if (!automatic.has(image.assetId)) {
        this.logger.log(
          `Imagen ${image.imageId}: su política no permite escanearla sola (escaneo desactivado o solo bajo demanda)`,
        );
        continue;
      }
      if (image.scanStatus === 'scanned') {
        this.logger.log(
          `Imagen ${image.imageId} ya escaneada: ${byImage.get(image.imageId)?.length ?? 0} contenedores enlazados sin volver a analizarla`,
        );
        continue;
      }
      const jobId = await this.enqueue(
        image.imageId,
        false,
        parentJobId,
        used.has(image.assetId) ? undefined : UNUSED_IMAGE_SCAN_PRIORITY,
      );
      if (jobId) queued.push(jobId);
    }
    return queued;
  }

  /**
   * `stores` host → imagen: añade las de `imageIds` y, si el listado del host está completo,
   * quita las demás. Las que están vuelven a `active` (también las retiradas automáticamente);
   * las que se quedan sin ningún host pasan a `missing` con este host como ámbito, y las que ya
   * faltaban de este host suman una ejecución (a `RECONCILE_RETIRE_AFTER`, `retired`). Al final
   * se recalcula la política efectiva (las imágenes la heredan de quienes las usan).
   */
  private syncStores(
    hostId: string,
    imageIds: string[],
    complete: boolean,
  ): Promise<{ missing: number; retired: number }> {
    return this.db.transaction(async (m) => {
      await m.query(
        `INSERT INTO asset_relations (parent_id, child_id, type)
         SELECT $1, a.id, 'stores' FROM assets a
          WHERE a.type = 'image' AND a.natural_key = ANY($2::text[])
         ON CONFLICT DO NOTHING`,
        [hostId, imageIds],
      );
      await m.query(
        `UPDATE assets SET status = 'active', missing_runs = 0, missing_since = NULL,
                missing_scope_id = NULL, retired_auto = false, updated_at = now()
          WHERE type = 'image' AND natural_key = ANY($1::text[])
            AND (status = 'missing' OR (status = 'retired' AND retired_auto))`,
        [imageIds],
      );
      const result = { missing: 0, retired: 0 };
      if (complete) {
        // Las que ya faltaban de este host (o, de antes de §10, sin ámbito): una ejecución más.
        const [bumped]: [{ id: string; missing_runs: number }[], number] =
          await m.query(
            `UPDATE assets a SET missing_runs = a.missing_runs + 1, updated_at = now()
              WHERE a.type = 'image' AND a.status = 'missing'
                AND (a.missing_scope_id = $1 OR a.missing_scope_id IS NULL)
                AND NOT (a.natural_key = ANY($2::text[]))
                AND NOT EXISTS (SELECT 1 FROM asset_relations s
                                 WHERE s.child_id = a.id AND s.type = 'stores')
             RETURNING a.id, a.missing_runs`,
            [hostId, imageIds],
          );
        const retireAfter = this.config.get('RECONCILE_RETIRE_AFTER', {
          infer: true,
        });
        const retire = bumped
          .filter((b) => b.missing_runs >= retireAfter)
          .map((b) => b.id);
        await retireSubtrees(m, retire);
        result.retired = retire.length;

        // UPDATE y DELETE devuelven `[filas, número de filas]` (también con RETURNING).
        const [removed]: [{ child_id: string }[], number] = await m.query(
          `DELETE FROM asset_relations r USING assets a
            WHERE r.parent_id = $1 AND r.type = 'stores' AND a.id = r.child_id
              AND NOT (a.natural_key = ANY($2::text[]))
           RETURNING r.child_id`,
          [hostId, imageIds],
        );
        if (removed.length) {
          const [, affected]: [unknown, number] = await m.query(
            `UPDATE assets a SET status = 'missing', missing_runs = 1, missing_since = now(),
                    missing_scope_id = $2, updated_at = now()
              WHERE a.id = ANY($1::uuid[]) AND a.status = 'active'
                AND NOT EXISTS (SELECT 1 FROM asset_relations s
                                 WHERE s.child_id = a.id AND s.type = 'stores')`,
            [removed.map((r) => r.child_id), hostId],
          );
          result.missing = affected;
        }
      }
      await recomputePolicies(m);
      return result;
    });
  }

  /** De estas imágenes, las que su política deja escanear solas (activado y periódico). */
  private async automatic(imageAssetIds: string[]): Promise<Set<string>> {
    if (imageAssetIds.length === 0) return new Set();
    const rows: { id: string; effective_policy: unknown }[] =
      await this.db.query(
        `SELECT id, effective_policy FROM assets WHERE id = ANY($1::uuid[])`,
        [imageAssetIds],
      );
    return new Set(
      rows
        .filter((r) =>
          scansAutomatically(
            r.effective_policy as Parameters<typeof scansAutomatically>[0],
          ),
        )
        .map((r) => r.id),
    );
  }

  /** Imágenes (ids de asset) que usa algún contenedor activo. */
  async inUse(imageAssetIds: string[]): Promise<Set<string>> {
    if (imageAssetIds.length === 0) return new Set();
    const rows: { child_id: string }[] = await this.db.query(
      `SELECT DISTINCT i.child_id FROM asset_relations i
         JOIN assets c ON c.id = i.parent_id AND c.status = 'active'
        WHERE i.type = 'instance_of' AND i.child_id = ANY($1::uuid[])`,
      [imageAssetIds],
    );
    return new Set(rows.map((r) => r.child_id));
  }

  /** Hosts que tienen la imagen (`stores`) o un contenedor activo con ella. */
  async hostsOf(imageId: string): Promise<string[]> {
    const rows: { host_id: string }[] = await this.db.query(
      `SELECT s.parent_id AS host_id FROM asset_relations s
         JOIN assets i ON i.id = s.child_id AND i.type = 'image' AND i.natural_key = $1
        WHERE s.type = 'stores'
       UNION
       SELECT r.parent_id FROM assets c
         JOIN asset_relations r ON r.child_id = c.id AND r.type = 'contains'
        WHERE c.type = 'container' AND c.status = 'active'
          AND c.facts @> jsonb_build_object('docker', jsonb_build_object('imageId', $1::text))`,
      [imageId],
    );
    return rows.map((r) => r.host_id);
  }

  /**
   * Alta o actualización de una imagen (asset `image` y su ficha, sin tocar su escaneo) y enlace
   * `instance_of` de los contenedores que la usan (sustituye el de la imagen anterior).
   */
  async register(
    meta: ImageMeta,
    containers: readonly ImageContainer[] = [],
  ): Promise<ContainerImage> {
    return this.db.transaction(async (m) => {
      const [asset]: { id: string }[] = await m.query(
        `INSERT INTO assets (type, discovered_name, status, natural_key)
         VALUES ('image', $1, 'active', $2)
         ON CONFLICT (type, natural_key) WHERE natural_key IS NOT NULL
           DO UPDATE SET updated_at = now()
         RETURNING id`,
        [imageName(meta), meta.imageId],
      );
      await m.query(
        `INSERT INTO container_images (asset_id, image_id, repo_digests, repo_tags, platform)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (image_id) DO UPDATE SET
           repo_digests = CASE WHEN cardinality(EXCLUDED.repo_digests) > 0
                               THEN EXCLUDED.repo_digests ELSE container_images.repo_digests END,
           repo_tags = CASE WHEN cardinality(EXCLUDED.repo_tags) > 0
                            THEN EXCLUDED.repo_tags ELSE container_images.repo_tags END,
           platform = COALESCE(EXCLUDED.platform, container_images.platform),
           updated_at = now()`,
        [
          asset.id,
          meta.imageId,
          meta.repoDigests,
          meta.repoTags,
          meta.platform,
        ],
      );
      // Nombre y facts del asset, a partir de la ficha (conserva tags y digests conocidos) y el
      // tamaño en el host (para el límite de Trivy de las imágenes sin contenedores).
      await m.query(
        `UPDATE assets a SET
           discovered_name = COALESCE(ci.repo_tags[1], a.discovered_name),
           facts = a.facts || jsonb_build_object('image', jsonb_build_object(
             'imageId', ci.image_id, 'repoTags', to_jsonb(ci.repo_tags),
             'repoDigests', to_jsonb(ci.repo_digests), 'platform', ci.platform,
             'sizeBytes', COALESCE($2::bigint, (a.facts->'image'->>'sizeBytes')::bigint)))
          FROM container_images ci
         WHERE ci.asset_id = a.id AND a.id = $1`,
        [asset.id, meta.sizeBytes],
      );
      await linkContainers(
        m,
        asset.id,
        containers.map((c) => c.id),
      );
      return m.getRepository(ContainerImage).findOneByOrFail({
        imageId: meta.imageId,
      });
    });
  }

  /** Id del escaneo encolado (o del que ya estaba en cola), o null si no se pudo encolar. */
  async enqueue(
    imageId: string,
    force = false,
    parentJobId?: string,
    priority?: number,
    backfillHostId?: string,
  ): Promise<string | null> {
    try {
      const job = await this.queues.add(
        JOB_NAMES.imageScan,
        {
          imageId,
          ...(force ? { force } : {}),
          ...(backfillHostId ? { backfillHostId } : {}),
        } satisfies ImageScanJobData,
        {
          jobId: randomUUID(),
          deduplication: { id: scanDeduplicationId(imageId) },
          // El relleno no se reintenta en bucle: si falla, se anota y se sigue con otra.
          attempts: 1,
          ...(priority ? { priority } : {}),
        },
      );
      await recordQueued(this.db, job, parentJobId, this.logger);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar el escaneo de ${imageId}: ${(error as Error).name}`,
      );
      return null;
    }
  }

  /** Encola el SBOM de un servidor o CT (deduplicado por asset); null si no se pudo. */
  async enqueueHostScan(
    assetId: string,
    parentJobId?: string,
  ): Promise<string | null> {
    try {
      const job = await this.queues.add(
        JOB_NAMES.hostScan,
        { assetId } satisfies HostScanJobData,
        {
          jobId: randomUUID(),
          deduplication: { id: hostScanDeduplicationId(assetId) },
        },
      );
      await recordQueued(this.db, job, parentJobId, this.logger);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar el SBOM de ${assetId}: ${(error as Error).name}`,
      );
      return null;
    }
  }

  /** Encola la re-evaluación de los SBOMs (deduplicada); null si no se pudo. */
  async enqueueReevaluation(): Promise<string | null> {
    try {
      const job = await this.queues.add(
        JOB_NAMES.sbomReevaluate,
        {} satisfies SbomReevaluateJobData,
        {
          jobId: randomUUID(),
          deduplication: { id: SBOM_REEVALUATE_ID },
        },
      );
      await recordQueued(this.db, job, null, this.logger);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar la re-evaluación de los SBOMs: ${(error as Error).name}`,
      );
      return null;
    }
  }

  /**
   * Programa la re-evaluación periódica de los SBOMs cada `hours` horas (0 = desactivada). Solo
   * crea o cambia el job scheduler si no existe o cambió el intervalo: con `every`, BullMQ lanza
   * el primero en el acto, y no hace falta re-evaluar en cada arranque del worker.
   */
  async scheduleReevaluation(hours: number): Promise<void> {
    const current = await this.sbomQueue.getJobScheduler(SBOM_REEVALUATE_ID);
    if (hours <= 0) {
      if (current) {
        await this.sbomQueue.removeJobScheduler(SBOM_REEVALUATE_ID);
        this.logger.log('Re-evaluación periódica de los SBOMs desactivada');
      }
      return;
    }
    const every = hours * 3600_000;
    if (current && Number(current.every) === every) return;
    await this.sbomQueue.upsertJobScheduler(
      SBOM_REEVALUATE_ID,
      { every },
      {
        name: JOB_NAMES.sbomReevaluate,
        data: {} satisfies SbomReevaluateJobData,
      },
    );
    this.logger.log(`Re-evaluación de los SBOMs programada cada ${hours} h`);
  }

  /**
   * Relleno de SBOMs (imágenes escaneadas antes de que existieran): encola una imagen por cada
   * host que no tenga ya un relleno en marcha. Cada una, al terminar, encola la siguiente del
   * mismo host (`afterBackfill`): una a la vez por host. Entre réplicas lo garantiza un lock en
   * Redis por host (`backfill:<host>` = escaneo en curso), que pasa de un escaneo al siguiente y
   * caduca solo si la cadena se corta. Devuelve cuántas encoló.
   */
  async startBackfill(parentJobId?: string): Promise<number> {
    let queued = 0;
    for (const { host_id, image_id } of await this.backfillCandidates()) {
      const key = this.backfillKey(host_id);
      // Reservado antes de encolar: dos réplicas a la vez no lanzan dos rellenos del host.
      const reserved = await this.redis.client.set(
        key,
        'starting',
        'PX',
        BACKFILL_LOCK_MS,
        'NX',
      );
      if (reserved !== 'OK') continue;
      const id = await this.enqueue(
        image_id,
        false,
        parentJobId,
        BACKFILL_SCAN_PRIORITY,
        host_id,
      );
      if (id) {
        await this.redis.client.set(key, id, 'PX', BACKFILL_LOCK_MS);
        queued++;
      } else await this.redis.client.del(key);
    }
    return queued;
  }

  /**
   * Tras un escaneo de relleno: si la imagen sigue sin SBOM (falló o no se pudo), se anota para
   * no reintentarla sola; y se encola la siguiente del mismo host, que hereda el lock. Sin más
   * imágenes, el lock se suelta.
   */
  async afterBackfill(
    imageId: string,
    hostId: string,
    parentJobId?: string,
  ): Promise<void> {
    await this.db.query(
      `UPDATE container_images ci SET sbom_backfill_failed_at = now()
        WHERE ci.image_id = $1
          AND NOT EXISTS (SELECT 1 FROM sboms s WHERE s.asset_id = ci.asset_id)`,
      [imageId],
    );
    const key = this.backfillKey(hostId);
    const [next] = await this.backfillCandidates(hostId);
    const id = next
      ? await this.enqueue(
          next.image_id,
          false,
          parentJobId,
          BACKFILL_SCAN_PRIORITY,
          hostId,
        )
      : null;
    if (id) await this.redis.client.set(key, id, 'PX', BACKFILL_LOCK_MS);
    else await this.redis.client.del(key);
  }

  private backfillKey(hostId: string): string {
    return this.redis.key('lock', 'backfill', hostId);
  }

  /**
   * Una imagen por host (activo, por `stores`) escaneada, sin SBOM y sin relleno fallido; de las
   * escaneadas hace más tiempo a las más recientes.
   */
  private backfillCandidates(
    hostId?: string,
  ): Promise<{ host_id: string; image_id: string }[]> {
    // El relleno es automático: solo imágenes con escaneo periódico (§10).
    return this.db.query(
      `SELECT DISTINCT ON (h.id) h.id AS host_id, ci.image_id
         FROM container_images ci
         JOIN assets i ON i.id = ci.asset_id AND i.status = 'active'
                          AND ${scanAutomaticSql('i')}
         JOIN asset_relations s ON s.child_id = i.id AND s.type = 'stores'
         JOIN assets h ON h.id = s.parent_id AND h.status = 'active'
        WHERE ci.scan_status = 'scanned' AND ci.sbom_backfill_failed_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM sboms b WHERE b.asset_id = i.id)
          AND ($1::uuid IS NULL OR h.id = $1)
        ORDER BY h.id, ci.scanned_at NULLS FIRST, ci.image_id`,
      [hostId ?? null],
    );
  }
}

/** Nombre legible de una imagen: su primer tag o el image ID abreviado. */
function imageName(meta: ImageMeta): string {
  return meta.repoTags[0] ?? meta.imageId.slice(0, 19);
}

/** Cada contenedor apunta a una sola imagen: se quita el enlace anterior si era a otra. */
async function linkContainers(
  m: EntityManager,
  imageAssetId: string,
  containerIds: string[],
): Promise<void> {
  if (containerIds.length === 0) return;
  await m.query(
    `DELETE FROM asset_relations
      WHERE type = 'instance_of' AND parent_id = ANY($2::uuid[]) AND child_id <> $1`,
    [imageAssetId, containerIds],
  );
  await m.query(
    `INSERT INTO asset_relations (parent_id, child_id, type)
     SELECT c, $1, 'instance_of' FROM unnest($2::uuid[]) AS c
     ON CONFLICT DO NOTHING`,
    [imageAssetId, containerIds],
  );
}
