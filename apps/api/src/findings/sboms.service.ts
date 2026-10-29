import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Asset, AssetRelation } from '@infraward/domain';
import {
  JOB_NAMES,
  SBOM_REEVALUATE_ID,
  type AssetPackagesPage,
  type EnqueueJobResponse,
  type SbomSummary,
} from '@infraward/shared-types';
import { gunzipSync } from 'node:zlib';
import { DataSource } from 'typeorm';
import { JobsService } from '../jobs/jobs.service.js';
import type { PackageListQueryDto } from './sboms.dto.js';

const DEFAULT_LIMIT = 50;

interface SbomRow {
  asset_id: string;
  source: SbomSummary['source'];
  spec_version: string;
  os_family: string | null;
  os_name: string | null;
  package_count: number;
  size_bytes: number;
  trivy_version: string | null;
  generated_at: Date;
  evaluated_at: Date | null;
  db_updated_at: Date | null;
  vulnerability_count: number | null;
  evaluation_error: string | null;
}

/**
 * SBOMs y paquetes (DESIGN §5, §9). La API solo lee y encola: el SBOM lo generan y re-evalúan el
 * worker y Trivy. Un contenedor no tiene SBOM propio: es el de su imagen (`instance_of`).
 */
@Injectable()
export class SbomsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly jobs: JobsService,
  ) {}

  /** Paquetes del SBOM de un asset, por nombre, con el resumen del SBOM. */
  async packages(
    assetId: string,
    query: PackageListQueryDto,
  ): Promise<AssetPackagesPage> {
    const owner = await this.owner(assetId);
    const sbom = owner ? await this.summary(owner) : null;
    if (!owner || !sbom) return { items: [], total: 0, sbom: null };
    const where = ['asset_id = $1'];
    const params: unknown[] = [owner];
    if (query.q) {
      params.push(`%${query.q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
      where.push(`name ILIKE $${params.length}`);
    }
    if (query.ecosystem) {
      params.push(query.ecosystem);
      where.push(`ecosystem = $${params.length}`);
    }
    params.push(query.limit ?? DEFAULT_LIMIT, query.offset ?? 0);
    const rows: {
      id: string;
      name: string;
      version: string;
      ecosystem: string;
      purl: string | null;
      pkg_path: string | null;
      total: number;
    }[] = await this.db.query(
      `SELECT id, name, version, ecosystem, purl, pkg_path, count(*) OVER ()::int AS total
         FROM packages WHERE ${where.join(' AND ')}
        ORDER BY name, version, pkg_path NULLS FIRST, id
        LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );
    const total =
      rows[0]?.total ??
      (
        (await this.db.query(
          `SELECT count(*)::int AS n FROM packages WHERE ${where.join(' AND ')}`,
          params.slice(0, -2),
        )) as { n: number }[]
      )[0]!.n;
    return {
      items: rows.map((r) => ({
        id: r.id,
        name: r.name,
        version: r.version,
        ecosystem: r.ecosystem,
        purl: r.purl,
        pkgPath: r.pkg_path,
      })),
      total,
      sbom,
    };
  }

  /** SBOM CycloneDX guardado (JSON, sin las etiquetas de la imagen). */
  async cyclonedx(assetId: string): Promise<string> {
    const owner = await this.owner(assetId);
    const [row]: { content: Buffer }[] = owner
      ? await this.db.query('SELECT content FROM sboms WHERE asset_id = $1', [
          owner,
        ])
      : [];
    if (!row) throw new NotFoundException('El asset no tiene SBOM');
    return gunzipSync(row.content).toString('utf8');
  }

  /**
   * Encola ya la re-evaluación de todos los SBOMs (la periódica la programa el worker); con
   * `downloadDb`, el worker descarga antes la BD de Trivy aunque no haya caducado. Deduplicada: si
   * ya hay una pendiente o en curso, es esa.
   */
  reevaluate(downloadDb = false): Promise<EnqueueJobResponse> {
    return this.jobs.enqueue(
      JOB_NAMES.sbomReevaluate,
      downloadDb ? { downloadDb: true } : {},
      { deduplicationId: SBOM_REEVALUATE_ID },
    );
  }

  /** Asset dueño del SBOM: el propio o, en un contenedor, su imagen. */
  private async owner(assetId: string): Promise<string | null> {
    const asset = await this.db
      .getRepository(Asset)
      .findOne({ where: { id: assetId }, select: { id: true, type: true } });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    if (asset.type !== 'container') return asset.id;
    const rel = await this.db
      .getRepository(AssetRelation)
      .findOneBy({ parentId: assetId, type: 'instance_of' });
    return rel?.childId ?? null;
  }

  /** Resumen del SBOM de un asset (sin contenido), o null. */
  async summary(assetId: string): Promise<SbomSummary | null> {
    const [r]: SbomRow[] = await this.db.query(
      `SELECT asset_id, source, spec_version, os_family, os_name, package_count, size_bytes,
              trivy_version, generated_at, evaluated_at, db_updated_at, vulnerability_count,
              evaluation_error
         FROM sboms WHERE asset_id = $1`,
      [assetId],
    );
    if (!r) return null;
    return {
      assetId: r.asset_id,
      source: r.source,
      format: 'cyclonedx',
      specVersion: r.spec_version,
      os: r.os_family ? { family: r.os_family, name: r.os_name ?? '' } : null,
      packageCount: r.package_count,
      sizeBytes: r.size_bytes,
      trivyVersion: r.trivy_version,
      generatedAt: r.generated_at.toISOString(),
      evaluatedAt: r.evaluated_at?.toISOString() ?? null,
      dbUpdatedAt: r.db_updated_at?.toISOString() ?? null,
      vulnerabilityCount: r.vulnerability_count,
      evaluationError: r.evaluation_error,
    };
  }
}
