import type { SbomSource } from '@infraward/shared-types';
import { createHash } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import type { DataSource, EntityManager } from 'typeorm';
import { syncFindings, type FindingsSyncResult } from './findings-sync.js';
import type { ParsedSbom } from './sbom.js';
import type { TrivyScan } from './trivy-report.js';

/** Paquetes por INSERT (jsonb_to_recordset). */
const PACKAGE_BATCH = 2000;

/** SBOM guardado: la evaluación comprueba con `contentSha256` que nadie lo reemplazó entretanto. */
export interface StoredSbom {
  id: string;
  assetId: string;
  contentSha256: string;
}

/**
 * Guarda (o reemplaza) el SBOM de un asset y sus paquetes, en la transacción `m` (DESIGN §5). El
 * contenido va comprimido; los campos de la evaluación se vacían hasta que se evalúe.
 */
export async function saveSbom(
  m: EntityManager,
  assetId: string,
  parsed: ParsedSbom,
  source: SbomSource,
): Promise<StoredSbom> {
  const content = gzipSync(parsed.json);
  const contentSha256 = createHash('sha256').update(content).digest('hex');
  const [row]: { id: string }[] = await m.query(
    `INSERT INTO sboms (asset_id, source, spec_version, content, content_sha256, packages_sha256,
                        size_bytes, package_count, os_family, os_name, trivy_version, generated_at)
     VALUES ($1, $2::sbom_source, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
     ON CONFLICT (asset_id) DO UPDATE SET
       source = EXCLUDED.source, spec_version = EXCLUDED.spec_version,
       content = EXCLUDED.content, content_sha256 = EXCLUDED.content_sha256,
       packages_sha256 = EXCLUDED.packages_sha256, size_bytes = EXCLUDED.size_bytes,
       package_count = EXCLUDED.package_count, os_family = EXCLUDED.os_family,
       os_name = EXCLUDED.os_name, trivy_version = EXCLUDED.trivy_version,
       generated_at = EXCLUDED.generated_at, evaluated_at = NULL, db_updated_at = NULL,
       vulnerability_count = NULL, evaluation_error = NULL, updated_at = now()
     RETURNING id`,
    [
      assetId,
      source,
      parsed.specVersion,
      content,
      contentSha256,
      parsed.packagesSha256,
      Buffer.byteLength(parsed.json),
      parsed.packages.length,
      parsed.os?.family ?? null,
      parsed.os?.name || null,
      parsed.trivyVersion,
    ],
  );
  await m.query('DELETE FROM packages WHERE asset_id = $1', [assetId]);
  for (let i = 0; i < parsed.packages.length; i += PACKAGE_BATCH)
    await m.query(
      `INSERT INTO packages (asset_id, sbom_id, name, version, ecosystem, purl, pkg_path)
       SELECT $1, $2, x.name, x.version, x.ecosystem, x.purl, x."pkgPath"
         FROM jsonb_to_recordset($3::jsonb)
           AS x(name text, version text, ecosystem text, purl text, "pkgPath" text)`,
      [
        assetId,
        row.id,
        JSON.stringify(parsed.packages.slice(i, i + PACKAGE_BATCH)),
      ],
    );
  return { id: row.id, assetId, contentSha256 };
}

/** SBOM guardado de un asset (sin contenido), o null. */
export async function findSbom(
  m: EntityManager | DataSource,
  assetId: string,
): Promise<
  | (StoredSbom & {
      packagesSha256: string;
      packageCount: number;
      dbUpdatedAt: Date | null;
      evaluatedAt: Date | null;
    })
  | null
> {
  const [row]: {
    id: string;
    content_sha256: string;
    packages_sha256: string;
    package_count: number;
    db_updated_at: Date | null;
    evaluated_at: Date | null;
  }[] = await m.query(
    `SELECT id, content_sha256, packages_sha256, package_count, db_updated_at, evaluated_at
       FROM sboms WHERE asset_id = $1`,
    [assetId],
  );
  return row
    ? {
        id: row.id,
        assetId,
        contentSha256: row.content_sha256,
        packagesSha256: row.packages_sha256,
        packageCount: row.package_count,
        dbUpdatedAt: row.db_updated_at,
        evaluatedAt: row.evaluated_at,
      }
    : null;
}

/** JSON del SBOM guardado (descomprimido), o null si ya no existe. */
export async function loadSbomJson(
  db: DataSource,
  sbomId: string,
): Promise<string | null> {
  const [row]: { content: Buffer }[] = await db.query(
    'SELECT content FROM sboms WHERE id = $1',
    [sbomId],
  );
  return row ? gunzipSync(row.content).toString('utf8') : null;
}

/**
 * Aplica la evaluación de un SBOM: findings del asset y campos de la evaluación (y la ficha de la
 * imagen, si lo es). Con la fila del SBOM bloqueada; si un escaneo lo reemplazó mientras se
 * evaluaba (otro `content_sha256`) o ya no existe, no toca nada y devuelve null: el SBOM nuevo ya
 * se evaluó con su escaneo.
 */
export async function applyEvaluation(
  m: EntityManager,
  sbom: StoredSbom,
  scan: TrivyScan,
  dbUpdatedAt: Date | null,
): Promise<FindingsSyncResult | null> {
  const [current]: { content_sha256: string }[] = await m.query(
    'SELECT content_sha256 FROM sboms WHERE id = $1 FOR UPDATE',
    [sbom.id],
  );
  if (current?.content_sha256 !== sbom.contentSha256) return null;
  const synced = await syncFindings(m, sbom.assetId, scan.vulnerabilities);
  const count = scan.vulnerabilities.length;
  await m.query(
    `UPDATE sboms SET evaluated_at = now(), db_updated_at = $2, vulnerability_count = $3,
                      evaluation_error = NULL, updated_at = now()
      WHERE id = $1`,
    [sbom.id, dbUpdatedAt, count],
  );
  await m.query(
    `UPDATE container_images SET vulnerability_count = $2, db_updated_at = $3, updated_at = now()
      WHERE asset_id = $1`,
    [sbom.assetId, count, dbUpdatedAt],
  );
  return synced;
}

/** Anota por qué falló la evaluación de un SBOM (los findings se quedan como estaban). */
export async function markEvaluationError(
  db: DataSource,
  sbomId: string,
  reason: string,
): Promise<void> {
  await db.query(
    'UPDATE sboms SET evaluation_error = $2, updated_at = now() WHERE id = $1',
    [sbomId, reason.slice(0, 500)],
  );
}
