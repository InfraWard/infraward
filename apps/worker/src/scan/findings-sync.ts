import type { ImageVulnerability } from '@infraward/shared-types';
import type { EntityManager } from 'typeorm';

export interface FindingsSyncResult {
  created: number;
  fixed: number;
}

/**
 * Deja los findings de un asset (la imagen, asset `image`) igual que las vulnerabilidades de su
 * último escaneo (DESIGN §9). Se guardan una sola vez por imagen: sus contenedores llegan a
 * ellos con `instance_of`. Idempotente: un re-escaneo actualiza `last_seen_at` en lugar de
 * duplicar (único `(asset_id, fingerprint)`). Lo que ya no está pasa de `open` a `fixed`; lo
 * que reaparece vuelve a `open` (con `opened_at` nuevo); `accepted` se conserva.
 */
export async function syncFindings(
  m: EntityManager,
  assetId: string,
  vulnerabilities: ImageVulnerability[],
): Promise<FindingsSyncResult> {
  let created = 0;
  if (vulnerabilities.length) {
    const rows: { inserted: boolean }[] = await m.query(
      `INSERT INTO findings (asset_id, fingerprint, vulnerability_id, package_name,
                             installed_version, fixed_version, severity, title, fix_status,
                             pkg_path, primary_url, cvss_score)
       SELECT $1, x.fingerprint, x."vulnerabilityId", x."packageName", x."installedVersion",
              x."fixedVersion", x.severity::finding_severity, x.title, x."fixStatus",
              x."pkgPath", x."primaryUrl", x.cvss
         FROM jsonb_to_recordset($2::jsonb) AS x(
                fingerprint text, "vulnerabilityId" text, "packageName" text,
                "installedVersion" text, "fixedVersion" text, severity text, title text,
                "fixStatus" text, "pkgPath" text, "primaryUrl" text, cvss real)
       ON CONFLICT (asset_id, fingerprint) DO UPDATE SET
         fixed_version = EXCLUDED.fixed_version,
         cvss_score = EXCLUDED.cvss_score,
         severity = EXCLUDED.severity,
         title = EXCLUDED.title,
         fix_status = EXCLUDED.fix_status,
         primary_url = EXCLUDED.primary_url,
         last_seen_at = now(),
         status = CASE WHEN findings.status = 'fixed' THEN 'open'::finding_status
                       ELSE findings.status END,
         fixed_at = CASE WHEN findings.status = 'fixed' THEN NULL ELSE findings.fixed_at END,
         -- Reabierto: si vuelve a ser crítico, en KEV y expuesto, se vuelve a avisar.
         kev_alerted_at = CASE WHEN findings.status = 'fixed' THEN NULL
                               ELSE findings.kev_alerted_at END,
         -- Reabierto: vuelve a contar como nuevo (panel «CVEs nuevos desde tu última visita»).
         opened_at = CASE WHEN findings.status = 'fixed' THEN now() ELSE findings.opened_at END
       RETURNING (xmax = 0) AS inserted`,
      [assetId, JSON.stringify(vulnerabilities)],
    );
    created = rows.filter((r) => r.inserted).length;
  }
  const fixed: [unknown[], number] = await m.query(
    `UPDATE findings SET status = 'fixed', fixed_at = now()
      WHERE asset_id = $1 AND status = 'open' AND NOT (fingerprint = ANY($2::text[]))`,
    [assetId, vulnerabilities.map((v) => v.fingerprint)],
  );
  return { created, fixed: fixed[1] };
}
