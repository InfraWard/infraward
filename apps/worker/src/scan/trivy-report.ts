import {
  SEVERITIES,
  type ImageVulnerability,
  type Severity,
} from '@infraward/shared-types';
import { createHash } from 'node:crypto';

/** Lo que se guarda de un informe de `trivy image --format json`. */
export interface TrivyScan {
  /** `Metadata.ImageID`: digest del config de la imagen. */
  configDigest: string | null;
  trivyVersion: string | null;
  vulnerabilities: ImageVulnerability[];
}

/** Error con un mensaje apto para guardarse y mostrarse (sin secretos). */
export class TrivyError extends Error {}

const SEVERITY = new Set<string>(SEVERITIES);

/**
 * Normaliza el informe JSON de Trivy (SchemaVersion 2). El `Target` no se guarda: lleva la ruta
 * temporal del tar. Las vulnerabilidades repetidas (mismo paquete, versión, clase y ruta) se
 * quedan una vez.
 */
export function parseTrivyReport(json: string): TrivyScan {
  let report: unknown;
  try {
    report = JSON.parse(json);
  } catch {
    throw new TrivyError('El informe de Trivy no es JSON');
  }
  const r = record(report);
  if (r?.SchemaVersion !== 2 || !Array.isArray(r.Results ?? []))
    throw new TrivyError('Informe de Trivy no reconocido (SchemaVersion 2)');
  const metadata = record(r.Metadata);
  const byFingerprint = new Map<string, ImageVulnerability>();
  for (const result of (r.Results as unknown[] | undefined) ?? []) {
    const res = record(result);
    if (!res) continue;
    const klass = str(res.Class, 32);
    const pkgType = str(res.Type, 32);
    for (const vuln of Array.isArray(res.Vulnerabilities)
      ? res.Vulnerabilities
      : []) {
      const v = record(vuln);
      const vulnerabilityId = str(v?.VulnerabilityID, 128);
      const packageName = str(v?.PkgName, 255);
      const installedVersion = str(v?.InstalledVersion, 255) ?? '';
      if (!v || !vulnerabilityId || !packageName) continue;
      const pkgPath = str(v.PkgPath, 1024);
      const fingerprint = findingFingerprint([
        vulnerabilityId,
        packageName,
        installedVersion,
        klass ?? '',
        pkgType ?? '',
        pkgPath ?? '',
      ]);
      if (byFingerprint.has(fingerprint)) continue;
      const severity = String(v.Severity ?? '').toUpperCase();
      byFingerprint.set(fingerprint, {
        vulnerabilityId,
        packageName,
        installedVersion,
        fixedVersion: str(v.FixedVersion, 512),
        severity: (SEVERITY.has(severity) ? severity : 'UNKNOWN') as Severity,
        title: str(v.Title, 500),
        fixStatus: str(v.Status, 32),
        class: klass,
        pkgType,
        pkgPath,
        purl: str(record(v.PkgIdentifier)?.PURL, 1024),
        primaryUrl: str(v.PrimaryURL, 1024),
        cvss: cvssScore(v.CVSS),
        fingerprint,
      });
    }
  }
  return {
    configDigest: str(metadata?.ImageID, 71),
    trivyVersion: str(record(r.Trivy)?.Version, 32),
    vulnerabilities: [...byFingerprint.values()],
  };
}

/**
 * CVSS de un CVE en el informe (`CVSS: { nvd: { V3Score, V40Score, V2Score }, ghsa: …, … }`):
 * NVD primero y después la primera fuente con puntuación; en cada una, V3, si no V4.0 o V2.
 */
export function cvssScore(value: unknown): number | null {
  const sources = record(value);
  if (!sources) return null;
  const names = Object.keys(sources).sort((a, b) =>
    a === 'nvd' ? -1 : b === 'nvd' ? 1 : a.localeCompare(b),
  );
  for (const name of names) {
    const s = record(sources[name]);
    for (const key of ['V3Score', 'V40Score', 'V2Score']) {
      const score = s?.[key];
      if (typeof score === 'number' && score > 0 && score <= 10)
        return Math.round(score * 10) / 10;
    }
  }
  return null;
}

/** sha256 hex de los campos que identifican un finding (separados por NUL). */
export function findingFingerprint(parts: string[]): string {
  return createHash('sha256').update(parts.join('\0')).digest('hex');
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function str(value: unknown, max: number): string | null {
  return typeof value === 'string' && value ? value.slice(0, max) : null;
}
