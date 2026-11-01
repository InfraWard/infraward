import { createHash } from 'node:crypto';
import { TrivyError } from './trivy-report.js';
import { byCodeUnit } from '@infraward/shared-types';

/** Tamaño máximo de un SBOM (JSON sin comprimir). Una imagen grande ronda unos pocos MB. */
export const MAX_SBOM_BYTES = 64 * 1024 * 1024;
/** Componentes como mucho: más es un SBOM anómalo, no se guarda. */
const MAX_COMPONENTS = 200_000;

/** Propiedades que no se guardan: las etiquetas de la imagen pueden llevar secretos (§8). */
const DROPPED_PROPERTY_PREFIX = 'aquasecurity:trivy:Labels:';

/** Paquete del SBOM, como se guarda en `packages`. */
export interface SbomPackage {
  name: string;
  version: string;
  ecosystem: string;
  purl: string | null;
  pkgPath: string | null;
}

/** SBOM CycloneDX de Trivy, listo para guardarse. */
export interface ParsedSbom {
  /** JSON que se guarda y se evalúa: sin las etiquetas de la imagen ni vulnerabilidades. */
  json: string;
  specVersion: string;
  /** `aquasecurity:trivy:ImageID` (digest del config) en el SBOM de una imagen. */
  imageId: string | null;
  /** Sistema detectado (`debian` `12.5`), o null si Trivy no reconoció ninguno. */
  os: { family: string; name: string } | null;
  packages: SbomPackage[];
  /** sha256 de la lista ordenada de paquetes y el SO: igual ⇒ mismo software instalado. */
  packagesSha256: string;
  trivyVersion: string | null;
}

/**
 * Normaliza el CycloneDX JSON que genera Trivy (`--format cyclonedx`). Quita las etiquetas de la
 * imagen (como en los facts de Docker) y cualquier vulnerabilidad: el SBOM guardado es solo
 * inventario y lo vulnerable lo decide `trivy sbom` en cada evaluación. Los componentes
 * `operating-system` y `application` son agrupaciones de Trivy, no paquetes.
 */
export function parseCycloneDx(json: string): ParsedSbom {
  if (Buffer.byteLength(json) > MAX_SBOM_BYTES)
    throw new TrivyError('SBOM demasiado grande: no se guarda');
  let doc: unknown;
  try {
    doc = JSON.parse(json);
  } catch {
    throw new TrivyError('El SBOM de Trivy no es JSON');
  }
  const bom = record(doc);
  const specVersion = str(bom?.specVersion, 16);
  if (bom?.bomFormat !== 'CycloneDX' || !specVersion)
    throw new TrivyError('SBOM de Trivy no reconocido (CycloneDX)');
  delete bom.vulnerabilities;

  const metadata = record(bom.metadata);
  const main = record(metadata?.component);
  if (main && Array.isArray(main.properties))
    main.properties = main.properties.filter(
      (p) => !String(record(p)?.name ?? '').startsWith(DROPPED_PROPERTY_PREFIX),
    );
  const trivy = (
    (record(metadata?.tools)?.components as unknown[] | undefined) ?? []
  )
    .map(record)
    .find((t) => t?.name === 'trivy');

  const components = flatten(bom.components);
  if (components.length > MAX_COMPONENTS)
    throw new TrivyError('SBOM con demasiados componentes: no se guarda');
  let os: ParsedSbom['os'] = null;
  const seen = new Map<string, SbomPackage>();
  for (const c of components) {
    if (c.type === 'operating-system') {
      const family = str(c.name, 64);
      if (family && !os) os = { family, name: str(c.version, 64) ?? '' };
      continue;
    }
    if (c.type !== 'library') continue;
    const pkg = packageOf(c);
    if (pkg) seen.set(packageKey(pkg), pkg);
  }
  const packages = [...seen.values()];
  const lines = packages.map(packageKey).sort(byCodeUnit);
  if (os) lines.unshift(`os\0${os.family}\0${os.name}`);
  return {
    json: JSON.stringify(bom),
    specVersion,
    imageId: property(main, 'aquasecurity:trivy:ImageID', 71),
    os,
    packages,
    packagesSha256: createHash('sha256').update(lines.join('\n')).digest('hex'),
    trivyVersion: str(trivy?.version, 32),
  };
}

/**
 * Nombre como en los findings de Trivy: el grupo de CycloneDX va delante (`@scope/pkg` en npm,
 * `github.com/org/mod` en Go) y en Maven con dos puntos (`org.group:artifact`).
 */
function packageOf(c: Record<string, unknown>): SbomPackage | null {
  const base = str(c.name, 255);
  if (!base) return null;
  const purl = str(c.purl, 1024);
  const ecosystem =
    /^pkg:([a-z0-9.+-]+)\//i.exec(purl ?? '')?.[1].toLowerCase() ??
    property(c, 'aquasecurity:trivy:PkgType', 32) ??
    'unknown';
  const group = str(c.group, 255);
  const name = group
    ? `${group}${ecosystem === 'maven' ? ':' : '/'}${base}`.slice(0, 255)
    : base;
  return {
    name,
    version: str(c.version, 255) ?? '',
    ecosystem: ecosystem.slice(0, 32),
    purl,
    pkgPath: property(c, 'aquasecurity:trivy:FilePath', 1024),
  };
}

function packageKey(p: SbomPackage): string {
  return [p.ecosystem, p.name, p.version, p.purl ?? '', p.pkgPath ?? ''].join(
    '\0',
  );
}

/** Componentes de primer nivel y anidados (Trivy los da planos, CycloneDX permite anidar). */
function flatten(value: unknown): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  const stack = Array.isArray(value) ? [...(value as unknown[])] : [];
  while (stack.length && out.length <= MAX_COMPONENTS) {
    const c = record(stack.pop());
    if (!c) continue;
    out.push(c);
    if (Array.isArray(c.components)) stack.push(...(c.components as unknown[]));
  }
  return out;
}

function property(
  component: Record<string, unknown> | null,
  name: string,
  max: number,
): string | null {
  const props = Array.isArray(component?.properties)
    ? (component.properties as unknown[])
    : [];
  for (const p of props) {
    const r = record(p);
    if (r?.name === name) return str(r.value, max);
  }
  return null;
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function str(value: unknown, max: number): string | null {
  return typeof value === 'string' && value ? value.slice(0, max) : null;
}
