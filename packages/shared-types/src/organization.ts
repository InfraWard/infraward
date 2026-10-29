// Organización del inventario (DESIGN §5 y §10): proyectos, colores de tags y nombre visible.

import type { AssetSummary, AssetType } from './assets.js';
import type { Severity } from './findings.js';

/**
 * Paleta de colores de proyectos y tags (`#rrggbb`): tonos medios que se leen sobre fondo claro
 * y oscuro. La API admite cualquier `#rrggbb`; la web solo ofrece estos.
 */
export const ORGANIZATION_COLORS = [
  '#0d9488',
  '#2563eb',
  '#7c3aed',
  '#c026d3',
  '#db2777',
  '#dc2626',
  '#ea580c',
  '#ca8a04',
  '#65a30d',
  '#059669',
  '#0891b2',
  '#64748b',
] as const;

/** Formato de un color: `#rrggbb` (minúsculas o mayúsculas). */
export const COLOR_PATTERN = /^#[0-9a-fA-F]{6}$/;

// --- Tags ---

/** `GET /tags`: tags en uso (o con color) para el autocompletado y sus colores. */
export interface TagInfo {
  tag: string;
  /** Assets no retirados con ese tag. */
  assets: number;
  color: string | null;
}

export interface SetTagStyleRequest {
  /** null = sin color. */
  color: string | null;
}

// --- Proyectos ---

export const PROJECT_NAME_MAX = 100;
export const PROJECT_DESCRIPTION_MAX = 2000;

/**
 * Fila de pertenencia directa de un asset a un proyecto:
 * - `include`: el asset y lo que contiene (salvo excepciones más abajo) entran en el proyecto;
 * - `exclude`: excepción: el asset y lo que contiene salen de ese proyecto aunque lo herede.
 */
export const PROJECT_MEMBERSHIP_MODES = ['include', 'exclude'] as const;
export type ProjectMembershipMode = (typeof PROJECT_MEMBERSHIP_MODES)[number];

/** Resumen de lo que hay en un proyecto (heredado incluido; sin retirados). */
export interface ProjectStats {
  /** Assets no retirados por tipo. */
  assetsByType: Partial<Record<AssetType, number>>;
  assets: number;
  /** Findings `open` por severidad (de assets con el escaneo activado). */
  openFindings: Record<Severity, number>;
  /** Findings `open` CRITICAL y HIGH con parche. */
  fixableFindings: Record<'CRITICAL' | 'HIGH', number>;
  /** CVE distintos con algún finding abierto. */
  openVulnerabilities: number;
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  color: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectWithStats extends Project {
  stats: ProjectStats;
}

/** Fila directa (`include` o `exclude`) con el resumen del asset. */
export interface ProjectMember {
  asset: AssetSummary;
  mode: ProjectMembershipMode;
  createdAt: string;
}

/** `GET /projects/:id`. */
export interface ProjectDetail extends ProjectWithStats {
  members: ProjectMember[];
}

export interface CreateProjectRequest {
  name: string;
  description?: string | null;
  color?: string | null;
}

export type UpdateProjectRequest = Partial<CreateProjectRequest>;

export interface SetProjectMemberRequest {
  mode: ProjectMembershipMode;
}

/**
 * Por qué un asset está en un proyecto:
 * - `direct`: tiene su propia fila `include`;
 * - `inherited`: la hereda de un antepasado `contains` (`from`);
 * - `holders`: imagen: la usa un host o contenedor del proyecto.
 */
export type ProjectMembershipSource =
  | { kind: 'direct' }
  | { kind: 'inherited'; from: AssetSummary }
  | { kind: 'holders' };

/** `GET /assets/:id/projects`. */
export interface AssetProjects {
  /** Proyectos a los que pertenece, con el motivo. */
  projects: (Project & { source: ProjectMembershipSource })[];
  /** Excepciones propias (`exclude`) del asset. */
  excluded: Project[];
}
