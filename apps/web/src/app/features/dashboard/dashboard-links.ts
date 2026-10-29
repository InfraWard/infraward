import {
  ASSET_STATUSES,
  ASSET_TYPES,
  formatSearchTerm,
  TREE_HIDDEN_ASSET_TYPES,
  type AssetStatus,
  type AssetType,
  type AttentionKind,
} from '@infraward/shared-types';
import {
  ASSET_STATUS_LABELS,
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
} from '../../shared/labels';

/** Enlace del panel a una sección ya filtrada. */
export interface DashboardLink {
  path: string;
  queryParams?: Record<string, string>;
}

/** Filtros del inventario que entiende `/inventory?…` (ver `tree-nodes.ts`). */
export const LINKS = {
  type: (type: AssetType): DashboardLink => ({
    path: '/inventory',
    queryParams: { type },
  }),
  status: (status: AssetStatus): DashboardLink => ({
    path: '/inventory',
    queryParams: { status },
  }),
  inventory: { path: '/inventory' },
  pending: {
    path: '/inventory',
    queryParams: { status: 'pending_enrollment' },
  },
  sudoers: { path: '/inventory', queryParams: { attention: 'sudoers' } },
  partial: { path: '/inventory', queryParams: { attention: 'partial' } },
  duplicate: { path: '/inventory', queryParams: { attention: 'duplicate' } },
  clone: { path: '/inventory', queryParams: { attention: 'clone' } },
  domainExpiring: {
    path: '/inventory',
    queryParams: { attention: 'domain-expiring' },
  },
  dnsDangling: {
    path: '/inventory',
    queryParams: { attention: 'dns-dangling' },
  },
  dnsUnknown: {
    path: '/inventory',
    queryParams: { attention: 'dns-unknown' },
  },
  certExpiring: {
    path: '/inventory',
    queryParams: { attention: 'cert-expiring' },
  },
  sshCa: { path: '/inventory', queryParams: { attention: 'ssh-ca' } },
  sshPassword: {
    path: '/inventory',
    queryParams: { attention: 'ssh-password' },
  },
  vault: { path: '/vault' },
  failed: { path: '/activity', queryParams: { state: 'failed' } },
  running: { path: '/activity', queryParams: { state: 'running' } },
  activity: { path: '/activity' },
  // Sin parámetros: la vista principal (prioridad ≥ media, sin ruido) es lo que cuenta el panel.
  vulnerabilities: { path: '/vulnerabilities' },
  newVulnerabilities: { path: '/vulnerabilities', queryParams: { new: '1' } },
} satisfies Record<
  string,
  | DashboardLink
  | ((t: AssetType) => DashboardLink)
  | ((s: AssetStatus) => DashboardLink)
>;

/** Enlace de cada aviso del widget `attention`. */
export const ATTENTION_LINK: Record<AttentionKind, keyof typeof LINKS> = {
  duplicates: 'duplicate',
  certificatesExpiring: 'certExpiring',
  domainsExpiring: 'domainExpiring',
  dnsDangling: 'dnsDangling',
  dnsUnknown: 'dnsUnknown',
  clones: 'clone',
  sshCaOutdated: 'sshCa',
  sshdPasswordLogin: 'sshPassword',
  vaultRotationOverdue: 'vault',
  sudoersOutdated: 'sudoers',
  partialCollection: 'partial',
  failedJobs: 'failed',
};

/** Ámbito de los enlaces: el del widget (proyecto, tags y tipos). */
export interface LinkScope {
  project?: string;
  tags?: readonly string[];
  types?: readonly AssetType[];
}

export type DashboardLinks = {
  [K in keyof typeof LINKS]: (typeof LINKS)[K] extends (
    t: never,
  ) => DashboardLink
    ? (typeof LINKS)[K]
    : DashboardLink;
};

/** Los tags y tipos con la sintaxis de búsqueda del inventario y de vulnerabilidades. */
export function scopeQuery(scope: LinkScope): string | undefined {
  const terms = [
    ...(scope.tags ?? []).map((t) => formatSearchTerm('tag', t)),
    ...(scope.types ?? []).map((t) => formatSearchTerm('tipo', t)),
  ];
  return terms.length ? terms.join(' ') : undefined;
}

/**
 * Con ámbito, los enlaces al inventario y a vulnerabilidades lo conservan (`?project=` y los
 * tags y tipos en `?q=`); la actividad y la caja fuerte, no (no tienen esos filtros).
 */
function withScope(link: DashboardLink, scope: LinkScope): DashboardLink {
  if (link.path !== '/inventory' && link.path !== '/vulnerabilities')
    return link;
  const q = scopeQuery(scope);
  if (!scope.project && !q) return link;
  return {
    ...link,
    queryParams: {
      ...link.queryParams,
      ...(scope.project ? { project: scope.project } : {}),
      ...(q ? { q } : {}),
    },
  };
}

export function dashboardLinks(scope: LinkScope = {}): DashboardLinks {
  const out = {} as Record<string, unknown>;
  for (const [key, link] of Object.entries(LINKS))
    out[key] =
      typeof link === 'function'
        ? (v: AssetType & AssetStatus) => withScope(link(v), scope)
        : withScope(link, scope);
  return out as DashboardLinks;
}

export interface CountTile {
  key: string;
  label: string;
  icon: string;
  count: number;
  /** null en los tipos que no salen en el árbol (imágenes, volúmenes, redes). */
  link: DashboardLink | null;
}

const STATUS_ICONS: Record<AssetStatus, string> = {
  pending_enrollment: 'bi-hourglass-split',
  active: 'bi-check-circle',
  missing: 'bi-question-circle',
  retired: 'bi-archive',
};

/** Tipos o estados con algún asset, en el orden de siempre. */
export function countTiles(
  groupBy: 'type' | 'status',
  counts: Partial<Record<string, number>>,
  links: DashboardLinks = dashboardLinks(),
): CountTile[] {
  if (groupBy === 'status')
    return ASSET_STATUSES.filter((s) => (counts[s] ?? 0) > 0).map((s) => ({
      key: s,
      label: ASSET_STATUS_LABELS[s],
      icon: STATUS_ICONS[s],
      count: counts[s]!,
      link: links.status(s),
    }));
  return ASSET_TYPES.filter((t) => (counts[t] ?? 0) > 0).map((t) => ({
    key: t,
    label: ASSET_TYPE_LABELS[t],
    icon: ASSET_TYPE_ICONS[t],
    count: counts[t]!,
    link: (TREE_HIDDEN_ASSET_TYPES as readonly string[]).includes(t)
      ? null
      : links.type(t),
  }));
}
