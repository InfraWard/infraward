import {
  ASSET_RUNTIME_STATES,
  ASSET_STATUSES,
  ASSET_TYPES,
  type AssetRuntimeState,
  type AssetStatus,
  type AssetTreeSummaryNode,
  type AssetType,
} from './assets.js';
import { SEVERITIES, type Severity } from './findings.js';
import { PRIORITY_BANDS, type PriorityBand } from './priority.js';

/**
 * Sintaxis de búsqueda del inventario y de vulnerabilidades (DESIGN §15): `tag:prod nombre:web
 * -estado:retirado "texto libre"`. Un único parser para la web (chips, autocompletado) y la API
 * (que recibe la consulta en `q`): nunca lanza; lo que no entiende lo ignora y lo devuelve como
 * aviso.
 */

export const SEARCH_SCOPES = ['inventory', 'vulnerabilities'] as const;
export type SearchScope = (typeof SEARCH_SCOPES)[number];

export const SEARCH_KEYS = [
  'tag',
  'name',
  'type',
  'status',
  'role',
  'project',
  'site',
  'ip',
  'cve',
  'package',
  'severity',
  'priority',
] as const;
export type SearchKey = (typeof SEARCH_KEYS)[number];

export interface SearchKeyInfo {
  key: SearchKey;
  /** Lo que se puede escribir antes de `:`; el primero es el que sugiere el autocompletado. */
  aliases: readonly string[];
  scopes: readonly SearchScope[];
  /** Qué hace, para el autocompletado. */
  description: string;
  /** Reconocida pero aún sin datos (sitios: §18): se ignora con aviso. */
  unsupported?: boolean;
}

const BOTH: readonly SearchScope[] = SEARCH_SCOPES;
const VULNS: readonly SearchScope[] = ['vulnerabilities'];

export const SEARCH_KEY_INFO: readonly SearchKeyInfo[] = [
  { key: 'tag', aliases: ['tag'], scopes: BOTH, description: 'Tag exacto' },
  {
    key: 'name',
    aliases: ['nombre', 'name'],
    scopes: BOTH,
    description: 'Parte del nombre (visible o descubierto)',
  },
  {
    key: 'type',
    aliases: ['tipo', 'type'],
    scopes: BOTH,
    description: 'Tipo de asset',
  },
  {
    key: 'status',
    aliases: ['estado', 'status'],
    scopes: BOTH,
    description: 'Estado de inventario o de ejecución',
  },
  {
    key: 'role',
    aliases: ['rol', 'role'],
    scopes: BOTH,
    description: 'Rol exacto',
  },
  {
    key: 'project',
    aliases: ['proyecto', 'project'],
    scopes: BOTH,
    description: 'Proyecto (por nombre)',
  },
  {
    key: 'site',
    aliases: ['sitio', 'site'],
    scopes: BOTH,
    description: 'Sitio (aún no hay sitios)',
    unsupported: true,
  },
  {
    key: 'ip',
    aliases: ['ip'],
    scopes: BOTH,
    description: 'IP exacta, prefijo (10.0.) o red (10.0.0.0/24)',
  },
  {
    key: 'cve',
    aliases: ['cve'],
    scopes: VULNS,
    description: 'CVE (por prefijo)',
  },
  {
    key: 'package',
    aliases: ['paquete', 'package'],
    scopes: VULNS,
    description: 'Parte del nombre del paquete',
  },
  {
    key: 'severity',
    aliases: ['severidad', 'severity'],
    scopes: VULNS,
    description: 'Severidad',
  },
  {
    key: 'priority',
    aliases: ['prioridad', 'priority'],
    scopes: VULNS,
    description: 'Prioridad (urgente, alta, media, baja)',
  },
];

/** Las claves de asset que en vulnerabilidades se aplican al asset afectado. */
export const ASSET_SEARCH_KEYS = [
  'tag',
  'name',
  'type',
  'status',
  'role',
  'project',
  'ip',
] as const satisfies readonly SearchKey[];

export const SEARCH_QUERY_MAX_LENGTH = 500;
export const SEARCH_QUERY_MAX_TERMS = 30;
/**
 * Lo que admite la API en `q` (400 por encima): más que SEARCH_QUERY_MAX_LENGTH para que una
 * consulta larga se corte con aviso en lugar de fallar.
 */
export const SEARCH_QUERY_INPUT_MAX = 2000;

/** Sin mayúsculas ni tildes: `Crítica` → `critica`. */
export function foldText(text: string): string {
  return text.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();
}

/** Valores escritos (sin tildes ni mayúsculas) → el código: `servidor` → `server`. */
const TYPE_ALIASES: Record<string, AssetType> = {
  servidor: 'server',
  maquina: 'vm',
  ct: 'lxc',
  contenedor: 'container',
  dominio: 'domain',
  registro: 'dns_record',
  dns: 'dns_record',
  'registro-dns': 'dns_record',
  'base-de-datos': 'database',
  bd: 'database',
  db: 'database',
  imagen: 'image',
  volumen: 'volume',
  red: 'network',
  suscripcion: 'subscription',
  certificado: 'certificate',
  conector: 'dns_provider',
};

const STATUS_ALIASES: Record<string, AssetStatus | AssetRuntimeState> = {
  pendiente: 'pending_enrollment',
  pending: 'pending_enrollment',
  activo: 'active',
  desaparecido: 'missing',
  retirado: 'retired',
  'en-marcha': 'running',
  encendido: 'running',
  parado: 'stopped',
  apagado: 'stopped',
  pausado: 'paused',
};

const SEVERITY_ALIASES: Record<string, Severity> = {
  critica: 'CRITICAL',
  alta: 'HIGH',
  media: 'MEDIUM',
  baja: 'LOW',
  desconocida: 'UNKNOWN',
};

const PRIORITY_ALIASES: Record<string, PriorityBand> = {
  urgente: 'urgent',
  alta: 'high',
  media: 'medium',
  baja: 'low',
};

/** Valores que se sugieren para las claves cerradas (los códigos y su alias en español). */
export const SEARCH_VALUE_ALIASES = {
  type: TYPE_ALIASES,
  status: STATUS_ALIASES,
  severity: SEVERITY_ALIASES,
  priority: PRIORITY_ALIASES,
} as const;

export type SearchIssueKind =
  /** Clave desconocida: el token se busca como texto (así `nginx:1.25` sigue funcionando). */
  | 'unknown_key'
  /** Clave de la otra vista (`cve:` en el inventario): se ignora. */
  | 'wrong_scope'
  /** Clave reconocida pero aún sin datos (`sitio:`): se ignora. */
  | 'unsupported'
  /** Valor no válido para una clave cerrada (`tipo:foo`, `ip:abc`): se ignora. */
  | 'invalid_value'
  /** `clave:` sin valor: se ignora. */
  | 'empty_value'
  /** Comillas sin cerrar: el valor llega hasta el final. */
  | 'unclosed_quote'
  /** Más de SEARCH_QUERY_MAX_LENGTH caracteres o SEARCH_QUERY_MAX_TERMS términos: se corta. */
  | 'too_long';

export interface SearchIssue {
  kind: SearchIssueKind;
  /** Texto del token tal como se escribió. */
  raw: string;
  start: number;
  end: number;
}

export interface SearchTerm {
  /** null = texto libre. */
  key: SearchKey | null;
  /** Normalizado: el código del tipo, estado o severidad; el resto, tal cual (sin comillas). */
  value: string;
  negated: boolean;
  /** Tal como se escribió (para el chip). */
  raw: string;
  start: number;
  end: number;
}

export interface ParsedSearchQuery {
  /** Los que filtran, en orden de aparición. */
  terms: SearchTerm[];
  issues: SearchIssue[];
}

/** Términos de una misma clave y negación juntos: sus valores son O; los grupos, Y. */
export interface SearchGroup {
  key: SearchKey | null;
  negated: boolean;
  values: string[];
}

interface Token {
  negated: boolean;
  key: string | null;
  value: string;
  raw: string;
  start: number;
  end: number;
  unclosed: boolean;
}

const KEY_PATTERN = /^[\p{L}_]+$/u;

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = input.length;
  const space = (c: string | undefined) => c !== undefined && /\s/.test(c);
  while (i < n) {
    while (i < n && space(input[i])) i++;
    if (i >= n) break;
    const start = i;
    let negated = false;
    if (input[i] === '-' && i + 1 < n && !space(input[i + 1])) {
      negated = true;
      i++;
    }
    let key: string | null = null;
    // Una clave: letras hasta `:` (sin espacios ni comillas por medio).
    let j = i;
    while (j < n && !space(input[j]) && input[j] !== ':' && input[j] !== '"')
      j++;
    if (
      j < n &&
      input[j] === ':' &&
      j > i &&
      KEY_PATTERN.test(input.slice(i, j))
    ) {
      key = input.slice(i, j);
      i = j + 1;
    }
    let value: string;
    let unclosed = false;
    if (input[i] === '"') {
      const close = input.indexOf('"', i + 1);
      if (close === -1) {
        value = input.slice(i + 1);
        unclosed = true;
        i = n;
      } else {
        value = input.slice(i + 1, close);
        i = close + 1;
      }
    } else {
      const from = i;
      while (i < n && !space(input[i])) i++;
      value = input.slice(from, i);
    }
    tokens.push({
      negated,
      key,
      value,
      raw: input.slice(start, i),
      start,
      end: i,
      unclosed,
    });
  }
  return tokens;
}

const KEY_BY_ALIAS = new Map<string, SearchKeyInfo>(
  SEARCH_KEY_INFO.flatMap((info) =>
    info.aliases.map((a) => [a, info] as const),
  ),
);

export function searchKeyInfo(alias: string): SearchKeyInfo | undefined {
  return KEY_BY_ALIAS.get(foldText(alias));
}

/** El valor normalizado de una clave cerrada, o null si no vale. */
export function normalizeSearchValue(
  key: SearchKey,
  value: string,
): string | null {
  const folded = foldText(value.trim()).replace(/\s+/g, '-');
  switch (key) {
    case 'type': {
      if ((ASSET_TYPES as readonly string[]).includes(folded)) return folded;
      return TYPE_ALIASES[folded] ?? null;
    }
    case 'status': {
      if (
        (ASSET_STATUSES as readonly string[]).includes(folded) ||
        (ASSET_RUNTIME_STATES as readonly string[]).includes(folded)
      )
        return folded;
      return STATUS_ALIASES[folded] ?? null;
    }
    case 'severity': {
      const upper = folded.toUpperCase();
      if ((SEVERITIES as readonly string[]).includes(upper)) return upper;
      return SEVERITY_ALIASES[folded] ?? null;
    }
    case 'priority': {
      if ((PRIORITY_BANDS as readonly string[]).includes(folded)) return folded;
      return PRIORITY_ALIASES[folded] ?? null;
    }
    case 'ip':
      return ipMatcher(value) ? value.trim() : null;
    default:
      return value.trim() || null;
  }
}

/**
 * Analiza la consulta. Nunca lanza: lo que no entiende va a `issues` (el texto de una clave
 * desconocida se busca tal cual).
 */
export function parseSearchQuery(
  input: string | null | undefined,
  scope: SearchScope,
): ParsedSearchQuery {
  const terms: SearchTerm[] = [];
  const issues: SearchIssue[] = [];
  let text = typeof input === 'string' ? input : '';
  if (text.length > SEARCH_QUERY_MAX_LENGTH) {
    issues.push({
      kind: 'too_long',
      raw: text.slice(SEARCH_QUERY_MAX_LENGTH),
      start: SEARCH_QUERY_MAX_LENGTH,
      end: text.length,
    });
    text = text.slice(0, SEARCH_QUERY_MAX_LENGTH);
  }
  for (const token of tokenize(text)) {
    const at = { raw: token.raw, start: token.start, end: token.end };
    if (terms.length >= SEARCH_QUERY_MAX_TERMS) {
      issues.push({ kind: 'too_long', ...at });
      continue;
    }
    if (token.unclosed) issues.push({ kind: 'unclosed_quote', ...at });
    if (token.key === null) {
      if (token.value.trim() && token.value.trim() !== '-')
        terms.push({
          key: null,
          value: token.value.trim(),
          negated: token.negated,
          ...at,
        });
      continue;
    }
    const info = searchKeyInfo(token.key);
    if (!info) {
      issues.push({ kind: 'unknown_key', ...at });
      // Sin la negación: `-foo:bar` busca lo que no contiene `foo:bar`.
      const literal = `${token.key}:${token.value}`;
      terms.push({ key: null, value: literal, negated: token.negated, ...at });
      continue;
    }
    if (!info.scopes.includes(scope)) {
      issues.push({ kind: 'wrong_scope', ...at });
      continue;
    }
    if (info.unsupported) {
      issues.push({ kind: 'unsupported', ...at });
      continue;
    }
    if (!token.value.trim()) {
      issues.push({ kind: 'empty_value', ...at });
      continue;
    }
    const value = normalizeSearchValue(info.key, token.value);
    if (value === null) {
      issues.push({ kind: 'invalid_value', ...at });
      continue;
    }
    terms.push({ key: info.key, value, negated: token.negated, ...at });
  }
  return { terms, issues };
}

/** Agrupa por clave y negación (`tag:a tag:b` → un grupo O). */
export function searchGroups(parsed: ParsedSearchQuery): SearchGroup[] {
  const groups = new Map<string, SearchGroup>();
  for (const t of parsed.terms) {
    // El texto libre no se agrupa: cada palabra debe aparecer (Y).
    const id = t.key === null ? `text:${groups.size}` : `${t.key}:${t.negated}`;
    const group = groups.get(id);
    if (group) {
      if (!group.values.includes(t.value)) group.values.push(t.value);
    } else
      groups.set(id, { key: t.key, negated: t.negated, values: [t.value] });
  }
  return [...groups.values()];
}

/** Quita un término o aviso (por su posición) sin tocar el resto del texto. */
export function removeSearchToken(
  input: string,
  token: { start: number; end: number },
): string {
  return `${input.slice(0, token.start)} ${input.slice(token.end)}`
    .replace(/\s+/g, ' ')
    .trim();
}

/** Escribe un término con comillas si hace falta. */
export function formatSearchTerm(
  alias: string,
  value: string,
  negated = false,
): string {
  const v =
    /[\s"]/.test(value) || value === ''
      ? `"${value.replaceAll('"', '')}"`
      : value;
  return `${negated ? '-' : ''}${alias}:${v}`;
}

/** Cómo compara una IP: exacta, por prefijo (`10.0.`, `10.0`) o por red IPv4 (`10.0.0.0/24`). */
export type IpMatcher =
  | { kind: 'exact'; value: string }
  | { kind: 'prefix'; value: string }
  | { kind: 'cidr'; network: number; mask: number; value: string };

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ipv4Number(ip: string): number | null {
  const m = IPV4.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return (
    ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0
  );
}

export function ipMatcher(raw: string): IpMatcher | null {
  const value = raw.trim().toLowerCase();
  if (!value || value.length > 45) return null;
  const cidr = /^([\d.]+)\/(\d{1,2})$/.exec(value);
  if (cidr) {
    const base = ipv4Number(cidr[1]!);
    const bits = Number(cidr[2]);
    if (base === null || bits > 32) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return { kind: 'cidr', network: (base & mask) >>> 0, mask, value };
  }
  if (ipv4Number(value) !== null) return { kind: 'exact', value };
  // Prefijo IPv4 (`10.0.`, `192.168`) o cualquier IPv6 o trozo de ella.
  if (/^\d{1,3}(\.\d{0,3}){0,3}$/.test(value)) {
    const parts = value.split('.');
    const complete = parts.length === 4 && parts.every(Boolean);
    return complete || parts.some((p) => Number(p) > 255)
      ? null
      : { kind: 'prefix', value };
  }
  if (/^[0-9a-f:]+$/.test(value) && value.includes(':'))
    return value.split(':').length === 8 || value.includes('::')
      ? { kind: 'exact', value }
      : { kind: 'prefix', value };
  return null;
}

export function ipMatches(m: IpMatcher, ip: string): boolean {
  const candidate = ip.trim().toLowerCase();
  switch (m.kind) {
    case 'exact':
      return candidate === m.value;
    case 'prefix':
      return candidate.startsWith(m.value);
    case 'cidr': {
      const n = ipv4Number(candidate);
      return n !== null && (n & m.mask) >>> 0 === m.network;
    }
  }
}

export interface InventoryQueryContext {
  /** Para `proyecto:<nombre>`. */
  projects?: readonly { id: string; name: string }[];
}

/** Los ids de los proyectos que nombra un valor (por id o por nombre exacto sin mayúsculas). */
export function projectIdsFor(
  value: string,
  projects: readonly { id: string; name: string }[] = [],
): string[] {
  const folded = foldText(value);
  return projects
    .filter((p) => p.id === value || foldText(p.name) === folded)
    .map((p) => p.id);
}

/** Si un nodo del árbol cumple la consulta (DESIGN §15). */
export function matchesInventoryQuery(
  node: AssetTreeSummaryNode,
  parsed: ParsedSearchQuery,
  ctx: InventoryQueryContext = {},
): boolean {
  for (const group of searchGroups(parsed)) {
    const any = group.values.some((v) => matchesValue(node, group.key, v, ctx));
    if (group.negated ? any : !any) return false;
  }
  return true;
}

function matchesValue(
  node: AssetTreeSummaryNode,
  key: SearchKey | null,
  value: string,
  ctx: InventoryQueryContext,
): boolean {
  const folded = foldText(value);
  const names = () =>
    [node.name, node.discoveredName ?? ''].some((n) =>
      foldText(n).includes(folded),
    );
  switch (key) {
    // El texto libre busca solo en el nombre (visible y descubierto), nunca en los tags.
    case null:
    case 'name':
      return names();
    case 'tag':
      return node.tags.some((t) => foldText(t) === folded);
    case 'role':
      return node.roles.some((r) => foldText(r) === folded);
    case 'type':
      return node.type === value;
    case 'status':
      return node.status === value || node.runtimeState === value;
    case 'project': {
      const ids = projectIdsFor(value, ctx.projects);
      return ids.some((id) => (node.projects ?? []).includes(id));
    }
    case 'ip': {
      const m = ipMatcher(value);
      return !!m && (node.ips ?? []).some((ip) => ipMatches(m, ip));
    }
    default:
      // Claves de vulnerabilidades o sin datos: el parser ya las dejó fuera.
      return true;
  }
}
