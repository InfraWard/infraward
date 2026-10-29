import { USER_ROLES, type UserRole } from '@infraward/shared-types';
import type { EnvironmentVariables } from '../../config/env.validation.js';

/** Configuración del login OIDC ya validada (DESIGN §14). */
export interface OidcSettings {
  issuer: URL;
  clientId: string;
  /** Referencia `secret://…` al secreto del cliente (sin ella, cliente público con PKCE). */
  clientSecretRef: string | null;
  tokenAuthMethod: 'client_secret_basic' | 'client_secret_post';
  redirectUri: URL;
  /** Origen de la web: destino tras entrar (y tras salir del proveedor). */
  webOrigin: string;
  providerName: string;
  scopes: string;
  groupsClaim: string;
  roleMapping: ReadonlyMap<string, UserRole>;
  unmapped: 'deny' | 'viewer';
  /** Alta automática sin `email_verified: true` (OIDC_ALLOW_UNVERIFIED_SIGNUP). */
  allowUnverifiedSignup: boolean;
}

type OidcEnv = Pick<
  EnvironmentVariables,
  | 'OIDC_ISSUER'
  | 'OIDC_CLIENT_ID'
  | 'OIDC_CLIENT_SECRET_REF'
  | 'OIDC_TOKEN_AUTH_METHOD'
  | 'OIDC_REDIRECT_URI'
  | 'OIDC_PROVIDER_NAME'
  | 'OIDC_SCOPES'
  | 'OIDC_GROUPS_CLAIM'
  | 'OIDC_ROLE_MAPPING'
  | 'OIDC_UNMAPPED'
  | 'OIDC_ALLOW_UNVERIFIED_SIGNUP'
>;

/** La configuración OIDC del entorno, o null si no hay proveedor (sin OIDC_ISSUER). */
export function oidcSettings(env: OidcEnv): OidcSettings | null {
  if (!env.OIDC_ISSUER || !env.OIDC_CLIENT_ID || !env.OIDC_REDIRECT_URI)
    return null;
  const redirectUri = new URL(env.OIDC_REDIRECT_URI);
  return {
    issuer: new URL(env.OIDC_ISSUER),
    clientId: env.OIDC_CLIENT_ID,
    clientSecretRef: env.OIDC_CLIENT_SECRET_REF ?? null,
    tokenAuthMethod: env.OIDC_TOKEN_AUTH_METHOD,
    redirectUri,
    webOrigin: redirectUri.origin,
    providerName: env.OIDC_PROVIDER_NAME,
    scopes: env.OIDC_SCOPES,
    groupsClaim: env.OIDC_GROUPS_CLAIM,
    roleMapping: parseRoleMapping(env.OIDC_ROLE_MAPPING),
    unmapped: env.OIDC_UNMAPPED,
    allowUnverifiedSignup: env.OIDC_ALLOW_UNVERIFIED_SIGNUP ?? false,
  };
}

/**
 * `grupo=rol,grupo2=rol2` → mapa. El grupo puede llevar `=` (se parte por el último) y
 * espacios por dentro; un grupo repetido con otro rol es un error.
 */
export function parseRoleMapping(
  value: string | undefined,
): Map<string, UserRole> {
  const mapping = new Map<string, UserRole>();
  if (!value?.trim()) return mapping;
  for (const entry of value.split(',')) {
    const eq = entry.lastIndexOf('=');
    const group = eq === -1 ? '' : entry.slice(0, eq).trim();
    const role = eq === -1 ? '' : entry.slice(eq + 1).trim();
    if (!group || !role)
      throw new Error(
        'cada entrada tiene que ser grupo=rol (separadas por comas)',
      );
    if (!(USER_ROLES as readonly string[]).includes(role))
      throw new Error(
        `rol desconocido (disponibles: ${USER_ROLES.join(', ')})`,
      );
    const previous = mapping.get(group);
    if (previous && previous !== role)
      throw new Error('un grupo aparece con dos roles distintos');
    mapping.set(group, role as UserRole);
  }
  return mapping;
}

/**
 * Valores de texto de un claim: primero por su nombre literal (claims con URL o puntos, como
 * los de Auth0 o Entra) y, si no existe, como ruta con puntos (`realm_access.roles`).
 */
export function claimValues(
  claims: Record<string, unknown>,
  path: string,
): string[] {
  let value: unknown = claims[path];
  if (value === undefined && path.includes('.')) {
    value = path
      .split('.')
      .reduce<unknown>(
        (node, key) =>
          node && typeof node === 'object' && !Array.isArray(node)
            ? (node as Record<string, unknown>)[key]
            : undefined,
        claims,
      );
  }
  if (typeof value === 'string') return [value];
  if (Array.isArray(value))
    return value.filter((v): v is string => typeof v === 'string');
  return [];
}

export interface RoleResolution {
  /** Rol resultante, o null si se deniega el acceso. */
  role: UserRole | null;
  /** Grupos del usuario que tienen rol en el mapeo. */
  matched: string[];
}

/**
 * Rol de InfraWard según los grupos: con varios, el de más permisos (orden de `USER_ROLES`);
 * sin ninguno con rol, `viewer` o denegado según `unmapped`.
 */
export function resolveRole(
  groups: readonly string[],
  mapping: ReadonlyMap<string, UserRole>,
  unmapped: 'deny' | 'viewer',
): RoleResolution {
  const matched = [...new Set(groups)].filter((g) => mapping.has(g));
  if (matched.length === 0)
    return { role: unmapped === 'viewer' ? 'viewer' : null, matched };
  const role = matched
    .map((g) => mapping.get(g)!)
    .reduce((best, r) =>
      USER_ROLES.indexOf(r) < USER_ROLES.indexOf(best) ? r : best,
    );
  return { role, matched };
}

/**
 * Ruta de la web a la que volver tras entrar: solo rutas relativas del mismo origen (empieza
 * por una sola `/`, sin `\`, sin caracteres de control y de longitud razonable); si no, `/`.
 */
export function safeReturnPath(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length > 2048 ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    // eslint-disable-next-line no-control-regex
    /[\\\u0000-\u001f\u007f]/.test(value)
  )
    return '/';
  return value;
}
