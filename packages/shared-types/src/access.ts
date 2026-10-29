// Políticas de acceso interactivo (AccessPolicy, sesión 22, DESIGN §5 y §11): a quién se le
// concede `terminal.open` y dónde, además de lo que da su rol.

import { hasPermission, type UserRole } from './auth.js';

/** Permisos que se conceden por asset, etiqueta o proyecto. */
export const ACCESS_PERMISSIONS = ['terminal.open'] as const;
export type AccessPermission = (typeof ACCESS_PERMISSIONS)[number];

/** A quién: una persona o todas las de un rol. */
export const ACCESS_SUBJECT_TYPES = ['user', 'role'] as const;
export type AccessSubjectType = (typeof ACCESS_SUBJECT_TYPES)[number];

/**
 * Dónde: un asset (y todo lo que contiene, como una regla de política en un nodo), los assets
 * con una etiqueta o los de un proyecto (los efectivos: los heredados también).
 */
export const ACCESS_SCOPES = ['asset', 'tag', 'project'] as const;
export type AccessScope = (typeof ACCESS_SCOPES)[number];

export type AccessSubject =
  | { type: 'user'; userId: string; email: string | null; name: string | null }
  | { type: 'role'; role: UserRole };

/** Una regla (`GET /access-policies`). */
export interface AccessPolicyRule {
  id: string;
  permission: AccessPermission;
  subject: AccessSubject;
  scope: AccessScope;
  assetId: string | null;
  assetName: string | null;
  tag: string | null;
  projectId: string | null;
  projectName: string | null;
  createdAt: string;
  createdBy: { id: string; email: string } | null;
}

/** `POST /access-policies` (users.manage y reautenticación reciente). */
export interface CreateAccessPolicyRequest {
  permission: AccessPermission;
  subjectType: AccessSubjectType;
  userId?: string;
  role?: UserRole;
  scope: AccessScope;
  assetId?: string;
  tag?: string;
  projectId?: string;
}

/** Por qué una regla alcanza a un asset. */
export type AccessGrantSource =
  | { kind: 'own' }
  | { kind: 'inherited'; assetId: string }
  | { kind: 'tag'; tag: string }
  | { kind: 'project'; projectId: string };

/** Lo mínimo de una regla para resolverla. */
export interface AccessRuleTarget {
  scope: AccessScope;
  assetId: string | null;
  tag: string | null;
  projectId: string | null;
}

/** Lo que hace falta saber del asset: sus antepasados `contains` (del padre hacia arriba). */
export interface AccessAssetContext {
  assetId: string;
  ancestorIds: readonly string[];
  tags: readonly string[];
  /** `assets.effective_projects`: incluye los heredados por el árbol. */
  projectIds: readonly string[];
}

/**
 * ¿Alcanza esta regla al asset? Pura (la usan la API al decidir y al explicarlo). Una regla de
 * asset vale para él y todo lo que contiene; la de etiqueta, para los que la llevan; la de
 * proyecto, para sus miembros efectivos. Solo concede: no hay reglas que quiten.
 */
export function accessRuleApplies(
  rule: AccessRuleTarget,
  asset: AccessAssetContext,
): AccessGrantSource | null {
  switch (rule.scope) {
    case 'asset':
      if (rule.assetId === asset.assetId) return { kind: 'own' };
      if (rule.assetId && asset.ancestorIds.includes(rule.assetId))
        return { kind: 'inherited', assetId: rule.assetId };
      return null;
    case 'tag':
      return rule.tag && asset.tags.includes(rule.tag) ? { kind: 'tag', tag: rule.tag } : null;
    case 'project':
      return rule.projectId && asset.projectIds.includes(rule.projectId)
        ? { kind: 'project', projectId: rule.projectId }
        : null;
  }
}

/** ¿Es la regla de esta persona (por ella o por su rol)? */
export function accessRuleMatchesUser(
  subject: { type: AccessSubjectType; userId: string | null; role: UserRole | null },
  user: { id: string; role: UserRole },
): boolean {
  return subject.type === 'user' ? subject.userId === user.id : subject.role === user.role;
}

/**
 * ¿Puede `user` usar `permission` en el asset? Su rol primero (admin siempre puede) y, si no,
 * alguna de sus reglas que alcance al asset.
 */
export function canAccess(
  user: { id: string; role: UserRole },
  permission: AccessPermission,
  rules: readonly (AccessRuleTarget & {
    permission: AccessPermission;
    subjectType: AccessSubjectType;
    userId: string | null;
    role: UserRole | null;
  })[],
  asset: AccessAssetContext,
): boolean {
  if (hasPermission(user.role, permission)) return true;
  return rules.some(
    (r) =>
      r.permission === permission &&
      accessRuleMatchesUser({ type: r.subjectType, userId: r.userId, role: r.role }, user) &&
      accessRuleApplies(r, asset) !== null,
  );
}

/** Quién puede abrir terminal en un asset y por qué (`GET /assets/:id/access`). */
export interface AssetAccessEntry {
  rule: AccessPolicyRule;
  source: AccessGrantSource;
  /** Nombre del antepasado de una regla heredada. */
  sourceName: string | null;
}
export interface AssetAccess {
  /** Roles que lo tienen siempre (por `ROLE_PERMISSIONS`). */
  roles: UserRole[];
  entries: AssetAccessEntry[];
}
