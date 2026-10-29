/** Acciones del registro de auditoría (DESIGN §14). */
export const AUDIT_ACTIONS = [
  'auth.login',
  'auth.login_failed',
  'auth.logout',
  'auth.password_changed',
  'auth.mfa_challenge',
  'auth.mfa_enabled',
  'auth.mfa_disabled',
  'auth.mfa_recovery_regenerated',
  'auth.reauth',
  'auth.reauth_required',
  'user.created',
  'user.updated',
  'user.role_changed',
  'user.email_changed',
  'user.deactivated',
  'user.reactivated',
  'user.password_reset',
  'user.oidc_linked',
  'user.mfa_reset',
  'api_token.created',
  'api_token.revoked',
  'asset.created',
  'asset.updated',
  'asset.renamed',
  'asset.tags_changed',
  'asset.notes_changed',
  'tag.style_changed',
  'tag.deleted',
  'project.created',
  'project.updated',
  'project.deleted',
  'project.member_set',
  'project.member_removed',
  'project.dashboard_updated',
  'project.dashboard_reset',
  'asset.retired',
  'asset.purged',
  'asset.bulk_tags',
  'asset.bulk_project',
  'asset.bulk_collect',
  'asset.bulk_scan',
  'asset.bulk_policy',
  'asset.bulk_retire',
  'enrollment.started',
  'enrollment.ca_requested',
  'enrollment.admin_access_requested',
  'policy.global_updated',
  'policy.rule_created',
  'policy.rule_updated',
  'policy.rule_deleted',
  'policy.asset_set',
  'policy.asset_cleared',
  'inventory.reconcile_requested',
  'vulnerabilities.rescan_requested',
  'vulnerabilities.intel_refresh_requested',
  'vulnerabilities.reevaluate_requested',
  'connector.created',
  'connector.token_replaced',
  'connector.tested',
  'connector.sync_requested',
  'connector.deleted',
  'dns.check_accepted',
  'dns.check_reopened',
  'settings.expiry_changed',
  'settings.nat_created',
  'settings.nat_updated',
  'settings.nat_deleted',
  'service.path_pinned',
  'service.path_unpinned',
  'vault.created',
  'vault.updated',
  'vault.secret_replaced',
  'vault.rotated',
  'vault.deleted',
  'vault.restored',
  'vault.version_restored',
  'vault.revealed',
  'vault.purged',
  'vault.settings_changed',
  'terminal.session_requested',
  'terminal.session_opened',
  'terminal.session_closed',
  'terminal.session_rejected',
  'terminal.session_revoked',
  'access.granted',
  'access.revoked',
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

/** Categoría de una acción (lo que va antes del punto): filtro de la vista de auditoría. */
export type AuditCategory = AuditAction extends `${infer C}.${string}`
  ? C
  : never;

export const AUDIT_OUTCOMES = ['success', 'failure'] as const;
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];

/**
 * Motivo de un login fallido (solo en la auditoría: hacia fuera, «Credenciales inválidas» en el
 * login local y un código genérico en el OIDC).
 */
export type LoginFailureReason =
  | 'unknown_user'
  | 'bad_password'
  | 'disabled'
  | 'temp_expired'
  /** Login local desactivado (LOCAL_LOGIN=false) y no es el admin de emergencia. */
  | 'local_login_disabled'
  // OIDC (QoL-2)
  /** state desconocido, caducado, ya usado o sin la cookie del navegador que empezó el flujo. */
  | 'state_invalid'
  /** El proveedor devolvió un error (p. ej. access_denied) o falló el canje del código. */
  | 'provider_error'
  /** Discovery o JWKS del proveedor inaccesibles. */
  | 'provider_unavailable'
  | 'nonce_invalid'
  | 'issuer_invalid'
  | 'audience_invalid'
  | 'token_expired'
  | 'signature_invalid'
  | 'token_invalid'
  | 'email_missing'
  /** Hay un usuario con ese email y el proveedor no lo da por verificado: no se enlaza. */
  | 'email_unverified'
  /** El usuario con ese email ya está enlazado a otra identidad del proveedor. */
  | 'already_linked'
  /** El email es el del admin local de emergencia: nunca se enlaza al proveedor. */
  | 'emergency_account'
  /** Ningún grupo del usuario tiene rol (OIDC_UNMAPPED=deny). */
  | 'no_role_mapping'
  // Reautenticación con el proveedor (step-up, DESIGN §14)
  /** La identidad que vuelve del proveedor no es la del usuario de la sesión. */
  | 'subject_mismatch'
  /** El ID token no trae `auth_time`: no se puede saber si pidió las credenciales. */
  | 'auth_time_missing'
  /** `auth_time` anterior al inicio de la reautenticación: el proveedor no volvió a pedirlas. */
  | 'auth_time_stale'
  /** La sesión que pidió reautenticarse ya no existe o caducó. */
  | 'session_closed';

/** Valores admitidos en el detalle: pequeños y planos. Nunca secretos (los filtra la API). */
export type AuditDetailValue = string | number | boolean | null | string[];
export type AuditDetails = Record<string, AuditDetailValue>;

export interface AuditEvent {
  id: string;
  occurredAt: string;
  actorId: string | null;
  /** Email en el momento de la acción (o el tecleado en un login fallido). */
  actorEmail: string | null;
  action: AuditAction;
  outcome: AuditOutcome;
  targetType: string | null;
  targetId: string | null;
  /** Nombre del objetivo en el momento de la acción (sobrevive a una purga). */
  targetLabel: string | null;
  ip: string | null;
  details: AuditDetails;
}

export interface AuditQuery {
  action?: AuditAction[];
  category?: AuditCategory[];
  actorId?: string;
  targetId?: string;
  outcome?: AuditOutcome;
  /** Texto en el objetivo o en el email del actor. */
  q?: string;
  from?: string;
  to?: string;
  /** Cursor opaco de la página anterior (`nextCursor`). */
  cursor?: string;
  limit?: number;
}

export interface AuditPage {
  items: AuditEvent[];
  nextCursor: string | null;
}
