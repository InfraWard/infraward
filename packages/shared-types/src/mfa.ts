import { hasPermission, PERMISSIONS, type Permission, type UserRole } from './auth.js';

/** Código del 403 de la sesión intermedia del login: falta el segundo factor (POST /auth/mfa/verify). */
export const MFA_PENDING = 'mfa_pending';
/** Código del 403 de un admin local sin TOTP: debe configurarlo antes de seguir. */
export const MFA_SETUP_REQUIRED = 'mfa_setup_required';
/** Código del 403 de una acción sensible sin una reautenticación reciente (step-up). */
export const RECENT_AUTH_REQUIRED = 'recent_auth_required';
/** Código del 403 de una acción sensible de un usuario local que no tiene TOTP. */
export const MFA_REQUIRED_FOR_ACTION = 'mfa_required_for_action';

/** Ventana por defecto de la reautenticación reciente (segundos; REAUTH_MAX_AGE). */
export const REAUTH_MAX_AGE_DEFAULT = 600;
/** Códigos de recuperación que se generan cada vez. */
export const RECOVERY_CODES_COUNT = 10;

/**
 * Acciones sensibles (DESIGN §14): exigen identidad confirmada hace poco, además de la sesión.
 * Única lista: la API la aplica con `@RecentAuth(acción)` (un test compara las rutas con ella) y
 * la web enseña su etiqueta en el diálogo de reautenticación.
 */
export const SENSITIVE_ACTIONS = {
  'asset.purge': 'Purgar un asset',
  'user.role_change': 'Cambiar el rol de un usuario',
  'user.deactivate': 'Desactivar un usuario',
  'user.mfa_reset': 'Restablecer la verificación en dos pasos de un usuario',
  'api_token.create_write': 'Crear un token de API con permisos de escritura',
  'mfa.disable': 'Desactivar tu verificación en dos pasos',
  'mfa.replace': 'Cambiar el dispositivo de tu verificación en dos pasos',
  'mfa.recovery_regenerate': 'Generar códigos de recuperación nuevos',
  'terminal.open': 'Abrir una terminal',
  'vault.reveal': 'Revelar una credencial de la caja fuerte',
  'vault.version_restore': 'Restaurar una versión anterior de una credencial',
  'vault.settings_change': 'Cambiar los ajustes de la caja fuerte',
  'admin_access.enable': 'Activar el acceso interactivo de administración',
  'access.grant': 'Dar acceso a la terminal',
} as const;
export type SensitiveAction = keyof typeof SENSITIVE_ACTIONS;

/** Cómo se reautentica el usuario de la sesión: código TOTP (local) o login en el proveedor (OIDC). */
export type ReauthMethod = 'totp' | 'oidc';

/** Cuerpo del 403 `recent_auth_required` / `mfa_required_for_action`. */
export interface RecentAuthError {
  statusCode: 403;
  code: typeof RECENT_AUTH_REQUIRED | typeof MFA_REQUIRED_FOR_ACTION;
  message: string;
  action: SensitiveAction;
  /** null con un token de API: no hay forma de reautenticarse (solo desde la web). */
  method: ReauthMethod | null;
}

/** Permisos que solo leen: un token `role` de quien solo tiene estos no escribe. */
const READ_PERMISSIONS: readonly Permission[] = ['secrets.status', 'audit.read', 'users.read'];

/** ¿Puede escribir algo este rol? (un token de API `role` suyo es «de escritura»). */
export function roleCanWrite(role: UserRole): boolean {
  return PERMISSIONS.some((p) => !READ_PERMISSIONS.includes(p) && hasPermission(role, p));
}

/** Código TOTP (6 dígitos) o de recuperación (`xxxx-xxxx-xxxx-xxxx`). */
export interface MfaCodeRequest {
  code: string;
}

/** Alta de TOTP (POST /auth/mfa/setup): se enseña una vez y no se guarda en claro. */
export interface MfaSetupResponse {
  /** `otpauth://totp/…` (lo que lleva el QR). */
  otpauthUri: string;
  /** El secreto en base32, para teclearlo a mano. */
  secret: string;
  /** QR en PNG como `data:image/png;base64,…`. */
  qrDataUrl: string;
}

/** Los códigos de recuperación se devuelven una sola vez (en la BD, solo su sha256). */
export interface RecoveryCodesResponse {
  recoveryCodes: string[];
}

/** Estado de la verificación en dos pasos del usuario (en el perfil y en Usuarios). */
export interface MfaStatus {
  /** Tiene TOTP activo. */
  enabled: boolean;
  /** Códigos de recuperación sin usar. */
  recoveryCodesLeft: number;
  /** Le es obligatorio (admin local). */
  required: boolean;
}

/** POST /auth/reauth: hasta cuándo vale la reautenticación (ISO). */
export interface ReauthResponse {
  reauthenticatedUntil: string;
}
