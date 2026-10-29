/** Roles fijos, de más a menos permisos (DESIGN §14). */
export const USER_ROLES = [
  'admin',
  'editor',
  'operator',
  'auditor',
  'viewer',
] as const;
export type UserRole = (typeof USER_ROLES)[number];

/**
 * Permisos además de leer el inventario y las vulnerabilidades (eso lo puede todo usuario).
 * - `assets.operate`: recolectar, descubrir, escanear, re-escanear afectados, re-evaluar SBOMs
 *   y reconciliar (solo lee la infraestructura).
 * - `assets.write`: altas (con script o a mano), comandos de alta, pasos a CA, editar assets y
 *   darlos de baja (reversible) y comprobar referencias a secretos.
 * - `assets.purge`: purgar (borrado físico, no se puede deshacer).
 * - `assets.write` incluye también organizarlos: nombre visible, tags (y sus colores) y notas.
 * - `projects.write`: crear, cambiar y borrar proyectos y decidir qué assets entran.
 * - `policy.write`: la política de inventario (global, por etiqueta, por proyecto y por asset).
 * - `secrets.status`: estado de los proveedores de secretos (nunca valores).
 * - `audit.read`: el registro de auditoría.
 * - `users.read` / `users.manage`: ver / gestionar usuarios.
 * - `connectors.write`: conectores de dominios (alta con su token, probar, reemplazar el token,
 *   dar de baja). Sincronizarlos es `assets.operate`.
 * - `vault.manage`: caja fuerte de credenciales (QoL-7): ver sus metadatos, crear entradas,
 *   editarlas, sustituir el secreto (sin leerlo), marcarlas rotadas, borrarlas y recuperarlas.
 * - `vault.admin`: revelar una credencial, restaurar una versión anterior y los ajustes de la
 *   caja fuerte (las tres, además, con reautenticación reciente).
 * - `terminal.open`: abrir una terminal interactiva con la cuenta de administración de un
 *   servidor (con reautenticación reciente). El rol solo lo da a admin; a los demás se les
 *   concede por asset, etiqueta o proyecto con una AccessPolicy (sesión 22, `access.ts`).
 */
export const PERMISSIONS = [
  'assets.operate',
  'assets.write',
  'assets.purge',
  'projects.write',
  'policy.write',
  'secrets.status',
  'audit.read',
  'users.read',
  'users.manage',
  'connectors.write',
  'vault.manage',
  'vault.admin',
  'terminal.open',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

/** Única fuente de qué puede hacer cada rol: la usan la API (guard) y la web (qué enseña). */
export const ROLE_PERMISSIONS: Record<UserRole, readonly Permission[]> = {
  admin: PERMISSIONS,
  editor: [
    'assets.operate',
    'assets.write',
    'projects.write',
    'policy.write',
    'secrets.status',
    'connectors.write',
    'vault.manage',
  ],
  operator: ['assets.operate'],
  auditor: ['audit.read', 'users.read', 'secrets.status'],
  viewer: [],
};

export function hasPermission(
  role: UserRole | null | undefined,
  permission: Permission,
): boolean {
  return !!role && ROLE_PERMISSIONS[role]?.includes(permission) === true;
}

/** Longitud mínima y máxima de una contraseña elegida por el usuario. */
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 1024;

/** Cabecera con el token CSRF de la sesión (obligatoria en POST/PUT/PATCH/DELETE). */
export const CSRF_HEADER = 'x-csrf-token';

/** Código del 403 de una sesión que solo sirve para cambiar la contraseña temporal. */
export const PASSWORD_CHANGE_REQUIRED = 'password_change_required';

export interface LoginRequest {
  email: string;
  password: string;
}

/**
 * Cómo se creó la cuenta: `local` (alta en Ajustes o administrador inicial, con contraseña) u
 * `oidc` (alta automática al entrar con el proveedor OIDC; sin contraseña).
 */
export const USER_ORIGINS = ['local', 'oidc'] as const;
export type UserOrigin = (typeof USER_ORIGINS)[number];

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  origin: UserOrigin;
  /**
   * Enlazada a una identidad del proveedor OIDC (las `oidc` siempre; las `local`, si se enlazaron
   * por email verificado). Su rol lo decide el proveedor en cada login.
   */
  oidcLinked: boolean;
  /** Tiene la verificación en dos pasos (TOTP) activa. */
  mfaEnabled: boolean;
  createdAt: string;
}

/**
 * Sesión actual (POST /auth/login, GET /auth/session). El token de sesión va solo en una cookie
 * httpOnly: nunca en el cuerpo. El token CSRF no es una credencial por sí solo (sin la cookie no
 * vale) y la web lo guarda en memoria.
 */
export interface SessionInfo {
  user: UserProfile;
  csrfToken: string;
  /** Caducidad absoluta de la sesión (ISO). */
  expiresAt: string;
  /** Entró con una contraseña temporal: solo puede cambiarla (POST /auth/password). */
  mustChangePassword: boolean;
  /**
   * Puede cambiar su propio email (POST /auth/email): cuenta local sin enlazar, no la de
   * emergencia y sin OIDC configurado (con OIDC lo cambia un admin).
   */
  canChangeEmail: boolean;
  /**
   * Sesión intermedia del login: la contraseña era buena y falta el código TOTP o de
   * recuperación (POST /auth/mfa/verify). Hasta entonces no vale para nada más.
   */
  mfaPending: boolean;
  /** Admin local que entró con contraseña sin TOTP: debe configurarlo antes de seguir. */
  mfaSetupRequired: boolean;
  /** Cómo se reautentica para una acción sensible (TOTP o login en el proveedor). */
  reauthMethod: 'totp' | 'oidc';
  /** Hasta cuándo vale la última reautenticación (ISO) o null. */
  reauthenticatedUntil: string | null;
}

export interface UpdateProfileRequest {
  name: string;
}

/** Cambio del email propio (POST /auth/email): pide la contraseña actual. */
export interface ChangeEmailRequest {
  email: string;
  currentPassword: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

/** Usuario de Ajustes > Usuarios (GET /users). Nunca lleva el hash de la contraseña. */
export interface UserSummary extends UserProfile {
  active: boolean;
  /** Tiene una contraseña temporal pendiente (alta o restablecimiento). */
  mustChangePassword: boolean;
  lastLoginAt: string | null;
  /** Es el admin local de emergencia (LOCAL_LOGIN_EMERGENCY_EMAIL). */
  emergency: boolean;
}

export interface CreateUserRequest {
  email: string;
  name: string;
  role: UserRole;
}

export interface UpdateUserRequest {
  name?: string;
  role?: UserRole;
  /** Solo usuarios locales sin enlazar a OIDC (el email de los enlazados lo da el proveedor). */
  email?: string;
}

/** La contraseña temporal se devuelve una sola vez: la API no la guarda en claro. */
export interface TemporaryPasswordResponse {
  user: UserSummary;
  temporaryPassword: string;
  /** Hasta cuándo vale (ISO). */
  expiresAt: string;
}

/** Métodos de entrada disponibles (GET /auth/providers, público): la web decide qué enseña. */
export interface AuthProviders {
  /** Login con email y contraseña para todos (false: solo el admin de emergencia). */
  local: boolean;
  /** Proveedor OIDC configurado (null si no hay). */
  oidc: { name: string } | null;
}

/** POST /auth/logout: si la sesión vino del proveedor OIDC, URL para cerrar también la suya. */
export interface LogoutResponse {
  providerLogoutUrl: string | null;
}

/**
 * Error del login OIDC que la API pasa a la web en `/login?oidcError=<código>`. El motivo
 * concreto (state, nonce, firma…) solo va a la auditoría.
 */
export const OIDC_LOGIN_ERRORS = [
  'failed',
  'denied',
  'disabled',
  'email_conflict',
  'email_unverified',
  'unavailable',
] as const;
export type OidcLoginError = (typeof OIDC_LOGIN_ERRORS)[number];

/**
 * Tokens de API personales (QoL-6, DESIGN §14): `Authorization: Bearer iwt_…`. Valen lo que el
 * rol del usuario en cada momento (`role`) o solo para leer (`read`: GET y HEAD).
 */
export const API_TOKEN_SCOPES = ['read', 'role'] as const;
export type ApiTokenScope = (typeof API_TOKEN_SCOPES)[number];

/** Prefijo fijo de los tokens (para reconocerlos en un log o en un escáner de secretos). */
export const API_TOKEN_PREFIX = 'iwt_';
/** Caracteres del token que se guardan y se enseñan para reconocerlo (prefijo incluido). */
export const API_TOKEN_DISPLAY_LENGTH = 12;
/** Vida máxima de un token (días): la caducidad es obligatoria. */
export const API_TOKEN_MAX_DAYS = 365;
/** Tokens activos por usuario. */
export const API_TOKENS_MAX_ACTIVE = 25;
export const API_TOKEN_NAME_MAX = 100;

/** Código del 403 de un token de solo lectura en una petición que escribe. */
export const API_TOKEN_READ_ONLY = 'api_token_read_only';
/** Código del 403 de un endpoint que exige la sesión web (no admite tokens). */
export const SESSION_REQUIRED = 'session_required';

/** Token sin su valor (nunca se vuelve a enseñar; en la BD solo está su sha256). */
export interface ApiTokenSummary {
  id: string;
  name: string;
  /** Primeros caracteres (`iwt_ab12cd34`), para reconocerlo. */
  prefix: string;
  scope: ApiTokenScope;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  revokedAt: string | null;
  /** Vigente: ni revocado ni caducado. */
  active: boolean;
  /** Dueño (en la vista de admin, GET /api-tokens). */
  user?: { id: string; email: string; name: string };
}

export interface CreateApiTokenRequest {
  name: string;
  scope: ApiTokenScope;
  /** Caducidad (ISO), como mucho API_TOKEN_MAX_DAYS días desde ahora. */
  expiresAt: string;
}

/** El token en claro se devuelve una sola vez, al crearlo. */
export interface CreatedApiTokenResponse {
  token: ApiTokenSummary;
  secret: string;
}
