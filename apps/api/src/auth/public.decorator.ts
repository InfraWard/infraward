import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC = 'isPublic';

/** Marca un endpoint como accesible sin sesión (el guard de sesión es global). */
export const Public = () => SetMetadata(IS_PUBLIC, true);

export const ALLOW_PASSWORD_CHANGE = 'allowPasswordChange';

/**
 * Endpoint que admite la sesión limitada de una contraseña temporal (solo cambiarla, ver la
 * sesión y salir). Sin esta marca, esa sesión recibe 403 `password_change_required`.
 */
export const AllowPasswordChange = () =>
  SetMetadata(ALLOW_PASSWORD_CHANGE, true);

export const SESSION_ONLY = 'sessionOnly';

/**
 * Endpoint que exige la sesión web: con un token de API, 403 `session_required` (gestionar los
 * tokens, la contraseña, cerrar sesión, los flujos SSE). Así un token robado no se perpetúa.
 */
export const SessionOnly = () => SetMetadata(SESSION_ONLY, true);

export const ALLOW_MFA_PENDING = 'allowMfaPending';

/**
 * Endpoint que admite la sesión intermedia del login (contraseña buena, falta el código TOTP):
 * verificar el código, ver la sesión y salir. Sin esta marca, esa sesión recibe 403 `mfa_pending`.
 */
export const AllowMfaPending = () => SetMetadata(ALLOW_MFA_PENDING, true);

export const ALLOW_MFA_SETUP = 'allowMfaSetup';

/**
 * Endpoint que puede usar un admin local que aún no tiene TOTP (configurarlo, ver la sesión,
 * cambiar la contraseña y salir). Sin esta marca, 403 `mfa_setup_required`.
 */
export const AllowMfaSetup = () => SetMetadata(ALLOW_MFA_SETUP, true);
