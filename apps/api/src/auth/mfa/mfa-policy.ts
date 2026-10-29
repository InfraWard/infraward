import type { User } from '../../users/user.entity.js';
import type { SessionAuthMethod } from '../user-session.entity.js';

/** TOTP obligatorio (DESIGN §14): admins con contraseña local (incluido el de emergencia). */
export function mfaRequired(user: Pick<User, 'role' | 'origin'>): boolean {
  return user.role === 'admin' && user.origin === 'local';
}

/**
 * La sesión se abrió con contraseña, el usuario es admin y aún no tiene TOTP: debe configurarlo
 * antes de seguir. Quien entra por OIDC no (el MFA lo aplica el proveedor), aunque su cuenta
 * sea local enlazada.
 */
export function mfaSetupRequired(
  user: Pick<User, 'role' | 'totpSecretRef'>,
  authMethod: SessionAuthMethod,
): boolean {
  return authMethod === 'password' && user.role === 'admin' && !user.totpSecretRef;
}
