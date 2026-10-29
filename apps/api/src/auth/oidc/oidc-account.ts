import type {
  LoginFailureReason,
  OidcLoginError,
} from '@infraward/shared-types';
import type { User } from '../../users/user.entity.js';

/** Lo que cuenta de una identidad OIDC ya validada (ID token). */
export interface OidcIdentity {
  issuer: string;
  subject: string;
  /** En minúsculas; null si el proveedor no lo da. */
  email: string | null;
  /** Solo `email_verified === true` cuenta como verificado. */
  emailVerified: boolean;
  name: string | null;
  groups: string[];
}

export type AccountDecision =
  /** Ya enlazado a esta identidad (issuer + sub). */
  | { kind: 'existing'; user: User }
  /** Usuario local con el mismo email verificado: se enlaza. */
  | { kind: 'link'; user: User }
  /** Nadie con esa identidad ni ese email: alta automática. */
  | { kind: 'create' }
  | {
      kind: 'reject';
      reason: LoginFailureReason;
      error: OidcLoginError;
      user?: User;
    };

/**
 * A qué cuenta corresponde una identidad OIDC (DESIGN §14):
 * 1. la enlazada a su issuer + sub;
 * 2. si no, la de su email, pero solo si el proveedor lo marca como verificado, no está
 *    enlazada a otra identidad y no es el admin local de emergencia;
 * 3. si no hay ninguna, una nueva, también solo con el email verificado (salvo
 *    `allowUnverifiedSignup`): si no, quien se registre en el proveedor con el email de otra
 *    persona se quedaría con él y la persona real recibiría `already_linked` (revisión #3, M3).
 * Una cuenta desactivada nunca entra. El rol se decide aparte (`resolveRole`).
 */
export function decideAccount(
  identity: OidcIdentity,
  bySubject: User | null,
  byEmail: User | null,
  emergencyEmail: string | null,
  options: { allowUnverifiedSignup?: boolean } = {},
): AccountDecision {
  if (bySubject) {
    return bySubject.disabledAt
      ? {
          kind: 'reject',
          reason: 'disabled',
          error: 'disabled',
          user: bySubject,
        }
      : { kind: 'existing', user: bySubject };
  }
  if (!identity.email)
    return { kind: 'reject', reason: 'email_missing', error: 'failed' };
  if (!byEmail)
    return identity.emailVerified || options.allowUnverifiedSignup
      ? { kind: 'create' }
      : { kind: 'reject', reason: 'email_unverified', error: 'email_unverified' };

  const conflict = (reason: LoginFailureReason): AccountDecision => ({
    kind: 'reject',
    reason,
    error: 'email_conflict',
    user: byEmail,
  });
  if (byEmail.oidcSubject) return conflict('already_linked');
  if (emergencyEmail && byEmail.email === emergencyEmail)
    return conflict('emergency_account');
  if (!identity.emailVerified) return conflict('email_unverified');
  if (byEmail.disabledAt)
    return {
      kind: 'reject',
      reason: 'disabled',
      error: 'disabled',
      user: byEmail,
    };
  return { kind: 'link', user: byEmail };
}
