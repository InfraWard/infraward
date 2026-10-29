import type { ApiTokenScope, UserRole } from '@infraward/shared-types';
import type {
  SessionAuthMethod,
  SessionPurpose,
} from './user-session.entity.js';

/** Usuario autenticado que el guard de sesión deja en la request (rol leído de la BD). */
export interface AuthenticatedUser {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  /** Tiene TOTP activo. */
  mfaEnabled: boolean;
}

/** Sesión con la que se ha autenticado la request. */
export interface RequestSession {
  id: string;
  purpose: SessionPurpose;
  csrfToken: string;
  expiresAt: Date;
  authMethod: SessionAuthMethod;
  /** Última confirmación de la identidad (step-up) o null. */
  reauthenticatedAt: Date | null;
}

/** Token de API con el que se ha autenticado la request (QoL-6; sin sesión ni CSRF). */
export interface RequestApiToken {
  id: string;
  scope: ApiTokenScope;
  prefix: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
    authSession?: RequestSession;
    apiToken?: RequestApiToken;
  }
}
