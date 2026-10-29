import type { SessionInfo, UserRole } from '@infraward/shared-types';
import { primeSessionForTests } from '../core/auth/auth.service';

/** Sesión de prueba (lo que devolvería GET /auth/session). */
export function testSession(
  role: UserRole = 'admin',
  csrfToken = 'csrf',
  mustChangePassword = false,
): SessionInfo {
  return {
    user: {
      id: 'u1',
      email: `${role}@example.com`,
      name: role === 'admin' ? 'Admin' : 'Viewer',
      role,
      origin: 'local',
      oidcLinked: false,
      mfaEnabled: role === 'admin',
      createdAt: '2026-10-08T00:00:00.000Z',
    },
    csrfToken,
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    mustChangePassword,
    canChangeEmail: true,
    mfaPending: false,
    mfaSetupRequired: false,
    reauthMethod: 'totp',
    reauthenticatedUntil: null,
  };
}

/** Deja una sesión válida para los AuthService que se creen a continuación. */
export function storeSession(role: UserRole = 'admin', csrfToken = 'csrf'): void {
  primeSessionForTests(testSession(role, csrfToken));
}
