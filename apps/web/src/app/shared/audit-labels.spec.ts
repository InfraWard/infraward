import type { AuditEvent } from '@infraward/shared-types';
import { auditDetail } from './audit-labels';

const event = (action: AuditEvent['action'], details: AuditEvent['details']): AuditEvent => ({
  id: 'e',
  occurredAt: '2026-10-20T08:00:00Z',
  actorId: 'u',
  actorEmail: 'a@b.c',
  action,
  outcome: 'success',
  targetType: null,
  targetId: null,
  targetLabel: null,
  ip: null,
  details,
});

describe('auditDetail (MFA y reautenticación)', () => {
  it('el segundo paso y la confirmación dicen con qué se hizo', () => {
    expect(auditDetail(event('auth.mfa_challenge', { method: 'recovery', recoveryCodesLeft: 9 }))).toBe(
      'con un código de recuperación · quedan 9 códigos de recuperación',
    );
    expect(auditDetail(event('auth.login', { mfa: 'totp', forcedChange: false }))).toBe('con la app');
    expect(auditDetail(event('auth.reauth', { method: 'totp', action: 'asset.purge' }))).toBe(
      'Purgar un asset · con la app',
    );
  });

  it('el rechazo de una acción sensible dice cuál y por qué, sin «con la app»', () => {
    expect(
      auditDetail(
        event('auth.reauth_required', {
          action: 'asset.purge',
          reason: 'recent_auth_required',
          method: 'totp',
        }),
      ),
    ).toBe('Purgar un asset · sin confirmación reciente');
    expect(
      auditDetail(event('auth.reauth', { method: 'oidc', reason: 'auth_time_stale' })),
    ).toBe('OIDC · el proveedor no volvió a pedir las credenciales');
  });
});
