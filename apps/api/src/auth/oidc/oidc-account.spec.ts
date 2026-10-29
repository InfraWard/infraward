import type { User } from '../../users/user.entity.js';
import { decideAccount, type OidcIdentity } from './oidc-account.js';

const identity: OidcIdentity = {
  issuer: 'https://idp.example.com',
  subject: 'sub-1',
  email: 'ana@example.com',
  emailVerified: true,
  name: 'Ana',
  groups: [],
};

function user(over: Partial<User> = {}): User {
  return {
    id: 'u1',
    email: 'ana@example.com',
    disabledAt: null,
    oidcIssuer: null,
    oidcSubject: null,
    origin: 'local',
    role: 'viewer',
    ...over,
  } as User;
}

describe('decideAccount', () => {
  it('la identidad ya enlazada (issuer + sub) manda', () => {
    const linked = user({ oidcSubject: 'sub-1', oidcIssuer: identity.issuer });
    expect(decideAccount(identity, linked, null, null)).toEqual({
      kind: 'existing',
      user: linked,
    });
    // Aunque el email ya no esté verificado o haya cambiado.
    expect(
      decideAccount(
        { ...identity, emailVerified: false, email: null },
        linked,
        null,
        null,
      ).kind,
    ).toBe('existing');
  });

  it('enlazada pero desactivada → disabled', () => {
    const linked = user({ oidcSubject: 'sub-1', disabledAt: new Date() });
    expect(decideAccount(identity, linked, null, null)).toMatchObject({
      kind: 'reject',
      reason: 'disabled',
      error: 'disabled',
    });
  });

  it('nadie con esa identidad ni ese email → alta', () => {
    expect(decideAccount(identity, null, null, null)).toEqual({
      kind: 'create',
    });
  });

  it('alta solo con el email verificado (revisión #3, M3)', () => {
    expect(
      decideAccount({ ...identity, emailVerified: false }, null, null, null),
    ).toEqual({
      kind: 'reject',
      reason: 'email_unverified',
      error: 'email_unverified',
    });
    // Proveedores que no mandan email_verified (Entra): solo con el interruptor explícito.
    expect(
      decideAccount({ ...identity, emailVerified: false }, null, null, null, {
        allowUnverifiedSignup: true,
      }),
    ).toEqual({ kind: 'create' });
  });

  it('el interruptor nunca permite enlazar con una cuenta local sin verificar', () => {
    expect(
      decideAccount({ ...identity, emailVerified: false }, null, user(), null, {
        allowUnverifiedSignup: true,
      }),
    ).toMatchObject({ reason: 'email_unverified', error: 'email_conflict' });
  });

  it('sin email → no se puede crear ni enlazar', () => {
    expect(
      decideAccount({ ...identity, email: null }, null, null, null),
    ).toMatchObject({
      kind: 'reject',
      reason: 'email_missing',
      error: 'failed',
    });
  });

  it('email de un usuario local: se enlaza solo si está verificado', () => {
    const local = user();
    expect(decideAccount(identity, null, local, null)).toEqual({
      kind: 'link',
      user: local,
    });
    expect(
      decideAccount({ ...identity, emailVerified: false }, null, local, null),
    ).toMatchObject({
      kind: 'reject',
      reason: 'email_unverified',
      error: 'email_conflict',
    });
  });

  it('nunca enlaza una cuenta ya enlazada a otra identidad ni la de emergencia', () => {
    expect(
      decideAccount(identity, null, user({ oidcSubject: 'otro' }), null),
    ).toMatchObject({ reason: 'already_linked', error: 'email_conflict' });
    expect(
      decideAccount(identity, null, user(), 'ana@example.com'),
    ).toMatchObject({ reason: 'emergency_account', error: 'email_conflict' });
  });

  it('enlazar con una cuenta desactivada → disabled', () => {
    expect(
      decideAccount(identity, null, user({ disabledAt: new Date() }), null),
    ).toMatchObject({ reason: 'disabled', error: 'disabled' });
  });
});
