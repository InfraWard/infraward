import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import type { DataSource } from 'typeorm';
import type { AuditService } from '../audit/audit.service.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { UNUSABLE_PASSWORD_HASH } from '../users/temporary-password.js';
import type { User } from '../users/user.entity.js';
import type { UsersService } from '../users/users.service.js';
import type { ApiTokensService } from './api-tokens.service.js';
import { AuthService } from './auth.service.js';
import type { MfaService } from './mfa/mfa.service.js';
import type { OidcService } from './oidc/oidc.service.js';
import type { SessionService } from './session.service.js';

const client = { ip: '203.0.113.7', userAgent: 'vitest' };
const FULL_SESSION = {
  id: 's1',
  purpose: 'full' as const,
  csrfToken: 'c',
  expiresAt: new Date(),
  authMethod: 'password' as const,
  reauthenticatedAt: null,
};

describe('AuthService', () => {
  let hash: string;
  let user: User;
  let service: AuthService;
  let sessions: {
    create: ReturnType<typeof vi.fn>;
    revokeAllForUser: ReturnType<typeof vi.fn>;
    closeStreams: ReturnType<typeof vi.fn>;
    revoke: ReturnType<typeof vi.fn>;
    recordMfaFailure: ReturnType<typeof vi.fn>;
    markReauthenticated: ReturnType<typeof vi.fn>;
  };
  let apiTokens: { revokeAllForUser: ReturnType<typeof vi.fn> };
  let mfa: { verify: ReturnType<typeof vi.fn> };
  let audit: { record: ReturnType<typeof vi.fn> };
  let repo: { update: ReturnType<typeof vi.fn> };
  let env: Record<string, unknown>;

  function build(): AuthService {
    const manager = { getRepository: () => repo };
    const db = {
      getRepository: () => repo,
      transaction: (fn: (m: unknown) => unknown) => fn(manager),
    } as unknown as DataSource;
    const users = {
      findByEmail: async (email: string) =>
        email.trim().toLowerCase() === user.email ? user : null,
      findById: async (id: string) => (id === user.id ? user : null),
    } as unknown as UsersService;
    const oidc = {
      endSessionUrl: vi.fn(async () => null),
    } as unknown as OidcService;
    const config = {
      get: (name: string) => env[name],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    return new AuthService(
      users,
      sessions as unknown as SessionService,
      apiTokens as unknown as ApiTokensService,
      audit as unknown as AuditService,
      oidc,
      mfa as unknown as MfaService,
      db,
      config,
    );
  }

  beforeAll(async () => {
    hash = await argon2.hash('correcta-y-larga');
  });

  beforeEach(() => {
    user = {
      id: '00000000-0000-4000-8000-000000000001',
      email: 'ana@example.com',
      name: 'Ana',
      passwordHash: hash,
      role: 'viewer',
      origin: 'local',
      oidcIssuer: null,
      oidcSubject: null,
      disabledAt: null,
      mustChangePassword: false,
      tempPasswordExpiresAt: null,
      passwordChangedAt: null,
      lastLoginAt: null,
      vulnerabilitiesSeenAt: null,
      notificationsSeenAt: null,
      totpSecretRef: null,
      totpPendingRef: null,
      totpEnabledAt: null,
      totpLastStep: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    sessions = {
      create: vi.fn(
        async (
          _id: string,
          purpose: string,
          _client: unknown,
          options: { reauthenticatedAt?: Date | null } = {},
        ) => ({
          token: purpose === 'mfa' ? 'tok-mfa' : 'tok',
          session: {
            id: 's1',
            purpose,
            csrfToken: 'csrf',
            expiresAt: new Date('2026-10-13T12:00:00Z'),
            authMethod: 'password',
            reauthenticatedAt: options.reauthenticatedAt ?? null,
          },
        }),
      ),
      revokeAllForUser: vi.fn(async () => ['s0']),
      closeStreams: vi.fn(),
      revoke: vi.fn(),
      recordMfaFailure: vi.fn(async () => true),
      markReauthenticated: vi.fn(async () => undefined),
    };
    apiTokens = { revokeAllForUser: vi.fn(async () => 2) };
    mfa = { verify: vi.fn(async () => null) };
    audit = { record: vi.fn(async () => undefined) };
    repo = { update: vi.fn(async () => ({ affected: 1 })) };
    env = { LOCAL_LOGIN: true, REAUTH_MAX_AGE: 600 };
    service = build();
  });

  const lastAudit = () => audit.record.mock.calls.at(-1)!;

  it('abre una sesión completa: token solo para la cookie, CSRF y perfil en el cuerpo', async () => {
    const res = await service.login(
      'Ana@Example.com ',
      'correcta-y-larga',
      client,
    );
    expect(res.token).toBe('tok');
    expect(res.info).toMatchObject({
      csrfToken: 'csrf',
      mustChangePassword: false,
      user: { email: 'ana@example.com', name: 'Ana', role: 'viewer' },
    });
    expect(JSON.stringify(res.info)).not.toContain('tok"');
    expect(sessions.create).toHaveBeenCalledWith(user.id, 'full', client, {
      authMethod: 'password',
      reauthenticatedAt: null,
    });
    expect(lastAudit()[1]).toBe('auth.login');
    expect(lastAudit()[0]).toMatchObject({ ip: client.ip, actorId: user.id });
  });

  it.each([
    ['contraseña incorrecta', 'ana@example.com', 'mala', 'bad_password'],
    [
      'usuario inexistente',
      'nadie@example.com',
      'correcta-y-larga',
      'unknown_user',
    ],
  ])(
    '%s → 401 genérico y auditado con su motivo',
    async (_n, email, pwd, reason) => {
      await expect(service.login(email, pwd, client)).rejects.toThrow(
        new UnauthorizedException('Credenciales inválidas'),
      );
      const [actor, action, options] = lastAudit();
      expect(action).toBe('auth.login_failed');
      expect(actor).toMatchObject({ actorEmail: email, ip: client.ip });
      expect(options).toMatchObject({
        outcome: 'failure',
        details: { reason },
      });
      expect(JSON.stringify(audit.record.mock.calls)).not.toContain(
        pwd === 'mala' ? 'mala' : 'correcta',
      );
      expect(sessions.create).not.toHaveBeenCalled();
    },
  );

  it('desactivado: mismo 401 aunque la contraseña sea buena', async () => {
    user.disabledAt = new Date();
    await expect(
      service.login(user.email, 'correcta-y-larga', client),
    ).rejects.toThrow('Credenciales inválidas');
    expect(lastAudit()[2]).toMatchObject({ details: { reason: 'disabled' } });
  });

  it('contraseña temporal caducada → 401', async () => {
    user.mustChangePassword = true;
    user.tempPasswordExpiresAt = new Date(Date.now() - 1000);
    await expect(
      service.login(user.email, 'correcta-y-larga', client),
    ).rejects.toThrow(UnauthorizedException);
    expect(lastAudit()[2]).toMatchObject({
      details: { reason: 'temp_expired' },
    });
  });

  it('contraseña temporal: la gasta (un solo uso) y abre una sesión limitada', async () => {
    user.mustChangePassword = true;
    user.tempPasswordExpiresAt = new Date(Date.now() + 60_000);
    const res = await service.login(user.email, 'correcta-y-larga', client);
    expect(repo.update).toHaveBeenCalledWith(
      { id: user.id, passwordHash: hash },
      { passwordHash: UNUSABLE_PASSWORD_HASH, tempPasswordExpiresAt: null },
    );
    expect(sessions.create).toHaveBeenCalledWith(
      user.id,
      'password_change',
      client,
      { authMethod: 'password', reauthenticatedAt: null },
    );
    expect(res.info.mustChangePassword).toBe(true);
  });

  it('dos logins simultáneos con la misma temporal: solo uno entra', async () => {
    user.mustChangePassword = true;
    user.tempPasswordExpiresAt = new Date(Date.now() + 60_000);
    repo.update.mockResolvedValueOnce({ affected: 0 });
    await expect(
      service.login(user.email, 'correcta-y-larga', client),
    ).rejects.toThrow(UnauthorizedException);
    expect(sessions.create).not.toHaveBeenCalled();
  });

  describe('login local desactivado (LOCAL_LOGIN=false)', () => {
    beforeEach(() => {
      env = {
        LOCAL_LOGIN: false,
        LOCAL_LOGIN_EMERGENCY_EMAIL: 'Ana@Example.com',
      };
      user.role = 'admin';
      service = build();
    });

    it('entra el admin local de emergencia', async () => {
      await expect(
        service.login('ana@example.com', 'correcta-y-larga', client),
      ).resolves.toMatchObject({ token: 'tok' });
    });

    it('cualquier otro: el mismo 401 y el motivo en la auditoría', async () => {
      env.LOCAL_LOGIN_EMERGENCY_EMAIL = 'otra@example.com';
      service = build();
      await expect(
        service.login('ana@example.com', 'correcta-y-larga', client),
      ).rejects.toThrow(UnauthorizedException);
      expect(lastAudit()[2]).toMatchObject({
        details: { reason: 'local_login_disabled' },
      });
      expect(sessions.create).not.toHaveBeenCalled();
    });

    it('la de emergencia tiene que ser admin, local y sin enlazar al proveedor', async () => {
      for (const change of [
        { role: 'editor' as const },
        { origin: 'oidc' as const },
        { oidcSubject: 'sub-1', oidcIssuer: 'https://idp' },
      ]) {
        Object.assign(
          user,
          { role: 'admin', origin: 'local', oidcSubject: null },
          change,
        );
        await expect(
          service.login('ana@example.com', 'correcta-y-larga', client),
        ).rejects.toThrow(UnauthorizedException);
        expect(lastAudit()[2]).toMatchObject({
          details: { reason: 'local_login_disabled' },
        });
      }
    });

    it('con contraseña incorrecta el motivo sigue siendo bad_password', async () => {
      env.LOCAL_LOGIN_EMERGENCY_EMAIL = 'otra@example.com';
      service = build();
      await expect(
        service.login('ana@example.com', 'mala', client),
      ).rejects.toThrow(UnauthorizedException);
      expect(lastAudit()[2]).toMatchObject({
        details: { reason: 'bad_password' },
      });
    });
  });

  it('una cuenta creada por OIDC no puede cambiar la contraseña', async () => {
    user.origin = 'oidc';
    await expect(
      service.changePassword(
        user.id,
        FULL_SESSION,
        'x',
        'una-contraseña-nueva-larga',
        client,
      ),
    ).rejects.toThrow(BadRequestException);
  });

  describe('changePassword', () => {
    const full = FULL_SESSION;
    const limited = { ...full, purpose: 'password_change' as const };

    it('con sesión normal exige la actual', async () => {
      await expect(
        service.changePassword(
          user.id,
          full,
          'mala',
          'nueva-contraseña-larga',
          client,
        ),
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(lastAudit()[2]).toMatchObject({ outcome: 'failure' });
      expect(sessions.revokeAllForUser).not.toHaveBeenCalled();
      expect(apiTokens.revokeAllForUser).not.toHaveBeenCalled();
    });

    it('aplica la política (longitud, no el email, distinta de la actual)', async () => {
      for (const bad of ['corta', 'ana@example.com', 'correcta-y-larga'])
        await expect(
          service.changePassword(
            user.id,
            full,
            'correcta-y-larga',
            bad,
            client,
          ),
        ).rejects.toBeInstanceOf(BadRequestException);
    });

    it('cierra todas las sesiones, revoca los tokens de API y abre una sesión nueva', async () => {
      const res = await service.changePassword(
        user.id,
        full,
        'correcta-y-larga',
        'nueva-contraseña-larga',
        client,
      );
      expect(sessions.revokeAllForUser).toHaveBeenCalled();
      expect(apiTokens.revokeAllForUser).toHaveBeenCalledWith(
        user.id,
        expect.objectContaining({ actorId: user.id }),
        expect.anything(),
      );
      expect(sessions.closeStreams).toHaveBeenCalledWith(['s0']);
      expect(sessions.create).toHaveBeenCalledWith(user.id, 'full', client, {
        authMethod: 'password',
      });
      expect(res.info.mustChangePassword).toBe(false);
      const update = repo.update.mock.calls.at(-1)![1] as Record<
        string,
        unknown
      >;
      expect(update).toMatchObject({
        mustChangePassword: false,
        tempPasswordExpiresAt: null,
      });
      expect(
        await argon2.verify(
          update.passwordHash as string,
          'nueva-contraseña-larga',
        ),
      ).toBe(true);
      expect(lastAudit()[1]).toBe('auth.password_changed');
      expect(lastAudit()[2]).toMatchObject({
        details: { sessionsRevoked: 1, apiAccessRevoked: 2 },
      });
      expect(JSON.stringify(audit.record.mock.calls)).not.toContain(
        'nueva-contraseña',
      );
    });

    it('con la sesión de una temporal no pide la actual', async () => {
      user.passwordHash = UNUSABLE_PASSWORD_HASH;
      user.mustChangePassword = true;
      await service.changePassword(
        user.id,
        limited,
        undefined,
        'nueva-contraseña-larga',
        client,
      );
      expect(lastAudit()[2]).toMatchObject({ details: { forced: true } });
    });
  });

  describe('verificación en dos pasos', () => {
    const pending = { ...FULL_SESSION, purpose: 'mfa' as const };

    beforeEach(() => {
      user.totpSecretRef = 'secret://local/infraward/users/u/totp/x#secret';
    });

    it('con TOTP, la contraseña solo abre la sesión intermedia (sin auditar el login)', async () => {
      const res = await service.login(user.email, 'correcta-y-larga', client);
      expect(res.token).toBe('tok-mfa');
      expect(res.info).toMatchObject({ mfaPending: true, mustChangePassword: false });
      expect(sessions.create).toHaveBeenCalledWith(user.id, 'mfa', client, {
        authMethod: 'password',
      });
      expect(audit.record).not.toHaveBeenCalled();
    });

    it('código correcto: cambia la sesión intermedia por una nueva ya reautenticada', async () => {
      mfa.verify.mockResolvedValue({ method: 'totp', recoveryCodesLeft: null });
      const res = await service.verifyMfa(user.id, pending, '123456', client);
      expect(sessions.revoke).toHaveBeenCalledWith('s1');
      expect(res.token).toBe('tok');
      expect(res.info.mfaPending).toBe(false);
      expect(res.info.reauthenticatedUntil).not.toBeNull();
      expect(audit.record.mock.calls.map((c) => c[1])).toEqual([
        'auth.mfa_challenge',
        'auth.login',
      ]);
      expect(lastAudit()[2]).toMatchObject({ details: { mfa: 'totp' } });
    });

    it('código incorrecto: 400, cuenta el fallo y lo audita; al último, 401', async () => {
      await expect(
        service.verifyMfa(user.id, pending, '000000', client),
      ).rejects.toThrow(BadRequestException);
      expect(sessions.recordMfaFailure).toHaveBeenCalledWith('s1');
      expect(lastAudit()[1]).toBe('auth.mfa_challenge');
      expect(lastAudit()[2]).toMatchObject({ outcome: 'failure' });
      sessions.recordMfaFailure.mockResolvedValue(false);
      await expect(
        service.verifyMfa(user.id, pending, '000000', client),
      ).rejects.toThrow(UnauthorizedException);
      expect(sessions.create).not.toHaveBeenCalled();
    });

    it('solo con la sesión intermedia', async () => {
      await expect(
        service.verifyMfa(user.id, FULL_SESSION, '123456', client),
      ).rejects.toThrow(UnauthorizedException);
      expect(mfa.verify).not.toHaveBeenCalled();
    });

    it('con una temporal pendiente, el segundo paso abre la sesión de cambio', async () => {
      user.mustChangePassword = true;
      mfa.verify.mockResolvedValue({ method: 'recovery', recoveryCodesLeft: 9 });
      const res = await service.verifyMfa(user.id, pending, 'abcd-efgh-jkmn-pqrs', client);
      expect(res.info.mustChangePassword).toBe(true);
    });

    it('un admin local sin TOTP entra con la sesión que exige configurarlo', async () => {
      user.totpSecretRef = null;
      user.role = 'admin';
      const res = await service.login(user.email, 'correcta-y-larga', client);
      expect(res.info).toMatchObject({ mfaPending: false, mfaSetupRequired: true });
    });
  });

  describe('reautenticación reciente', () => {
    beforeEach(() => {
      user.totpSecretRef = 'secret://local/infraward/users/u/totp/x#secret';
    });
    const actor = { actorId: 'u', actorEmail: 'ana@example.com', ip: client.ip };

    it('código correcto: marca la sesión y lo audita con la acción', async () => {
      mfa.verify.mockResolvedValue({ method: 'totp', recoveryCodesLeft: null });
      const res = await service.reauthenticate(
        user.id,
        FULL_SESSION,
        '123456',
        'asset.purge',
        actor,
      );
      expect(sessions.markReauthenticated).toHaveBeenCalledWith('s1', expect.any(Date));
      expect(Date.parse(res.reauthenticatedUntil) - Date.now()).toBeGreaterThan(590_000);
      expect(lastAudit()[1]).toBe('auth.reauth');
      expect(lastAudit()[2]).toMatchObject({
        details: { method: 'totp', action: 'asset.purge' },
      });
    });

    it('código incorrecto: 400 y fallo auditado, sin marcar', async () => {
      await expect(
        service.reauthenticate(user.id, FULL_SESSION, '000000', undefined, actor),
      ).rejects.toThrow(BadRequestException);
      expect(sessions.markReauthenticated).not.toHaveBeenCalled();
      expect(lastAudit()[2]).toMatchObject({ outcome: 'failure' });
    });

    it('sin TOTP o con una sesión OIDC: 409', async () => {
      await expect(
        service.reauthenticate(
          user.id,
          { ...FULL_SESSION, authMethod: 'oidc' },
          '123456',
          undefined,
          actor,
        ),
      ).rejects.toThrow(ConflictException);
      user.totpSecretRef = null;
      await expect(
        service.reauthenticate(user.id, FULL_SESSION, '123456', undefined, actor),
      ).rejects.toThrow(ConflictException);
      expect(mfa.verify).not.toHaveBeenCalled();
    });
  });
});
