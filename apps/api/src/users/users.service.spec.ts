import { BadRequestException, ConflictException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { DataSource, Repository } from 'typeorm';
import type { AuditService } from '../audit/audit.service.js';
import type { ApiTokensService } from '../auth/api-tokens.service.js';
import type { SessionService } from '../auth/session.service.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import {
  UsersService,
  assertAnotherActiveAdmin,
  assertEmailChangeAllowed,
  assertPasswordPolicy,
  toUserSummary,
} from './users.service.js';
import type { User } from './user.entity.js';

describe('assertAnotherActiveAdmin', () => {
  it('el último admin activo no se desactiva ni se degrada', () => {
    expect(() => assertAnotherActiveAdmin(['a'], 'a')).toThrow(
      ConflictException,
    );
    expect(() => assertAnotherActiveAdmin([], 'a')).toThrow(ConflictException);
  });

  it('con otro admin activo, sí', () => {
    expect(() => assertAnotherActiveAdmin(['a', 'b'], 'a')).not.toThrow();
  });
});

describe('assertPasswordPolicy', () => {
  it('12–1024 caracteres y distinta del email', () => {
    expect(() => assertPasswordPolicy('corta', 'a@b.c')).toThrow(
      BadRequestException,
    );
    expect(() => assertPasswordPolicy('x'.repeat(1025), 'a@b.c')).toThrow(
      BadRequestException,
    );
    expect(() =>
      assertPasswordPolicy('Ana@Example.com', 'ana@example.com'),
    ).toThrow(BadRequestException);
    expect(() =>
      assertPasswordPolicy('una-contraseña-buena', 'a@b.c'),
    ).not.toThrow();
  });
});

describe('assertEmailChangeAllowed', () => {
  const local = { email: 'a@b.c', origin: 'local' as const, oidcSubject: null };

  it('cuenta local normal: sí', () => {
    expect(() => assertEmailChangeAllowed(local, null)).not.toThrow();
    expect(() => assertEmailChangeAllowed(local, 'otro@b.c')).not.toThrow();
  });

  it('cuenta OIDC o enlazada: no (el email lo da el proveedor)', () => {
    expect(() =>
      assertEmailChangeAllowed({ ...local, origin: 'oidc' }, null),
    ).toThrow(ConflictException);
    expect(() =>
      assertEmailChangeAllowed({ ...local, oidcSubject: 'sub' }, null),
    ).toThrow(ConflictException);
  });

  it('admin de emergencia: no (va por LOCAL_LOGIN_EMERGENCY_EMAIL)', () => {
    expect(() => assertEmailChangeAllowed(local, 'a@b.c')).toThrow(
      ConflictException,
    );
  });
});

describe('toUserSummary', () => {
  it('nunca lleva el hash', () => {
    const summary = toUserSummary({
      id: 'u',
      email: 'a@b.c',
      name: 'A',
      passwordHash: 'HASH',
      role: 'viewer',
      origin: 'local',
      oidcIssuer: null,
      oidcSubject: null,
      disabledAt: new Date(),
      mustChangePassword: true,
      tempPasswordExpiresAt: new Date(),
      passwordChangedAt: null,
      lastLoginAt: null,
      vulnerabilitiesSeenAt: null,
      notificationsSeenAt: null,
      totpSecretRef: null,
      totpPendingRef: null,
      totpEnabledAt: null,
      totpLastStep: null,
      createdAt: new Date('2026-10-13T00:00:00Z'),
      updatedAt: new Date(),
    } satisfies User);
    expect(summary).toMatchObject({
      active: false,
      mustChangePassword: true,
      lastLoginAt: null,
      origin: 'local',
      oidcLinked: false,
      emergency: false,
    });
    expect(JSON.stringify(summary)).not.toContain('HASH');
  });
});

describe('UsersService.resetPassword', () => {
  const actor = {
    actorId: 'admin-1',
    actorEmail: 'admin@example.com',
    ip: null,
  };

  function build(target: Partial<User>) {
    const repo = {
      findOne: vi.fn(async () => ({
        id: 'u1',
        email: 'ana@example.com',
        name: 'Ana',
        role: 'editor',
        origin: 'local',
        disabledAt: null,
        oidcSubject: null,
        totpSecretRef: null,
        createdAt: new Date(),
        lastLoginAt: null,
        ...target,
      })),
      update: vi.fn(async () => ({ affected: 1 })),
    };
    const manager = { getRepository: () => repo };
    const db = {
      transaction: (fn: (m: unknown) => unknown) => fn(manager),
    } as unknown as DataSource;
    const sessions = {
      revokeAllForUser: vi.fn(async () => ['s1', 's2']),
      closeStreams: vi.fn(),
    };
    const apiTokens = { revokeAllForUser: vi.fn(async () => 3) };
    const audit = { record: vi.fn(async () => undefined) };
    const env: Record<string, unknown> = {
      LOCAL_LOGIN: true,
      TEMP_PASSWORD_TTL: 3600,
    };
    const config = {
      get: (name: string) => env[name],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    const service = new UsersService(
      {} as unknown as Repository<User>,
      db,
      sessions as unknown as SessionService,
      apiTokens as unknown as ApiTokensService,
      audit as unknown as AuditService,
      config,
    );
    return { service, manager, sessions, apiTokens, audit };
  }

  it('revoca también los tokens de API del usuario (revisión #3, M2)', async () => {
    const { service, manager, sessions, apiTokens, audit } = build({});
    const res = await service.resetPassword('u1', actor);
    expect(res.temporaryPassword).toBeTruthy();
    expect(sessions.revokeAllForUser).toHaveBeenCalledWith('u1', { manager });
    expect(apiTokens.revokeAllForUser).toHaveBeenCalledWith(
      'u1',
      actor,
      manager,
    );
    expect(sessions.closeStreams).toHaveBeenCalledWith(['s1', 's2']);
    expect(audit.record).toHaveBeenCalledWith(
      actor,
      'user.password_reset',
      expect.objectContaining({
        details: { sessionsRevoked: 2, apiAccessRevoked: 3 },
      }),
    );
  });

  it('con una cuenta OIDC no toca nada', async () => {
    const { service, apiTokens } = build({ origin: 'oidc' });
    await expect(service.resetPassword('u1', actor)).rejects.toBeInstanceOf(
      ConflictException,
    );
    expect(apiTokens.revokeAllForUser).not.toHaveBeenCalled();
  });
});
