import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  LoginFailureReason,
  LogoutResponse,
  SensitiveAction,
  SessionInfo,
  UserProfile,
} from '@infraward/shared-types';
import { InjectDataSource } from '@nestjs/typeorm';
import * as argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { UNUSABLE_PASSWORD_HASH } from '../users/temporary-password.js';
import { User } from '../users/user.entity.js';
import {
  assertEmailChangeAllowed,
  assertPasswordPolicy,
  emailChangeBlockedReason,
  hashPassword,
  normalizeEmail,
  toUserProfile,
  userTarget,
  UsersService,
} from '../users/users.service.js';
import { ApiTokensService } from './api-tokens.service.js';
import type {
  AuthenticatedUser,
  RequestSession,
} from './authenticated-user.js';
import { MfaService } from './mfa/mfa.service.js';
import { mfaSetupRequired } from './mfa/mfa-policy.js';
import { OidcService } from './oidc/oidc.service.js';
import { SessionService, type ClientContext } from './session.service.js';
import type { UserSession } from './user-session.entity.js';

export interface LoginResult {
  /** Token para la cookie (nunca va en el cuerpo). */
  token: string;
  info: SessionInfo;
}

@Injectable()
export class AuthService {
  // Hash de relleno: se verifica aunque el usuario no exista para no revelar su existencia por tiempo.
  private readonly dummyHash = argon2.hash(randomBytes(32), {
    type: argon2.argon2id,
  });

  private readonly localLogin: boolean;
  private readonly oidcEnabled: boolean;
  private readonly emergencyEmail: string | null;
  private readonly reauthMaxAgeMs: number;

  constructor(
    private readonly users: UsersService,
    private readonly sessions: SessionService,
    private readonly apiTokens: ApiTokensService,
    private readonly audit: AuditService,
    private readonly oidc: OidcService,
    private readonly mfa: MfaService,
    @InjectDataSource() private readonly db: DataSource,
    config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.reauthMaxAgeMs = config.get('REAUTH_MAX_AGE', { infer: true }) * 1000;
    this.localLogin = config.get('LOCAL_LOGIN', { infer: true });
    this.oidcEnabled = Boolean(config.get('OIDC_ISSUER', { infer: true }));
    const emergency = config.get('LOCAL_LOGIN_EMERGENCY_EMAIL', {
      infer: true,
    });
    this.emergencyEmail = emergency ? normalizeEmail(emergency) : null;
  }

  /**
   * Hacia fuera, cualquier fallo es «Credenciales inválidas» (no revela si la cuenta existe, está
   * desactivada o tiene la temporal caducada); el motivo queda en la auditoría. Con una
   * contraseña temporal, el login la gasta y abre una sesión que solo sirve para cambiarla.
   * Con LOCAL_LOGIN=false solo entra el admin local de emergencia (DESIGN §14).
   */
  async login(
    email: string,
    password: string,
    client: ClientContext,
  ): Promise<LoginResult> {
    const user = await this.users.findByEmail(email);
    const valid = await argon2
      .verify(user?.passwordHash ?? (await this.dummyHash), password)
      .catch(() => false);
    const reason =
      failureReason(user, valid) ??
      (this.localLoginAllowed(user!) ? null : 'local_login_disabled');
    if (reason || !user) {
      await this.audit.record(
        {
          actorId: user?.id ?? null,
          actorEmail: normalizeEmail(email),
          ip: client.ip,
        },
        'auth.login_failed',
        {
          outcome: 'failure',
          target: user ? userTarget(user) : undefined,
          details: { reason: reason ?? 'unknown_user' },
        },
      );
      throw new UnauthorizedException('Credenciales inválidas');
    }

    const purpose = user.mustChangePassword ? 'password_change' : 'full';
    if (purpose === 'password_change') {
      // Con TOTP, la temporal se gasta aquí igualmente: el segundo paso abre la sesión de cambio.
      // Un solo uso: solo la primera de dos peticiones simultáneas la gasta.
      const res = await this.db
        .getRepository(User)
        .update(
          { id: user.id, passwordHash: user.passwordHash },
          { passwordHash: UNUSABLE_PASSWORD_HASH, tempPasswordExpiresAt: null },
        );
      if (!res.affected)
        throw new UnauthorizedException('Credenciales inválidas');
    }
    if (user.totpSecretRef) {
      const pending = await this.sessions.create(user.id, 'mfa', client, {
        authMethod: 'password',
      });
      return { token: pending.token, info: this.sessionInfo(user, pending.session) };
    }
    return this.completeLogin(user, purpose, client, null);
  }

  /**
   * Segundo paso del login: código TOTP o de recuperación con la sesión intermedia. Si vale, la
   * cambia por una nueva (otra cookie: sin fijación de sesión) con la identidad recién
   * confirmada; a los 5 fallos la sesión intermedia se borra y hay que volver a empezar.
   */
  async verifyMfa(
    userId: string,
    session: RequestSession,
    code: string,
    client: ClientContext,
  ): Promise<LoginResult> {
    const user = await this.users.findById(userId);
    if (!user || session.purpose !== 'mfa') throw new UnauthorizedException();
    const actor = { actorId: user.id, actorEmail: user.email, ip: client.ip };
    const verified = await this.mfa.verify(user, code);
    if (!verified) {
      const alive = await this.sessions.recordMfaFailure(session.id);
      await this.audit.record(actor, 'auth.mfa_challenge', {
        outcome: 'failure',
        target: userTarget(user),
        details: { reason: 'bad_code', sessionClosed: !alive },
      });
      if (!alive)
        throw new UnauthorizedException(
          'Demasiados códigos incorrectos: vuelve a entrar',
        );
      throw new BadRequestException('El código no es correcto');
    }
    await this.sessions.revoke(session.id);
    await this.audit.record(actor, 'auth.mfa_challenge', {
      target: userTarget(user),
      details: {
        method: verified.method,
        ...(verified.recoveryCodesLeft !== null
          ? { recoveryCodesLeft: verified.recoveryCodesLeft }
          : {}),
      },
    });
    const purpose = user.mustChangePassword ? 'password_change' : 'full';
    return this.completeLogin(user, purpose, client, verified.method);
  }

  /** Abre la sesión definitiva y audita el login. */
  private async completeLogin(
    user: User,
    purpose: 'full' | 'password_change',
    client: ClientContext,
    mfaMethod: 'totp' | 'recovery' | null,
  ): Promise<LoginResult> {
    const now = new Date();
    await this.db
      .getRepository(User)
      .update({ id: user.id }, { lastLoginAt: now });
    const { token, session } = await this.sessions.create(
      user.id,
      purpose,
      client,
      { authMethod: 'password', reauthenticatedAt: mfaMethod ? now : null },
    );
    await this.audit.record(
      { actorId: user.id, actorEmail: user.email, ip: client.ip },
      'auth.login',
      {
        target: userTarget(user),
        details: {
          forcedChange: purpose === 'password_change',
          ...(mfaMethod ? { mfa: mfaMethod } : {}),
        },
      },
    );
    return { token, info: this.sessionInfo(user, session) };
  }

  /**
   * Reautenticación reciente (step-up) de una sesión local con un código TOTP o de
   * recuperación. Las sesiones OIDC se reautentican en el proveedor (GET /auth/oidc/reauth).
   */
  async reauthenticate(
    userId: string,
    session: RequestSession,
    code: string,
    action: SensitiveAction | undefined,
    actor: AuditActor,
  ): Promise<{ reauthenticatedUntil: string }> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    if (session.authMethod === 'oidc')
      throw new ConflictException(
        'Tu sesión viene del proveedor OIDC: confirma tu identidad allí',
      );
    if (!user.totpSecretRef)
      throw new ConflictException(
        'Activa la verificación en dos pasos en tu perfil para confirmar tu identidad',
      );
    const verified = await this.mfa.verify(user, code);
    const details = { method: 'totp', ...(action ? { action } : {}) };
    if (!verified) {
      await this.audit.record(actor, 'auth.reauth', {
        outcome: 'failure',
        target: userTarget(user),
        details: { ...details, reason: 'bad_code' },
      });
      throw new BadRequestException('El código no es correcto');
    }
    const now = new Date();
    await this.sessions.markReauthenticated(session.id, now);
    await this.audit.record(actor, 'auth.reauth', {
      target: userTarget(user),
      details: {
        ...details,
        method: verified.method,
        ...(verified.recoveryCodesLeft !== null
          ? { recoveryCodesLeft: verified.recoveryCodesLeft }
          : {}),
      },
    });
    return {
      reauthenticatedUntil: new Date(
        now.getTime() + this.reauthMaxAgeMs,
      ).toISOString(),
    };
  }

  async session(
    user: AuthenticatedUser,
    session: RequestSession,
  ): Promise<SessionInfo> {
    const current = await this.users.findById(user.id);
    if (!current) throw new UnauthorizedException();
    return this.sessionInfo(current, session);
  }

  /**
   * Cierra la sesión. Si se abrió con el proveedor OIDC y este admite RP-Initiated Logout,
   * devuelve la URL para cerrar también la suya (la web navega a ella).
   */
  async logout(
    session: RequestSession,
    actor: AuditActor,
  ): Promise<LogoutResponse> {
    const idToken = await this.sessions.oidcIdToken(session.id);
    await this.sessions.revoke(session.id);
    const providerLogoutUrl = await this.oidc.endSessionUrl(idToken);
    await this.audit.record(actor, 'auth.logout', {
      target: actor.actorId
        ? { type: 'user', id: actor.actorId, label: actor.actorEmail }
        : undefined,
      details: idToken
        ? { method: 'oidc', providerLogout: providerLogoutUrl !== null }
        : {},
    });
    return { providerLogoutUrl };
  }

  private sessionInfo(
    user: User,
    session: Pick<
      UserSession,
      'purpose' | 'csrfToken' | 'expiresAt' | 'authMethod' | 'reauthenticatedAt'
    >,
  ): SessionInfo {
    const reauthAt = session.reauthenticatedAt?.getTime();
    return {
      user: toProfile(user),
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt.toISOString(),
      mustChangePassword: session.purpose === 'password_change',
      canChangeEmail:
        !this.oidcEnabled &&
        emailChangeBlockedReason(user, this.emergencyEmail) === null,
      mfaPending: session.purpose === 'mfa',
      mfaSetupRequired:
        session.purpose === 'full' &&
        mfaSetupRequired(user, session.authMethod),
      reauthMethod: session.authMethod === 'oidc' ? 'oidc' : 'totp',
      reauthenticatedUntil:
        reauthAt !== undefined
          ? new Date(reauthAt + this.reauthMaxAgeMs).toISOString()
          : null,
    };
  }

  /** Con el login local desactivado, solo el admin de emergencia (local, sin enlazar). */
  private localLoginAllowed(user: User): boolean {
    if (this.localLogin) return true;
    return (
      this.emergencyEmail !== null &&
      user.email === this.emergencyEmail &&
      user.role === 'admin' &&
      user.origin === 'local' &&
      !user.oidcSubject
    );
  }

  async profile(userId: string): Promise<UserProfile> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    return toProfile(user);
  }

  async updateProfile(
    userId: string,
    name: string,
    actor: AuditActor,
  ): Promise<UserProfile> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    const trimmed = name.trim();
    if (trimmed !== user.name) {
      const from = user.name;
      user.name = trimmed;
      await this.db
        .getRepository(User)
        .update({ id: userId }, { name: trimmed });
      await this.audit.record(actor, 'user.updated', {
        target: userTarget(user),
        details: { nameFrom: from, nameTo: trimmed, self: true },
      });
    }
    return toProfile(user);
  }

  /**
   * Cambia el email propio: pide la contraseña actual (cuentas locales; las OIDC o enlazadas
   * reciben 409, su email lo da el proveedor). Las sesiones siguen abiertas.
   *
   * Con OIDC configurado no se permite: el login OIDC enlaza una cuenta local por email
   * verificado y le aplica el rol de los grupos, así que quien eligiera el email de otro aún
   * sin enlazar heredaría su rol (y seguiría entrando con su contraseña). Lo cambia un admin.
   */
  async changeEmail(
    userId: string,
    email: string,
    currentPassword: string,
    actor: AuditActor,
  ): Promise<UserProfile> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    if (this.oidcEnabled) throw new ConflictException(OIDC_SELF_EMAIL);
    // Antes de verificar la contraseña: una cuenta que no puede cambiarlo recibe 409, no 400.
    assertEmailChangeAllowed(user, this.emergencyEmail);
    const ok = await argon2
      .verify(user.passwordHash, currentPassword)
      .catch(() => false);
    if (!ok) {
      await this.audit.record(actor, 'user.email_changed', {
        outcome: 'failure',
        target: userTarget(user),
        details: { reason: 'bad_current', self: true },
      });
      throw new BadRequestException('La contraseña actual no es correcta');
    }
    const updated = await this.db.transaction(async (m) => {
      const target = await m.getRepository(User).findOne({
        where: { id: userId },
        lock: { mode: 'pessimistic_write' },
      });
      if (!target) throw new UnauthorizedException();
      await this.users.changeEmail(m, target, email, actor, true);
      return target;
    });
    return toProfile(updated);
  }

  /**
   * Cambia la contraseña propia. Con una sesión normal pide la actual; con la sesión de una
   * temporal (ya gastada al entrar) no hace falta. Cierra todas sus sesiones, revoca sus tokens de
   * API y abre una sesión nueva.
   */
  async changePassword(
    userId: string,
    session: RequestSession,
    currentPassword: string | undefined,
    newPassword: string,
    client: ClientContext,
  ): Promise<LoginResult> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException();
    const forced = session.purpose === 'password_change';
    const actor = { actorId: user.id, actorEmail: user.email, ip: client.ip };
    if (user.origin === 'oidc')
      throw new BadRequestException(
        'Tu cuenta entra con el proveedor OIDC: no tiene contraseña en InfraWard',
      );
    if (!forced) {
      const ok = await argon2
        .verify(user.passwordHash, currentPassword ?? '')
        .catch(() => false);
      if (!ok) {
        await this.audit.record(actor, 'auth.password_changed', {
          outcome: 'failure',
          target: userTarget(user),
          details: { reason: 'bad_current' },
        });
        throw new BadRequestException('La contraseña actual no es correcta');
      }
      if (currentPassword === newPassword)
        throw new BadRequestException(
          'La nueva contraseña debe ser distinta de la actual',
        );
    }
    assertPasswordPolicy(newPassword, user.email);

    const passwordHash = await hashPassword(newPassword);
    let revoked: string[] = [];
    await this.db.transaction(async (m) => {
      await m.getRepository(User).update(
        { id: user.id },
        {
          passwordHash,
          mustChangePassword: false,
          tempPasswordExpiresAt: null,
          passwordChangedAt: new Date(),
        },
      );
      revoked = await this.sessions.revokeAllForUser(user.id, { manager: m });
      // Cambiar la contraseña corta todo el acceso anterior (sesiones y tokens), como el reset y
      // la desactivación: si alguien la conocía, pudo crearse un token que la sobreviviría.
      const tokensRevoked = await this.apiTokens.revokeAllForUser(
        user.id,
        actor,
        m,
      );
      await this.audit.record(actor, 'auth.password_changed', {
        target: userTarget(user),
        // «token» en la clave lo descartaría el saneador.
        details: {
          forced,
          sessionsRevoked: revoked.length,
          apiAccessRevoked: tokensRevoked,
        },
        manager: m,
      });
    });
    this.sessions.closeStreams(revoked);
    user.mustChangePassword = false;
    const created = await this.sessions.create(user.id, 'full', client, {
      authMethod: session.authMethod,
    });
    return { token: created.token, info: this.sessionInfo(user, created.session) };
  }
}

function failureReason(
  user: User | null,
  validPassword: boolean,
): LoginFailureReason | null {
  if (!user) return 'unknown_user';
  if (!validPassword) return 'bad_password';
  if (user.disabledAt) return 'disabled';
  if (
    user.mustChangePassword &&
    (!user.tempPasswordExpiresAt ||
      user.tempPasswordExpiresAt.getTime() <= Date.now())
  )
    return 'temp_expired';
  return null;
}

function toProfile(user: User): UserProfile {
  return toUserProfile(user);
}

const OIDC_SELF_EMAIL =
  'Con el inicio de sesión OIDC activo, el email lo cambia un administrador';
