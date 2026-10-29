import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  type CreateUserRequest,
  type TemporaryPasswordResponse,
  type UpdateUserRequest,
  type UserProfile,
  type UserRole,
  type UserSummary,
} from '@infraward/shared-types';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import * as argon2 from 'argon2';
import { DataSource, type EntityManager, Repository } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import { ApiTokensService } from '../auth/api-tokens.service.js';
import { SessionService } from '../auth/session.service.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { isUniqueViolation } from '../database/pg-errors.js';
import { generateTemporaryPassword } from './temporary-password.js';
import { User } from './user.entity.js';

@Injectable()
export class UsersService {
  private readonly localLogin: boolean;
  private readonly oidcEnabled: boolean;
  private readonly emergencyEmail: string | null;

  constructor(
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly sessions: SessionService,
    private readonly apiTokens: ApiTokensService,
    private readonly audit: AuditService,
    private readonly config: ConfigService<EnvironmentVariables, true>,
  ) {
    this.localLogin = config.get('LOCAL_LOGIN', { infer: true });
    this.oidcEnabled = Boolean(config.get('OIDC_ISSUER', { infer: true }));
    const emergency = config.get('LOCAL_LOGIN_EMERGENCY_EMAIL', {
      infer: true,
    });
    this.emergencyEmail = emergency ? normalizeEmail(emergency) : null;
  }

  /** Resumen para Ajustes > Usuarios (marca al admin de emergencia). */
  summary(user: User): UserSummary {
    return toUserSummary(user, this.emergencyEmail);
  }

  findById(id: string): Promise<User | null> {
    return this.users.findOneBy({ id });
  }

  findByEmail(email: string): Promise<User | null> {
    return this.users.findOneBy({ email: normalizeEmail(email) });
  }

  list(): Promise<User[]> {
    return this.users.find({ order: { email: 'ASC' } });
  }

  count(): Promise<number> {
    return this.users.count();
  }

  /** Alta con una contraseña elegida (administrador inicial desde el entorno). */
  async create(
    email: string,
    password: string,
    role: UserRole = 'viewer',
  ): Promise<User> {
    const normalized = normalizeEmail(email);
    return this.users.save(
      this.users.create({
        email: normalized,
        name: defaultName(normalized),
        passwordHash: await hashPassword(password),
        role,
        passwordChangedAt: new Date(),
      }),
    );
  }

  /** Alta desde Ajustes: con una contraseña temporal que el usuario cambia al entrar. */
  async createWithTemporaryPassword(
    dto: CreateUserRequest,
    actor: AuditActor,
  ): Promise<TemporaryPasswordResponse> {
    if (!this.localLogin)
      throw new ConflictException(
        'El login local está desactivado: los usuarios se crean al entrar con el proveedor OIDC',
      );
    const temporaryPassword = generateTemporaryPassword();
    const expiresAt = this.tempExpiry();
    const email = normalizeEmail(dto.email);
    try {
      const user = await this.db.transaction(async (m) => {
        const saved = await m.getRepository(User).save(
          m.getRepository(User).create({
            email,
            name: dto.name.trim(),
            role: dto.role,
            passwordHash: await hashPassword(temporaryPassword),
            mustChangePassword: true,
            tempPasswordExpiresAt: expiresAt,
          }),
        );
        await this.audit.record(actor, 'user.created', {
          target: userTarget(saved),
          details: { role: saved.role, name: saved.name },
          manager: m,
        });
        return saved;
      });
      return {
        user: this.summary(user),
        temporaryPassword,
        expiresAt: expiresAt.toISOString(),
      };
    } catch (error) {
      if (isUniqueViolation(error))
        throw new ConflictException('Ya existe un usuario con ese email');
      throw error;
    }
  }

  /** Cambia nombre, email y/o rol. Nunca deja el sistema sin un admin activo. */
  async update(
    id: string,
    dto: UpdateUserRequest,
    actor: AuditActor,
  ): Promise<UserSummary> {
    const user = await this.db.transaction(async (m) => {
      const admins = await this.lockActiveAdmins(m);
      const target = await this.lockUser(m, id);
      const repo = m.getRepository(User);
      if (dto.name !== undefined && dto.name.trim() !== target.name) {
        const from = target.name;
        target.name = dto.name.trim();
        await repo.update({ id }, { name: target.name });
        await this.audit.record(actor, 'user.updated', {
          target: userTarget(target),
          details: { nameFrom: from, nameTo: target.name },
          manager: m,
        });
      }
      if (dto.email !== undefined)
        await this.changeEmail(m, target, dto.email, actor, false);
      if (dto.role !== undefined && dto.role !== target.role) {
        if (this.oidcEnabled && target.oidcSubject)
          throw new ConflictException(
            'El rol de un usuario enlazado al proveedor OIDC lo decide el proveedor en cada login',
          );
        if (target.role === 'admin' && !target.disabledAt)
          assertAnotherActiveAdmin(admins, id);
        const from = target.role;
        target.role = dto.role;
        await repo.update({ id }, { role: dto.role });
        await this.audit.record(actor, 'user.role_changed', {
          target: userTarget(target),
          details: { from, to: dto.role },
          manager: m,
        });
      }
      return target;
    });
    // Un cambio de rol puede quitarle la terminal: las abiertas se vuelven a comprobar.
    if (dto.role !== undefined) this.sessions.userChanged(id);
    return this.summary(user);
  }

  /**
   * Desactiva: no puede entrar y sus sesiones se borran en la misma transacción (su siguiente
   * petición recibe 401) y sus flujos SSE se cortan tras el commit.
   */
  async deactivate(id: string, actor: AuditActor): Promise<UserSummary> {
    if (id === actor.actorId)
      throw new BadRequestException('No puedes desactivar tu propia cuenta');
    let revoked: string[] = [];
    const user = await this.db.transaction(async (m) => {
      const admins = await this.lockActiveAdmins(m);
      const target = await this.lockUser(m, id);
      if (target.disabledAt) return target;
      if (target.role === 'admin') assertAnotherActiveAdmin(admins, id);
      target.disabledAt = new Date();
      await m
        .getRepository(User)
        .update({ id }, { disabledAt: target.disabledAt });
      revoked = await this.sessions.revokeAllForUser(id, { manager: m });
      const tokensRevoked = await this.apiTokens.revokeAllForUser(
        id,
        actor,
        m,
      );
      await this.audit.record(actor, 'user.deactivated', {
        target: userTarget(target),
        // «token» en la clave lo descartaría el saneador.
        details: {
          sessionsRevoked: revoked.length,
          apiAccessRevoked: tokensRevoked,
        },
        manager: m,
      });
      return target;
    });
    this.sessions.closeStreams(revoked);
    return this.summary(user);
  }

  async reactivate(id: string, actor: AuditActor): Promise<UserSummary> {
    const user = await this.db.transaction(async (m) => {
      const target = await this.lockUser(m, id);
      if (!target.disabledAt) return target;
      target.disabledAt = null;
      await m.getRepository(User).update({ id }, { disabledAt: null });
      await this.audit.record(actor, 'user.reactivated', {
        target: userTarget(target),
        manager: m,
      });
      return target;
    });
    return this.summary(user);
  }

  /** Nueva contraseña temporal de un solo uso; borra las sesiones y revoca sus tokens de API. */
  async resetPassword(
    id: string,
    actor: AuditActor,
  ): Promise<TemporaryPasswordResponse> {
    const temporaryPassword = generateTemporaryPassword();
    const passwordHash = await hashPassword(temporaryPassword);
    const expiresAt = this.tempExpiry();
    let revoked: string[] = [];
    const user = await this.db.transaction(async (m) => {
      const target = await this.lockUser(m, id);
      if (target.origin === 'oidc')
        throw new ConflictException(
          'Un usuario creado por OIDC no tiene contraseña: entra con el proveedor',
        );
      if (!this.localLogin && target.email !== this.emergencyEmail)
        throw new ConflictException(
          'El login local está desactivado: solo el admin de emergencia usa contraseña',
        );
      Object.assign(target, {
        passwordHash,
        mustChangePassword: true,
        tempPasswordExpiresAt: expiresAt,
      });
      await m
        .getRepository(User)
        .update(
          { id },
          {
            passwordHash,
            mustChangePassword: true,
            tempPasswordExpiresAt: expiresAt,
          },
        );
      revoked = await this.sessions.revokeAllForUser(id, { manager: m });
      // Como al desactivar: un reset suele ser por sospecha de compromiso y un token de API
      // (hasta 365 días) seguiría dando acceso sin la contraseña.
      const tokensRevoked = await this.apiTokens.revokeAllForUser(
        id,
        actor,
        m,
      );
      await this.audit.record(actor, 'user.password_reset', {
        target: userTarget(target),
        // «token» en la clave lo descartaría el saneador.
        details: {
          sessionsRevoked: revoked.length,
          apiAccessRevoked: tokensRevoked,
        },
        manager: m,
      });
      return target;
    });
    this.sessions.closeStreams(revoked);
    return {
      user: this.summary(user),
      temporaryPassword,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Cambia el email (lo usan el admin, PATCH /users/:id, y el propio usuario, POST /auth/email)
   * dentro de la transacción del llamante y con la fila ya bloqueada. Normaliza, exige que sea
   * único y lo audita. No se cambia el de una cuenta OIDC o enlazada (el email lo da el proveedor
   * y se usa para enlazar cuentas) ni el del admin de emergencia (va por LOCAL_LOGIN_EMERGENCY_EMAIL).
   */
  async changeEmail(
    m: EntityManager,
    target: User,
    email: string,
    actor: AuditActor,
    self: boolean,
  ): Promise<void> {
    const to = normalizeEmail(email);
    if (to === target.email) return;
    assertEmailChangeAllowed(target, this.emergencyEmail);
    const repo = m.getRepository(User);
    const taken = await repo.findOne({ where: { email: to }, select: { id: true } });
    if (taken && taken.id !== target.id)
      throw new ConflictException('Ya existe un usuario con ese email');
    const from = target.email;
    try {
      await repo.update({ id: target.id }, { email: to });
    } catch (error) {
      if (isUniqueViolation(error))
        throw new ConflictException('Ya existe un usuario con ese email');
      throw error;
    }
    target.email = to;
    await this.audit.record(actor, 'user.email_changed', {
      target: userTarget(target),
      details: { from, to, ...(self ? { self: true } : {}) },
      manager: m,
    });
  }

  private tempExpiry(): Date {
    return new Date(
      Date.now() + this.config.get('TEMP_PASSWORD_TTL', { infer: true }) * 1000,
    );
  }

  private async lockUser(m: EntityManager, id: string): Promise<User> {
    const user = await m
      .getRepository(User)
      .findOne({ where: { id }, lock: { mode: 'pessimistic_write' } });
    if (!user) throw new NotFoundException('Usuario no encontrado');
    return user;
  }

  private lockActiveAdmins(m: EntityManager): Promise<string[]> {
    return lockActiveAdmins(m);
  }
}

/**
 * Bloquea las filas de los admins activos, siempre antes que la del usuario afectado y en el
 * mismo orden: dos cambios simultáneos se esperan en vez de dejar el sistema sin admins (ni
 * interbloquearse). También lo usa el login OIDC, que reevalúa el rol.
 */
export async function lockActiveAdmins(m: EntityManager): Promise<string[]> {
  const rows: { id: string }[] = await m.query(
    `SELECT id FROM users WHERE role = 'admin' AND disabled_at IS NULL ORDER BY id FOR UPDATE`,
  );
  return rows.map((r) => r.id);
}

/** Exige que quede algún admin activo además de `exceptId`. */
export function assertAnotherActiveAdmin(
  activeAdminIds: readonly string[],
  exceptId: string,
): void {
  if (!activeAdminIds.some((id) => id !== exceptId))
    throw new ConflictException(
      'Es el último administrador activo: no se puede desactivar ni quitarle el rol admin',
    );
}

/** Por qué no se puede cambiar el email de una cuenta desde InfraWard (null: sí se puede). */
export function emailChangeBlockedReason(
  user: Pick<User, 'email' | 'origin' | 'oidcSubject'>,
  emergencyEmail: string | null,
): string | null {
  if (user.origin === 'oidc' || user.oidcSubject)
    return 'El email de una cuenta del proveedor OIDC lo gestiona el proveedor';
  if (emergencyEmail !== null && user.email === emergencyEmail)
    return 'El email del admin de emergencia se configura con LOCAL_LOGIN_EMERGENCY_EMAIL';
  return null;
}

export function assertEmailChangeAllowed(
  user: Pick<User, 'email' | 'origin' | 'oidcSubject'>,
  emergencyEmail: string | null,
): void {
  const reason = emailChangeBlockedReason(user, emergencyEmail);
  if (reason) throw new ConflictException(reason);
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function defaultName(email: string): string {
  return email.split('@')[0].slice(0, 120) || email.slice(0, 120);
}

export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, { type: argon2.argon2id });
}

/** Política de contraseñas elegidas por el usuario (la temporal la genera la API). */
export function assertPasswordPolicy(password: string, email: string): void {
  if (
    password.length < PASSWORD_MIN_LENGTH ||
    password.length > PASSWORD_MAX_LENGTH
  )
    throw new BadRequestException(
      `La contraseña debe tener entre ${PASSWORD_MIN_LENGTH} y ${PASSWORD_MAX_LENGTH} caracteres`,
    );
  if (password.trim().toLowerCase() === normalizeEmail(email))
    throw new BadRequestException('La contraseña no puede ser tu email');
}

export function userTarget(user: Pick<User, 'id' | 'email'>) {
  return { type: 'user', id: user.id, label: user.email };
}

export function toUserProfile(u: User): UserProfile {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    origin: u.origin,
    oidcLinked: Boolean(u.oidcSubject),
    mfaEnabled: Boolean(u.totpSecretRef),
    createdAt: u.createdAt.toISOString(),
  };
}

export function toUserSummary(
  u: User,
  emergencyEmail: string | null = null,
): UserSummary {
  return {
    ...toUserProfile(u),
    active: !u.disabledAt,
    mustChangePassword: u.mustChangePassword,
    lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
    emergency: emergencyEmail !== null && u.email === emergencyEmail,
  };
}
