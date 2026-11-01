import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash, randomBytes } from 'node:crypto';
import { In, type EntityManager, Repository } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { User } from '../users/user.entity.js';
import { SessionRegistry } from './session-registry.js';
import {
  UserSession,
  type SessionAuthMethod,
  type SessionPurpose,
} from './user-session.entity.js';

/** Vida de una sesión que solo sirve para cambiar la contraseña temporal. */
export const PASSWORD_CHANGE_SESSION_TTL_MS = 15 * 60 * 1000;
/** Vida de la sesión intermedia del login (contraseña buena, falta el código TOTP). */
export const MFA_SESSION_TTL_MS = 5 * 60 * 1000;
/** Códigos fallidos que admite la sesión intermedia antes de borrarse. */
export const MFA_SESSION_MAX_FAILURES = 5;
/** `last_seen_at` se actualiza como mucho una vez por minuto. */
const TOUCH_INTERVAL_MS = 60 * 1000;

export interface ClientContext {
  ip: string | null;
  userAgent: string | null;
}

export interface CreatedSession {
  /** Token en claro: solo para la cookie (aquí se guarda su sha256). */
  token: string;
  session: UserSession;
}

export function hashSessionToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

/** Sesiones web opacas (DESIGN §14): crear, resolver la de la cookie y revocar. */
@Injectable()
export class SessionService {
  constructor(
    @InjectRepository(UserSession)
    private readonly sessions: Repository<UserSession>,
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly registry: SessionRegistry,
  ) {}

  async create(
    userId: string,
    purpose: SessionPurpose,
    client: ClientContext,
    options: {
      oidcIdToken?: string;
      authMethod?: SessionAuthMethod;
      /** La identidad se acaba de confirmar (login con TOTP): vale para el step-up. */
      reauthenticatedAt?: Date | null;
    } = {},
  ): Promise<CreatedSession> {
    const token = randomBytes(32).toString('base64url');
    const now = new Date();
    const ttlMs =
      purpose === 'password_change'
        ? PASSWORD_CHANGE_SESSION_TTL_MS
        : purpose === 'mfa'
          ? MFA_SESSION_TTL_MS
          : this.config.get('SESSION_TTL', { infer: true }) * 1000;
    const session = await this.sessions.save(
      this.sessions.create({
        userId,
        tokenHash: hashSessionToken(token),
        csrfToken: randomBytes(32).toString('base64url'),
        purpose,
        lastSeenAt: now,
        expiresAt: new Date(now.getTime() + ttlMs),
        ip: client.ip,
        userAgent: client.userAgent?.slice(0, 255) ?? null,
        oidcIdToken: options.oidcIdToken ?? null,
        authMethod:
          options.authMethod ?? (options.oidcIdToken ? 'oidc' : 'password'),
        reauthenticatedAt: options.reauthenticatedAt ?? null,
      }),
    );
    return { token, session };
  }

  /** Identidad confirmada ahora (o en `at`, el `auth_time` del proveedor): vale para el step-up. */
  async markReauthenticated(sessionId: string, at = new Date()): Promise<void> {
    await this.sessions.update({ id: sessionId }, { reauthenticatedAt: at });
  }

  /**
   * Cuenta un código fallido en la sesión intermedia del login; al llegar al máximo la borra.
   * Devuelve si sigue viva.
   */
  async recordMfaFailure(sessionId: string): Promise<boolean> {
    const result = await this.sessions
      .createQueryBuilder()
      .update()
      .set({ mfaFailures: () => 'mfa_failures + 1' })
      .where('id = :id', { id: sessionId })
      .returning('mfa_failures')
      .execute();
    const rows = result.raw as { mfa_failures: number }[];
    const failures = rows[0]?.mfa_failures ?? MFA_SESSION_MAX_FAILURES;
    if (failures < MFA_SESSION_MAX_FAILURES) return true;
    await this.revoke(sessionId);
    return false;
  }

  /** Sesión viva (sin caducar) de un usuario, por id: el callback OIDC de una reautenticación. */
  async findActive(sessionId: string, userId: string): Promise<UserSession | null> {
    const session = await this.sessions.findOneBy({ id: sessionId, userId });
    if (session?.purpose !== 'full') return null;
    const now = Date.now();
    const idleMs = this.config.get('SESSION_IDLE_TTL', { infer: true }) * 1000;
    if (
      session.expiresAt.getTime() <= now ||
      session.lastSeenAt.getTime() + idleMs <= now
    )
      return null;
    return session;
  }

  /**
   * Actividad fuera de la API (una terminal en uso, sesión 22): cuenta como uso de la sesión web
   * para la caducidad por inactividad, pero nunca revive una que ya caducó.
   */
  async touch(sessionIds: readonly string[]): Promise<void> {
    if (sessionIds.length === 0) return;
    const idle = this.config.get('SESSION_IDLE_TTL', { infer: true });
    await this.sessions
      .createQueryBuilder()
      .update()
      .set({ lastSeenAt: () => 'now()' })
      .where({ id: In([...sessionIds]) })
      .andWhere("purpose = 'full'")
      .andWhere('expires_at > now()')
      .andWhere('last_seen_at > now() - make_interval(secs => :idle)', { idle })
      .execute();
  }

  /** ID token con el que se abrió la sesión por OIDC (null si fue local). Solo para el logout. */
  async oidcIdToken(sessionId: string): Promise<string | null> {
    const row = await this.sessions.findOne({
      select: { id: true, oidcIdToken: true },
      where: { id: sessionId },
    });
    return row?.oidcIdToken ?? null;
  }

  /**
   * Sesión y usuario de un token de cookie, o null si no existe, caducó (absoluta o por
   * inactividad) o el usuario está desactivado. Las caducadas se borran.
   */
  async resolve(
    token: string,
  ): Promise<{ session: UserSession; user: User } | null> {
    if (!token || token.length > 128) return null;
    const session = await this.sessions.findOne({
      where: { tokenHash: hashSessionToken(token) },
      relations: { user: true },
    });
    if (!session?.user) return null;
    const now = Date.now();
    const idleMs = this.config.get('SESSION_IDLE_TTL', { infer: true }) * 1000;
    if (
      session.expiresAt.getTime() <= now ||
      session.lastSeenAt.getTime() + idleMs <= now
    ) {
      await this.sessions.delete({ id: session.id });
      return null;
    }
    if (session.user.disabledAt) return null;
    if (now - session.lastSeenAt.getTime() >= TOUCH_INTERVAL_MS) {
      session.lastSeenAt = new Date(now);
      await this.sessions.update(
        { id: session.id },
        { lastSeenAt: session.lastSeenAt },
      );
    }
    const { user } = session;
    return { session, user };
  }

  /** Cierra una sesión (logout). */
  async revoke(sessionId: string): Promise<void> {
    await this.sessions.delete({ id: sessionId });
    this.registry.closeSessions([sessionId]);
  }

  /**
   * Borra las sesiones del usuario (salvo `exceptId`) dentro de la transacción `manager` si se
   * da. Devuelve los ids: hay que pasarlos a `closeStreams` tras el commit.
   */
  async revokeAllForUser(
    userId: string,
    options: { exceptId?: string; manager?: EntityManager } = {},
  ): Promise<string[]> {
    const repo = options.manager
      ? options.manager.getRepository(UserSession)
      : this.sessions;
    const rows = await repo.find({ select: { id: true }, where: { userId } });
    const ids = rows.map((r) => r.id).filter((id) => id !== options.exceptId);
    if (ids.length > 0) await repo.delete({ id: In(ids) });
    if (!options.manager) this.closeStreams(ids);
    return ids;
  }

  /** Cambió lo que puede hacer el usuario (rol): quien dependa de ello lo vuelve a comprobar. */
  userChanged(userId: string): void {
    this.registry.userChanged(userId);
  }

  /** Corta los flujos SSE de sesiones ya borradas. */
  closeStreams(sessionIds: readonly string[]): void {
    this.registry.closeSessions(sessionIds);
  }
}
