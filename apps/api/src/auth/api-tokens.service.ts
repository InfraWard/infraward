import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  API_TOKEN_DISPLAY_LENGTH,
  API_TOKEN_MAX_DAYS,
  API_TOKEN_PREFIX,
  API_TOKENS_MAX_ACTIVE,
  type ApiTokenSummary,
  type CreateApiTokenRequest,
  type CreatedApiTokenResponse,
} from '@infraward/shared-types';
import { randomBytes } from 'node:crypto';
import { IsNull, MoreThan, type EntityManager, Repository } from 'typeorm';
import { AuditService } from '../audit/audit.service.js';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import type { User } from '../users/user.entity.js';
import { ApiToken } from './api-token.entity.js';
import { hashSessionToken } from './session.service.js';

/** `last_used_at` se actualiza como mucho una vez por minuto. */
const TOUCH_INTERVAL_MS = 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
/** `iwt_` + 43 caracteres base64url (32 bytes). Más largo no puede ser uno nuestro. */
const TOKEN_MAX_LENGTH = 64;

export function isApiTokenActive(token: ApiToken, now = Date.now()): boolean {
  return !token.revokedAt && token.expiresAt.getTime() > now;
}

function tokenTarget(token: ApiToken) {
  return { type: 'api_token', id: token.id, label: token.name };
}

/** Tokens de API personales (QoL-6, DESIGN §14): crear, resolver el Bearer, listar y revocar. */
@Injectable()
export class ApiTokensService {
  constructor(
    @InjectRepository(ApiToken)
    private readonly tokens: Repository<ApiToken>,
    private readonly audit: AuditService,
  ) {}

  async create(
    userId: string,
    dto: CreateApiTokenRequest,
    actor: AuditActor,
  ): Promise<CreatedApiTokenResponse> {
    const name = dto.name.trim();
    if (!name) throw new BadRequestException('El nombre es obligatorio');
    const expiresAt = new Date(dto.expiresAt);
    const now = Date.now();
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= now)
      throw new BadRequestException('La caducidad tiene que ser futura');
    // Un minuto de margen para el reloj del navegador.
    if (expiresAt.getTime() > now + API_TOKEN_MAX_DAYS * DAY_MS + 60_000)
      throw new BadRequestException(
        `La caducidad no puede pasar de ${API_TOKEN_MAX_DAYS} días`,
      );

    const secret = API_TOKEN_PREFIX + randomBytes(32).toString('base64url');
    const saved = await this.tokens.manager.transaction(async (m) => {
      const repo = m.getRepository(ApiToken);
      // Serializa las altas del mismo usuario (límite y nombre único entre los vigentes).
      await m.query('SELECT 1 FROM users WHERE id = $1 FOR UPDATE', [userId]);
      const active = (await repo.find({ where: { userId } })).filter((t) =>
        isApiTokenActive(t, now),
      );
      if (active.length >= API_TOKENS_MAX_ACTIVE)
        throw new ConflictException(
          `Ya tienes ${API_TOKENS_MAX_ACTIVE} tokens vigentes: revoca alguno`,
        );
      if (active.some((t) => t.name.toLowerCase() === name.toLowerCase()))
        throw new ConflictException(
          'Ya tienes un token vigente con ese nombre',
        );
      const token = await repo.save(
        repo.create({
          userId,
          name,
          prefix: secret.slice(0, API_TOKEN_DISPLAY_LENGTH),
          tokenHash: hashSessionToken(secret),
          scope: dto.scope,
          expiresAt,
          lastUsedAt: null,
          lastUsedIp: null,
          revokedAt: null,
          revokedById: null,
        }),
      );
      await this.audit.record(actor, 'api_token.created', {
        target: tokenTarget(token),
        details: {
          scope: token.scope,
          expiresAt: token.expiresAt.toISOString(),
          prefix: token.prefix,
        },
        manager: m,
      });
      return token;
    });
    return { token: this.summary(saved), secret };
  }

  /**
   * Token y usuario de un Bearer, o null si no existe, caducó, se revocó o el usuario está
   * desactivado.
   */
  async resolve(
    secret: string,
    ip: string | null,
  ): Promise<{ token: ApiToken; user: User } | null> {
    if (
      !secret.startsWith(API_TOKEN_PREFIX) ||
      secret.length > TOKEN_MAX_LENGTH
    )
      return null;
    const token = await this.tokens.findOne({
      where: { tokenHash: hashSessionToken(secret) },
      relations: { user: true },
    });
    if (!token?.user || token.user.disabledAt) return null;
    const now = Date.now();
    if (!isApiTokenActive(token, now)) return null;
    if (
      !token.lastUsedAt ||
      now - token.lastUsedAt.getTime() >= TOUCH_INTERVAL_MS ||
      token.lastUsedIp !== ip
    ) {
      token.lastUsedAt = new Date(now);
      token.lastUsedIp = ip;
      await this.tokens.update(
        { id: token.id },
        { lastUsedAt: token.lastUsedAt, lastUsedIp: ip },
      );
    }
    return { token, user: token.user };
  }

  /** Los de un usuario (vigentes primero). */
  async listForUser(userId: string): Promise<ApiTokenSummary[]> {
    const rows = await this.tokens.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
    return this.sorted(rows).map((t) => this.summary(t));
  }

  /** Los de todos (vista de admin), con su dueño. */
  async listAll(filter: { userId?: string } = {}): Promise<ApiTokenSummary[]> {
    const rows = await this.tokens.find({
      where: filter.userId ? { userId: filter.userId } : {},
      relations: { user: true },
      order: { createdAt: 'DESC' },
      take: 1000,
    });
    return this.sorted(rows).map((t) => this.summary(t, true));
  }

  /**
   * Revoca un token. Con `ownerId`, solo si es suyo (si no, 404: no revela tokens ajenos).
   * Revocar uno ya revocado no hace nada.
   */
  async revoke(
    id: string,
    actor: AuditActor,
    options: { ownerId?: string } = {},
  ): Promise<ApiTokenSummary> {
    const token = await this.tokens.findOne({
      where: { id },
      relations: { user: true },
    });
    if (!token || (options.ownerId && token.userId !== options.ownerId))
      throw new NotFoundException('Token no encontrado');
    if (token.revokedAt) return this.summary(token, !options.ownerId);
    await this.tokens.manager.transaction(async (m) => {
      token.revokedAt = new Date();
      token.revokedById = actor.actorId;
      await m
        .getRepository(ApiToken)
        .update(
          { id, revokedAt: IsNull() },
          { revokedAt: token.revokedAt, revokedById: actor.actorId },
        );
      await this.audit.record(actor, 'api_token.revoked', {
        target: tokenTarget(token),
        details: {
          prefix: token.prefix,
          owner: token.user?.email ?? null,
          byOwner: token.userId === actor.actorId,
        },
        manager: m,
      });
    });
    return this.summary(token, !options.ownerId);
  }

  /** Revoca los vigentes de un usuario (al desactivarlo), en la transacción `manager`. */
  async revokeAllForUser(
    userId: string,
    actor: AuditActor,
    manager: EntityManager,
  ): Promise<number> {
    const res = await manager
      .getRepository(ApiToken)
      .update(
        { userId, revokedAt: IsNull(), expiresAt: MoreThan(new Date()) },
        { revokedAt: new Date(), revokedById: actor.actorId },
      );
    return res.affected ?? 0;
  }

  summary(token: ApiToken, withUser = false): ApiTokenSummary {
    return {
      id: token.id,
      name: token.name,
      prefix: token.prefix,
      scope: token.scope,
      createdAt: token.createdAt.toISOString(),
      expiresAt: token.expiresAt.toISOString(),
      lastUsedAt: token.lastUsedAt?.toISOString() ?? null,
      lastUsedIp: token.lastUsedIp,
      revokedAt: token.revokedAt?.toISOString() ?? null,
      active: isApiTokenActive(token),
      ...(withUser && token.user
        ? {
            user: {
              id: token.user.id,
              email: token.user.email,
              name: token.user.name,
            },
          }
        : {}),
    };
  }

  private sorted(rows: ApiToken[]): ApiToken[] {
    const now = Date.now();
    return [...rows].sort(
      (a, b) =>
        Number(isApiTokenActive(b, now)) - Number(isApiTokenActive(a, now)),
    );
  }
}
