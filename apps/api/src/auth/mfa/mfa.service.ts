import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { formatSecretRef, SecretsService } from '@infraward/secrets';
import {
  RECOVERY_CODES_COUNT,
  type MfaSetupResponse,
  type MfaStatus,
  type RecoveryCodesResponse,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import QRCode from 'qrcode';
import { DataSource, IsNull, type EntityManager } from 'typeorm';
import type { AuditActor } from '../../audit/audit-context.decorator.js';
import { AuditService } from '../../audit/audit.service.js';
import type { EnvironmentVariables } from '../../config/env.validation.js';
import { writableSecretsProvider } from '../../secrets/writable-provider.js';
import { User } from '../../users/user.entity.js';
import { userTarget } from '../../users/users.service.js';
import { SessionService } from '../session.service.js';
import { mfaRequired } from './mfa-policy.js';
import { UserRecoveryCode } from './recovery-code.entity.js';
import {
  generateRecoveryCode,
  generateTotpSecret,
  hashRecoveryCode,
  normalizeRecoveryCode,
  otpauthUri,
  verifyTotp,
} from './totp.js';

/** Campo del secreto TOTP en el proveedor de secretos. */
const TOTP_FIELD = 'secret';
/** Emisor que enseña la app de autenticación. */
const ISSUER = 'InfraWard';

export type MfaMethod = 'totp' | 'recovery';

/** Resultado de comprobar un código: con qué se aceptó, o null si no vale. */
export interface MfaVerification {
  method: MfaMethod;
  /** Códigos de recuperación sin usar que quedan (tras usar uno; null con TOTP). */
  recoveryCodesLeft: number | null;
}

/**
 * Verificación en dos pasos de los usuarios locales (DESIGN §14): TOTP (RFC 6238) con el secreto
 * cifrado en el proveedor de secretos (aquí solo su referencia) y códigos de recuperación de un
 * solo uso (aquí solo su sha256). Cada alta usa una ruta nueva (`…/totp/<uuid>`): confirmar el
 * alta es cambiar la referencia en la BD, sin copiar el secreto, y la anterior se borra después.
 */
@Injectable()
export class MfaService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly sessions: SessionService,
    private readonly audit: AuditService,
    private readonly config: ConfigService<EnvironmentVariables, true>,
  ) {}

  async status(user: User): Promise<MfaStatus> {
    return {
      enabled: Boolean(user.totpSecretRef),
      recoveryCodesLeft: user.totpSecretRef
        ? await this.recoveryCodesLeft(this.db.manager, user.id)
        : 0,
      required: mfaRequired(user),
    };
  }

  /**
   * Empieza un alta (o un cambio de dispositivo): secreto nuevo guardado como pendiente. Se
   * devuelve una sola vez para el QR; hasta confirmarlo con un código no sustituye al activo.
   */
  async beginSetup(userId: string): Promise<MfaSetupResponse> {
    const user = await this.findUser(userId);
    if (user.origin === 'oidc')
      throw new ConflictException(
        'Tu cuenta entra con el proveedor OIDC: la verificación en dos pasos la aplica el proveedor',
      );
    const secret = generateTotpSecret();
    const base = formatSecretRef({
      provider: writableSecretsProvider(this.secrets, this.config),
      path: `infraward/users/${user.id}/totp/${randomUUID()}`,
    });
    await this.secrets.store(base, { [TOTP_FIELD]: secret });
    const ref = `${base}#${TOTP_FIELD}`;
    const previous = user.totpPendingRef;
    await this.db.getRepository(User).update({ id: user.id }, { totpPendingRef: ref });
    if (previous) await this.removeSecret(previous);
    const uri = otpauthUri(secret, user.email, ISSUER);
    return {
      otpauthUri: uri,
      secret,
      // PNG: la web lo pinta en un <img> (Angular no admite SVG en data: y la CSP sí PNG).
      qrDataUrl: await QRCode.toDataURL(uri, { margin: 1, width: 240 }),
    };
  }

  /**
   * Confirma el alta con un código de la app: el pendiente pasa a ser el activo, se generan
   * códigos de recuperación nuevos (se devuelven una sola vez) y la sesión queda reautenticada.
   */
  async enable(
    userId: string,
    code: string,
    sessionId: string,
    actor: AuditActor,
  ): Promise<RecoveryCodesResponse> {
    const user = await this.findUser(userId);
    if (!user.totpPendingRef)
      throw new ConflictException('Empieza de nuevo la configuración');
    const secret = await this.secrets.resolve(user.totpPendingRef, { fresh: true });
    const step = verifyTotp(secret, code.trim());
    if (step === null) {
      await this.audit.record(actor, 'auth.mfa_enabled', {
        outcome: 'failure',
        target: userTarget(user),
        details: { reason: 'bad_code' },
      });
      throw new BadRequestException('El código no es correcto');
    }
    const previous = user.totpSecretRef;
    const recoveryCodes = await this.db.transaction(async (m) => {
      const res = await m.getRepository(User).update(
        { id: user.id, totpPendingRef: user.totpPendingRef! },
        {
          totpSecretRef: user.totpPendingRef,
          totpPendingRef: null,
          totpEnabledAt: new Date(),
          totpLastStep: step,
        },
      );
      if (!res.affected) throw new ConflictException('Empieza de nuevo la configuración');
      const codes = await this.replaceRecoveryCodes(m, user.id);
      await this.audit.record(actor, 'auth.mfa_enabled', {
        target: userTarget(user),
        details: { replaced: previous !== null },
        manager: m,
      });
      return codes;
    });
    if (previous) await this.removeSecret(previous);
    await this.sessions.markReauthenticated(sessionId);
    return { recoveryCodes };
  }

  /** Quita la verificación en dos pasos propia (no a un admin local: le es obligatoria). */
  async disable(userId: string, actor: AuditActor): Promise<void> {
    const user = await this.findUser(userId);
    if (!user.totpSecretRef) return;
    if (mfaRequired(user))
      throw new ConflictException(
        'Los administradores no pueden quitarse la verificación en dos pasos (pueden cambiar de dispositivo)',
      );
    await this.clear(user, actor, 'auth.mfa_disabled', {});
  }

  /** Códigos de recuperación nuevos (los anteriores dejan de valer). */
  async regenerateRecoveryCodes(
    userId: string,
    actor: AuditActor,
  ): Promise<RecoveryCodesResponse> {
    const user = await this.findUser(userId);
    if (!user.totpSecretRef)
      throw new ConflictException('No tienes activada la verificación en dos pasos');
    const recoveryCodes = await this.db.transaction(async (m) => {
      const codes = await this.replaceRecoveryCodes(m, user.id);
      await this.audit.record(actor, 'auth.mfa_recovery_regenerated', {
        target: userTarget(user),
        manager: m,
      });
      return codes;
    });
    return { recoveryCodes };
  }

  /**
   * Un admin se lo quita a otro usuario (perdió el móvil): borra el secreto y los códigos y
   * cierra sus sesiones. Si le es obligatorio, al volver a entrar tendrá que configurarlo.
   */
  async adminReset(targetId: string, actor: AuditActor): Promise<User> {
    if (targetId === actor.actorId)
      throw new BadRequestException(
        'Para la tuya, usa tu perfil (cambiar de dispositivo)',
      );
    const user = await this.db.getRepository(User).findOneBy({ id: targetId });
    if (!user) throw new NotFoundException('Usuario no encontrado');
    if (!user.totpSecretRef && !user.totpPendingRef)
      throw new ConflictException('No tiene activada la verificación en dos pasos');
    await this.clear(user, actor, 'user.mfa_reset', { revokeSessions: true });
    return user;
  }

  /**
   * Comprueba un código TOTP (6 cifras; cada paso vale una sola vez) o de recuperación (se gasta).
   * Las dos comprobaciones son actualizaciones condicionadas: de dos peticiones simultáneas con
   * el mismo código, solo una lo acepta.
   */
  async verify(user: User, code: string): Promise<MfaVerification | null> {
    if (!user.totpSecretRef) return null;
    const trimmed = code.trim();
    if (/^\d{6}$/.test(trimmed)) {
      const secret = await this.secrets.resolve(user.totpSecretRef);
      const step = verifyTotp(secret, trimmed, { lastStep: user.totpLastStep });
      if (step === null) return null;
      const res = await this.db
        .getRepository(User)
        .createQueryBuilder()
        .update()
        .set({ totpLastStep: step })
        .where('id = :id', { id: user.id })
        .andWhere('(totp_last_step IS NULL OR totp_last_step < :step)', { step })
        .execute();
      if (!res.affected) return null;
      user.totpLastStep = step;
      return { method: 'totp', recoveryCodesLeft: null };
    }
    const normalized = normalizeRecoveryCode(trimmed);
    if (!normalized) return null;
    const res = await this.db
      .getRepository(UserRecoveryCode)
      .update(
        { userId: user.id, codeHash: hashRecoveryCode(normalized), usedAt: IsNull() },
        { usedAt: new Date() },
      );
    if (!res.affected) return null;
    return {
      method: 'recovery',
      recoveryCodesLeft: await this.recoveryCodesLeft(this.db.manager, user.id),
    };
  }

  private async clear(
    user: User,
    actor: AuditActor,
    action: 'auth.mfa_disabled' | 'user.mfa_reset',
    options: { revokeSessions?: boolean },
  ): Promise<void> {
    const refs = [user.totpSecretRef, user.totpPendingRef].filter(
      (r): r is string => r !== null,
    );
    let revoked: string[] = [];
    await this.db.transaction(async (m) => {
      await m.getRepository(User).update(
        { id: user.id },
        {
          totpSecretRef: null,
          totpPendingRef: null,
          totpEnabledAt: null,
          totpLastStep: null,
        },
      );
      await m.getRepository(UserRecoveryCode).delete({ userId: user.id });
      if (options.revokeSessions)
        revoked = await this.sessions.revokeAllForUser(user.id, { manager: m });
      await this.audit.record(actor, action, {
        target: userTarget(user),
        details: options.revokeSessions ? { sessionsRevoked: revoked.length } : {},
        manager: m,
      });
    });
    this.sessions.closeStreams(revoked);
    user.totpSecretRef = null;
    user.totpPendingRef = null;
    for (const ref of refs) await this.removeSecret(ref);
  }

  private async replaceRecoveryCodes(m: EntityManager, userId: string): Promise<string[]> {
    const repo = m.getRepository(UserRecoveryCode);
    await repo.delete({ userId });
    const codes = Array.from({ length: RECOVERY_CODES_COUNT }, generateRecoveryCode);
    await repo.insert(
      codes.map((code) => ({
        userId,
        codeHash: hashRecoveryCode(normalizeRecoveryCode(code)!),
      })),
    );
    return codes;
  }

  private recoveryCodesLeft(m: EntityManager, userId: string): Promise<number> {
    return m.getRepository(UserRecoveryCode).countBy({ userId, usedAt: IsNull() });
  }

  private async findUser(userId: string): Promise<User> {
    const user = await this.db.getRepository(User).findOneBy({ id: userId });
    if (!user) throw new UnauthorizedException();
    return user;
  }

  /** Borra un secreto TOTP del proveedor; si falla, queda huérfano pero sin referencia. */
  private async removeSecret(ref: string): Promise<void> {
    const base = ref.split('#')[0];
    await this.secrets.remove(base).catch(() => undefined);
  }
}
