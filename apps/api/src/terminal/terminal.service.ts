import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { Asset, findAncestorRows } from '@infraward/domain';
import { SecretError, type TerminalCertSigner } from '@infraward/secrets';
import {
  ADMIN_ACCESS_USER,
  TERMINAL_ASSET_TYPES,
  TERMINAL_PRINCIPAL,
  TERMINAL_TICKET_TTL_SECONDS,
  type AssetTerminalStatus,
  type CreateTerminalSessionResponse,
  type GatewayHeartbeatRequest,
  type GatewayHeartbeatResponse,
  type RedeemTerminalTicketRequest,
  type RedeemTerminalTicketResponse,
  type TerminalCertificateResponse,
  type TerminalClosedRequest,
  type TerminalOpenedRequest,
  type TerminalRevocation,
} from '@infraward/shared-types';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { DataSource, In, type EntityManager } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AccessService } from '../access/access.service.js';
import { AuditService } from '../audit/audit.service.js';
import type { AuthenticatedUser, RequestSession } from '../auth/authenticated-user.js';
import { SessionService } from '../auth/session.service.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { User } from '../users/user.entity.js';
import { TerminalControl } from './terminal-control.js';
import { TerminalSession } from './terminal-session.entity.js';
import { TERMINAL_SIGNER } from './terminal.tokens.js';

/** Certificados que se firman como mucho por sesión (un reintento de conexión, no más). */
const MAX_CERTIFICATES = 3;
/** Plazo para pedir el certificado desde que se canjea el ticket. */
const CERTIFICATE_WINDOW_MS = 60_000;
/** Email que cabe tal cual en el key_id (si no, el id del usuario). */
const KEY_ID_EMAIL = /^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{1,100}$/;
const VMID = /^[1-9][0-9]{2,8}$/;
const CONTAINER_ID = /^[0-9a-f]{64}$/;

/** Estados de una sesión con el gateway ya dentro (latido, barrido y cortes). */
const LIVE_STATES = ['starting', 'active'] as const;

/** Código del 409 cuando la terminal no está configurada en esta instalación. */
export const TERMINAL_UNAVAILABLE = 'terminal_unavailable';

export function hashTicket(ticket: string): Buffer {
  return createHash('sha256').update(ticket, 'utf8').digest();
}

/** Asset destino y servidor por el que se entra (DESIGN §11). */
interface TerminalTarget {
  asset: Asset;
  host: Asset;
}

/**
 * Terminal interactiva (sesión 21, DESIGN §11). La API decide quién entra: comprueba el permiso
 * y la reautenticación (en el controlador), que el destino tiene el acceso de administración y
 * emite un ticket de un solo uso. El gateway lo canjea y pide aquí el certificado de pocos
 * minutos para su clave efímera: el gateway nunca toca el gestor de secretos.
 */
@Injectable()
export class TerminalService {
  private readonly logger = new Logger(TerminalService.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    @Inject(TERMINAL_SIGNER) private readonly signer: TerminalCertSigner | null,
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly sessions: SessionService,
    private readonly audit: AuditService,
    private readonly access: AccessService,
    private readonly control: TerminalControl,
  ) {}

  /**
   * `GET /assets/:id/terminal`: ¿puede esta persona abrir terminal aquí y está disponible? Sin
   * permiso, ni siquiera se dice por qué no estaría disponible (el botón no se enseña).
   */
  async status(user: AuthenticatedUser, assetId: string): Promise<AssetTerminalStatus> {
    const none = { available: false, reason: null, host: null, account: null };
    if (!(await this.access.can(user, 'terminal.open', assetId))) {
      if (!(await this.db.getRepository(Asset).existsBy({ id: assetId })))
        throw new NotFoundException('El asset no existe');
      return { allowed: false, ...none };
    }
    if (!this.signer || !this.config.get('GATEWAY_PUBLIC_URL', { infer: true }))
      return {
        allowed: true,
        ...none,
        reason: 'La terminal no está configurada en esta instalación',
      };
    try {
      const { host } = await this.target(this.db.manager, assetId);
      return {
        allowed: true,
        available: true,
        reason: null,
        host: { id: host.id, name: host.displayName ?? host.name },
        account: ADMIN_ACCESS_USER,
      };
    } catch (error) {
      if (error instanceof ConflictException)
        return { allowed: true, ...none, reason: conflictMessage(error) };
      throw error;
    }
  }

  /** POST /terminal/sessions: ticket para abrir una terminal en `assetId`. */
  async create(
    user: AuthenticatedUser,
    session: RequestSession | undefined,
    assetId: string,
    actor: AuditActor,
  ): Promise<CreateTerminalSessionResponse> {
    const gateway = this.config.get('GATEWAY_PUBLIC_URL', { infer: true });
    if (!this.signer || !gateway)
      throw new ConflictException({
        code: TERMINAL_UNAVAILABLE,
        message:
          'La terminal no está configurada en esta instalación (hace falta OpenBao con el rol de la terminal y el gateway)',
      });
    if (!session) throw new ForbiddenException('La terminal solo se abre desde la sesión web');
    await this.expireTickets();
    let target: TerminalTarget;
    try {
      target = await this.target(this.db.manager, assetId);
    } catch (error) {
      if (error instanceof ConflictException)
        await this.audit.tryRecord(actor, 'terminal.session_rejected', {
          target: { type: 'asset', id: assetId },
          outcome: 'failure',
          details: { reason: (error.getResponse() as { message?: string }).message ?? 'conflict' },
        });
      throw error;
    }
    const ticket = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + TERMINAL_TICKET_TTL_SECONDS * 1000);
    const row = await this.db.transaction(async (m) => {
      const saved = await m.save(
        m.create(TerminalSession, {
          userId: user.id,
          authSessionId: session.id,
          assetId: target.asset.id,
          hostAssetId: target.host.id,
          assetName: target.asset.name.slice(0, 255),
          account: ADMIN_ACCESS_USER,
          state: 'pending',
          ticketHash: hashTicket(ticket),
          ticketExpiresAt: expiresAt,
          requestIp: actor.ip && isIP(actor.ip) ? actor.ip : null,
        }),
      );
      await this.audit.record(actor, 'terminal.session_requested', {
        target: { type: target.asset.type, id: target.asset.id, label: target.asset.name },
        details: { sessionId: saved.id, host: target.host.name, account: ADMIN_ACCESS_USER },
        manager: m,
      });
      return saved;
    });
    return {
      sessionId: row.id,
      ticket,
      gatewayUrl: `${gateway}/terminal`,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Canje del ticket por el gateway: lo gasta (`pending` → `starting`, condicionado: de dos
   * canjes a la vez solo gana uno) y vuelve a comprobar que la persona sigue pudiendo entrar
   * (usuario activo, sesión web viva **y la misma de la cookie del WebSocket**, permiso en el
   * asset y destino con acceso).
   */
  async redeem(body: RedeemTerminalTicketRequest): Promise<RedeemTerminalTicketResponse> {
    const result = await this.db
      .createQueryBuilder()
      .update(TerminalSession)
      .set({
        state: 'starting',
        ticketHash: null,
        redeemedAt: () => 'now()',
        heartbeatAt: () => 'now()',
        gateway: body.gateway.slice(0, 64),
      })
      .where('ticket_hash = :hash', { hash: hashTicket(body.ticket) })
      .andWhere("state = 'pending'")
      .andWhere('ticket_expires_at > now()')
      .returning(['id'])
      .execute();
    const id = (result.raw as { id: string }[])[0]?.id;
    if (!id) throw new NotFoundException('Ticket desconocido, caducado o ya usado');
    const row = await this.db.getRepository(TerminalSession).findOneByOrFail({ id });
    const user = await this.db.getRepository(User).findOneBy({ id: row.userId });
    const actor = this.actorOf(row, user);
    const deny = async (reason: string): Promise<never> => {
      await this.finish(row.id, 'rejected', { reason: 'denied', exitCode: null, message: reason });
      await this.audit.tryRecord(actor, 'terminal.session_rejected', {
        target: { type: 'asset', id: row.assetId ?? undefined, label: row.assetName },
        outcome: 'failure',
        details: { sessionId: row.id, reason },
      });
      throw new ForbiddenException(reason);
    };
    const denied = await this.denial(row, user, { cookieHash: body.sessionCookieHash });
    if (denied || !user || !row.assetId) return deny(denied ?? 'El asset ya no existe');
    return {
      sessionId: row.id,
      userId: user.id,
      userEmail: user.email,
      assetId: row.assetId,
      assetName: row.assetName,
      account: row.account,
    };
  }

  /**
   * Certificado de pocos minutos para la clave efímera del gateway: principal de rol, key_id con
   * la sesión, la persona y el asset (aparece en el auth.log del servidor) y `permit-pty`. Solo
   * para una sesión recién canjeada y un número limitado de veces.
   */
  async certificate(id: string, publicKey: string): Promise<TerminalCertificateResponse> {
    if (!this.signer) throw new ConflictException({ code: TERMINAL_UNAVAILABLE });
    const result = await this.db
      .createQueryBuilder()
      .update(TerminalSession)
      .set({ certificatesIssued: () => 'certificates_issued + 1' })
      .where('id = :id', { id })
      .andWhere("state = 'starting'")
      .andWhere('certificates_issued < :max', { max: MAX_CERTIFICATES })
      .andWhere(`redeemed_at > now() - interval '${CERTIFICATE_WINDOW_MS / 1000} seconds'`)
      .returning(['id'])
      .execute();
    if ((result.raw as unknown[]).length === 0)
      throw new NotFoundException('Sesión desconocida o fuera de plazo');
    const row = await this.db.getRepository(TerminalSession).findOneByOrFail({ id });
    if (!row.assetId) throw new NotFoundException('El asset ya no existe');
    const user = await this.db.getRepository(User).findOneByOrFail({ id: row.userId });
    const who = KEY_ID_EMAIL.test(user.email) ? user.email : user.id;
    const ttlSeconds = this.config.get('TERMINAL_CERT_TTL', { infer: true });
    try {
      const certificate = await this.signer.sign({
        publicKey,
        principal: TERMINAL_PRINCIPAL,
        keyId: `infraward:session=${id}:user=${who}:asset=${row.assetId}`,
        ttlSeconds,
      });
      return { certificate, ttlSeconds };
    } catch (error) {
      // Ni el certificado ni la respuesta de OpenBao van al log: solo el tipo de fallo.
      if (error instanceof TypeError) throw new ConflictException('Clave pública no válida');
      this.logger.error(
        `No se pudo firmar el certificado de la terminal: ${error instanceof SecretError ? error.message : 'error del proveedor'}`,
      );
      throw new ServiceUnavailableException('No se pudo firmar el certificado (OpenBao)');
    }
  }

  /** El gateway conectó: la sesión pasa a `active`. */
  async opened(id: string, body: TerminalOpenedRequest): Promise<void> {
    const result = await this.db
      .createQueryBuilder()
      .update(TerminalSession)
      .set({
        state: 'active',
        startedAt: () => 'now()',
        gateway: body.gateway.slice(0, 64),
        clientIp: body.clientIp && isIP(body.clientIp) ? body.clientIp : null,
      })
      .where('id = :id', { id })
      .andWhere("state = 'starting'")
      .execute();
    if (!result.affected) throw new NotFoundException('Sesión desconocida o no está empezando');
    const row = await this.db.getRepository(TerminalSession).findOneByOrFail({ id });
    const user = await this.db.getRepository(User).findOneBy({ id: row.userId });
    await this.audit.tryRecord(this.actorOf(row, user), 'terminal.session_opened', {
      target: { type: 'asset', id: row.assetId ?? undefined, label: row.assetName },
      details: { sessionId: id, account: row.account, gateway: row.gateway },
    });
  }

  /** La sesión terminó (o no llegó a abrirse). Idempotente: una sesión ya cerrada no cambia. */
  async closed(id: string, body: TerminalClosedRequest): Promise<void> {
    const row = await this.db.getRepository(TerminalSession).findOneBy({ id });
    if (!row) throw new NotFoundException();
    if (row.state === 'closed' || row.state === 'rejected') return;
    const opened = row.state === 'active';
    await this.finish(id, opened ? 'closed' : 'rejected', body);
    const user = await this.db.getRepository(User).findOneBy({ id: row.userId });
    await this.audit.tryRecord(
      this.actorOf(row, user),
      opened ? 'terminal.session_closed' : 'terminal.session_rejected',
      {
        target: { type: 'asset', id: row.assetId ?? undefined, label: row.assetName },
        outcome: opened ? 'success' : 'failure',
        details: {
          sessionId: id,
          reason: body.reason,
          exitCode: body.exitCode,
          ...(row.startedAt && {
            seconds: Math.round((Date.now() - row.startedAt.getTime()) / 1000),
          }),
          ...(body.message && { message: body.message.slice(0, 200) }),
        },
      },
    );
  }

  /**
   * Latido del gateway (cada `GATEWAY_HEARTBEAT_INTERVAL`): marca vivas sus sesiones, mantiene
   * viva la sesión web de quien está usando la terminal (si no ha caducado ya) y devuelve las que
   * ya no pueden seguir (la misma comprobación que al canjear el ticket), o que la API ya cerró.
   */
  async heartbeat(body: GatewayHeartbeatRequest): Promise<GatewayHeartbeatResponse> {
    const ids = [...new Set(body.sessions.map((s) => s.id))];
    if (ids.length === 0) return { revoke: [] };
    await this.db
      .createQueryBuilder()
      .update(TerminalSession)
      .set({ heartbeatAt: () => 'now()' })
      .where({ id: In(ids), state: In(LIVE_STATES), gateway: body.gateway })
      .execute();
    const rows = await this.db
      .getRepository(TerminalSession)
      .findBy({ id: In(ids), state: In(LIVE_STATES), gateway: body.gateway });
    const used = new Set(body.sessions.filter((s) => s.active).map((s) => s.id));
    await this.sessions.touch(
      rows.filter((r) => used.has(r.id) && r.authSessionId).map((r) => r.authSessionId!),
    );
    const live = new Set(rows.map((r) => r.id));
    const gone: TerminalRevocation[] = ids
      .filter((id) => !live.has(id))
      .map((id) => ({ id, message: 'InfraWard ya ha dado esta sesión por terminada' }));
    return { revoke: [...gone, ...(await this.revokeDenied(rows))] };
  }

  /**
   * Vuelve a comprobar las terminales abiertas (todas o las de unas personas) y pide al gateway
   * que corte las que ya no pueden seguir. La disparan el cierre de sesiones web, los cambios de
   * rol y de reglas de acceso; el latido lo repite como respaldo.
   */
  async recheck(filter: { userIds?: readonly string[] } = {}): Promise<number> {
    const rows = await this.db.getRepository(TerminalSession).findBy({
      state: In(LIVE_STATES),
      ...(filter.userIds && { userId: In([...filter.userIds]) }),
    });
    const revoked = await this.revokeDenied(rows);
    await this.control.revoke(revoked);
    return revoked.length;
  }

  /**
   * Barrido (cada `TERMINAL_SWEEP_INTERVAL`): las sesiones sin latido desde hace
   * `TERMINAL_HEARTBEAT_TIMEOUT` quedan cerradas (`gateway_lost`): su gateway murió sin pararse
   * bien. Condicionado: con varias réplicas de la API, cada sesión la cierra y audita una sola.
   */
  async sweep(): Promise<number> {
    await this.expireTickets();
    const timeout = this.config.get('TERMINAL_HEARTBEAT_TIMEOUT', { infer: true });
    // En un CTE: TypeORM devuelve `[filas, n]` en un UPDATE crudo y solo las filas en un SELECT.
    const rows: SweptRow[] = await this.db.query(
      `WITH swept AS (
       UPDATE terminal_sessions
          SET state = (CASE WHEN state = 'active' THEN 'closed' ELSE 'rejected' END)::terminal_session_state,
              ticket_hash = NULL,
              ended_at = now(),
              close_reason = 'gateway_lost',
              close_message = 'El gateway ' || coalesce(gateway, '') || ' dejó de responder'
        WHERE state IN ('starting', 'active')
          AND coalesce(heartbeat_at, redeemed_at, created_at) < now() - make_interval(secs => $1)
      RETURNING id, user_id, asset_id, asset_name, gateway, state, started_at, client_ip, request_ip
       )
       SELECT * FROM swept`,
      [timeout],
    );
    for (const r of rows) {
      const row = {
        userId: r.user_id,
        clientIp: r.client_ip,
        requestIp: r.request_ip,
        gateway: r.gateway,
      } as TerminalSession;
      const user = await this.db.getRepository(User).findOneBy({ id: r.user_id });
      const opened = r.state === 'closed';
      await this.audit.tryRecord(
        this.actorOf(row, user),
        opened ? 'terminal.session_closed' : 'terminal.session_rejected',
        {
          target: { type: 'asset', id: r.asset_id ?? undefined, label: r.asset_name },
          outcome: 'failure',
          details: {
            sessionId: r.id,
            reason: 'gateway_lost',
            gateway: r.gateway,
            ...(r.started_at && {
              seconds: Math.round((Date.now() - new Date(r.started_at).getTime()) / 1000),
            }),
          },
        },
      );
    }
    if (rows.length > 0)
      this.logger.warn(`${rows.length} terminal(es) sin latido del gateway: cerradas`);
    return rows.length;
  }

  /**
   * ¿Por qué no puede (seguir) esta sesión? null si puede. Lo mismo al canjear el ticket y con la
   * sesión abierta; al canjear, además, la cookie del WebSocket tiene que ser la de la sesión web
   * que pidió el ticket.
   */
  private async denial(
    row: TerminalSession,
    user: User | null,
    options: { cookieHash?: string | null } = {},
  ): Promise<string | null> {
    if (!user || user.disabledAt) return 'Tu cuenta de InfraWard está desactivada';
    const web = row.authSessionId
      ? await this.sessions.findActive(row.authSessionId, user.id)
      : null;
    if (!web) return 'Se ha cerrado la sesión de InfraWard desde la que se abrió la terminal';
    if ('cookieHash' in options && !sameHash(options.cookieHash, web.tokenHash))
      return 'La terminal solo se abre desde la sesión de InfraWard que la pidió';
    if (!row.assetId) return 'El asset ya no existe';
    if (!(await this.access.can(user, 'terminal.open', row.assetId)))
      return `Ya no tienes permiso para abrir terminales en ${row.assetName}`;
    try {
      await this.target(this.db.manager, row.assetId);
    } catch (error) {
      if (error instanceof ConflictException || error instanceof NotFoundException)
        return conflictMessage(error);
      throw error;
    }
    return null;
  }

  /** Las sesiones que ya no pueden seguir, marcadas (y auditadas la primera vez). */
  private async revokeDenied(rows: TerminalSession[]): Promise<TerminalRevocation[]> {
    const denied: { row: TerminalSession; user: User | null; message: string }[] = [];
    for (const row of rows) {
      const user = await this.db.getRepository(User).findOneBy({ id: row.userId });
      const message = await this.denial(row, user);
      if (message) denied.push({ row, user, message });
    }
    if (denied.length === 0) return [];
    const result = await this.db
      .createQueryBuilder()
      .update(TerminalSession)
      .set({ revokeRequestedAt: () => 'now()' })
      .where({ id: In(denied.map((d) => d.row.id)) })
      .andWhere('revoke_requested_at IS NULL')
      .returning(['id'])
      .execute();
    const first = new Set((result.raw as { id: string }[]).map((r) => r.id));
    for (const { row, user, message } of denied) {
      if (!first.has(row.id)) continue;
      await this.audit.tryRecord(
        { ...this.actorOf(row, user), via: 'api' },
        'terminal.session_revoked',
        {
          target: { type: 'asset', id: row.assetId ?? undefined, label: row.assetName },
          details: { sessionId: row.id, message: message.slice(0, 200) },
        },
      );
    }
    return denied.map(({ row, message }) => ({ id: row.id, message }));
  }

  /**
   * Destino válido: tipo con terminal (servidor, CT o contenedor), activo, y el servidor por el
   * que se entra (el propio asset o el primer antecesor con conexión SSH) con el acceso de
   * administración, en modo CA y con la host key fijada.
   */
  private async target(m: EntityManager, assetId: string): Promise<TerminalTarget> {
    const asset = await m.findOneBy(Asset, { id: assetId });
    if (!asset) throw new NotFoundException('El asset no existe');
    if (!(TERMINAL_ASSET_TYPES as readonly string[]).includes(asset.type))
      throw new ConflictException('Solo se abren terminales en servidores, CT y contenedores');
    if (asset.status !== 'active') throw new ConflictException('El asset no está activo');
    if (asset.type === 'container' && !CONTAINER_ID.test(dockerId(asset) ?? ''))
      throw new ConflictException('El contenedor no tiene su id de Docker');
    if (asset.type === 'lxc' && !VMID.test(String(proxmoxVmid(asset) ?? '')))
      throw new ConflictException('El CT no tiene su vmid de Proxmox');
    let host: Asset | null = asset.connection ? asset : null;
    if (!host) {
      const ancestors = await findAncestorRows(m, asset.id);
      const ids = ancestors.filter((a) => a.depth > 0).map((a) => a.id);
      const rows = ids.length ? await m.findBy(Asset, { id: In(ids) }) : [];
      const byId = new Map(rows.map((r) => [r.id, r]));
      host =
        ancestors
          .filter((a) => a.depth > 0)
          .sort((a, b) => a.depth - b.depth)
          .map((a) => byId.get(a.id))
          .find((a): a is Asset => !!a?.connection) ?? null;
    }
    if (!host) throw new ConflictException('No hay un servidor con SSH por el que llegar al asset');
    if (!host.adminAccess)
      throw new ConflictException(
        `${host.name} no tiene el acceso interactivo de administración activado`,
      );
    if (host.status !== 'active' || host.sshAuth !== 'ca_certificate' || !host.hostKeyFingerprint)
      throw new ConflictException(
        `${host.name} no está activo, en modo CA y con la host key fijada`,
      );
    return { asset, host };
  }

  private async finish(
    id: string,
    state: 'closed' | 'rejected',
    body: TerminalClosedRequest,
  ): Promise<void> {
    await this.db
      .createQueryBuilder()
      .update(TerminalSession)
      .set({
        state,
        ticketHash: null,
        endedAt: () => 'now()',
        closeReason: body.reason,
        exitCode: body.exitCode,
        closeMessage: body.message?.slice(0, 500) ?? null,
      })
      .where('id = :id', { id })
      .andWhere("state IN ('pending', 'starting', 'active')")
      .execute();
  }

  /** Los tickets que caducaron sin usarse dejan de estar pendientes. */
  private async expireTickets(): Promise<void> {
    await this.db
      .createQueryBuilder()
      .update(TerminalSession)
      .set({ state: 'closed', ticketHash: null, closeReason: 'expired', endedAt: () => 'now()' })
      .where("state = 'pending'")
      .andWhere('ticket_expires_at <= now()')
      .execute();
  }

  /** Lo que hace el gateway se audita a nombre de la persona de la sesión. */
  private actorOf(row: TerminalSession, user: User | null): AuditActor {
    return {
      actorId: row.userId,
      actorEmail: user?.email ?? null,
      ip: row.clientIp ?? row.requestIp,
      via: row.gateway ? `gateway:${row.gateway}` : 'gateway',
    };
  }
}

interface SweptRow {
  id: string;
  user_id: string;
  asset_id: string | null;
  asset_name: string;
  gateway: string | null;
  state: 'closed' | 'rejected';
  started_at: Date | string | null;
  client_ip: string | null;
  request_ip: string | null;
}

function conflictMessage(error: ConflictException | NotFoundException): string {
  return (error.getResponse() as { message?: string }).message ?? 'Destino no válido';
}

/** sha256 en hex (de la cookie, calculado por el gateway) frente al de la sesión web. */
function sameHash(hex: string | null | undefined, expected: Buffer): boolean {
  if (!hex || !/^[0-9a-f]{64}$/.test(hex)) return false;
  const given = Buffer.from(hex, 'hex');
  return given.length === expected.length && timingSafeEqual(given, expected);
}

function proxmoxVmid(asset: Asset): unknown {
  return (asset.facts.proxmox as { vmid?: unknown } | undefined)?.vmid;
}

function dockerId(asset: Asset): string | undefined {
  const docker = asset.facts.docker as { id?: unknown } | undefined;
  return typeof docker?.id === 'string' ? docker.id : undefined;
}
