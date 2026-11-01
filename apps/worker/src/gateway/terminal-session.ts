import { Logger } from '@nestjs/common';
import {
  parseTerminalClientMessage,
  type TerminalCloseReason,
  type TerminalServerMessage,
} from '@infraward/shared-types';
import type { WebSocket, RawData } from 'ws';
import type { HostSlots, SlotLease } from '../jobs/host-slots.js';
import { HostKeyMismatchError } from '../ssh/host-keys.js';
import type { PtyProcess } from '../ssh/pty-bridge.js';
import type { SshClient } from '../ssh/ssh-client.js';
import { GatewayApiError, type GatewayApiClient } from './gateway-api.client.js';
import { InteractiveRouteError, type InteractiveRoutes } from './interactive-routes.js';
import type { PinnedHostKeys } from './pinned-host-keys.js';

/** Plazo para que el cliente mande el ticket tras conectar. */
const AUTH_TIMEOUT_MS = 10_000;
/** Aviso antes de cerrar por inactividad o duración máxima. */
const WARN_BEFORE_MS = 60_000;
/** Si la shell no sale tras el SIGHUP, se mata. */
const HANGUP_GRACE_MS = 5_000;
/** Renovación de los cupos (un tercio de su vida). */
const LEASE_RENEW_MS = 20_000;
/** Salida del PTY que se guarda mientras la API registra la apertura (bytes). */
const MAX_PENDING_OUTPUT_BYTES = 1024 * 1024;

export interface TerminalSessionDeps {
  api: GatewayApiClient;
  routes: InteractiveRoutes;
  ssh: SshClient;
  hostKeys: PinnedHostKeys;
  slots: HostSlots;
  gatewayName: string;
  limits: {
    perUser: number;
    perHost: number;
    idleMs: number;
    maxDurationMs: number;
  };
}

/** Fallo que termina la sesión antes de abrirse, con su motivo y un mensaje para la persona. */
class SessionFailure extends Error {
  constructor(
    readonly reason: TerminalCloseReason,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Una terminal (DESIGN §11): el WebSocket del cliente ↔ `ssh -tt` en un PTY. Canjea el ticket en
 * la API, pide los cupos (por persona y por host), resuelve el salto y entra con un certificado
 * firmado por la API para una clave efímera. Datos en binario; control (`resize`) en JSON.
 * Avisa a la API al abrirse y al cerrarse, con el motivo.
 */
export class TerminalSession {
  private readonly logger = new Logger(TerminalSession.name);
  private sessionId: string | null = null;
  private pty: PtyProcess | null = null;
  private reason: TerminalCloseReason | null = null;
  private closeMessage: string | undefined;
  private readonly leases: SlotLease[] = [];
  private renewTimer?: NodeJS.Timeout;
  private idleTimer?: NodeJS.Timeout;
  private idleWarnTimer?: NodeJS.Timeout;
  private maxTimers: NodeJS.Timeout[] = [];
  private hangupTimer?: NodeJS.Timeout;
  private opened = false;
  /** Registro de la apertura en la API, en curso o hecho (con la salida temprana ya enviada). */
  private opening: Promise<boolean> | null = null;
  private starting = false;
  /** Acción de solo lectura: la entrada del cliente no llega al PTY. */
  private readOnly = false;
  private finished = false;
  /** La persona tecleó desde el último latido (mantiene viva su sesión web). */
  private activity = false;
  private resolveDone!: () => void;
  /** Se cumple cuando la sesión ha terminado del todo (avisada la API, cupos sueltos). */
  readonly done = new Promise<void>((resolve) => (this.resolveDone = resolve));

  /**
   * @param sessionCookieHash sha256 (hex) de la cookie de sesión de la web que llegó en el
   *   upgrade: la API exige que sea la de la sesión que pidió el ticket. Nunca la cookie.
   */
  constructor(
    private readonly ws: WebSocket,
    private readonly clientIp: string | null,
    private readonly sessionCookieHash: string | null,
    private readonly deps: TerminalSessionDeps,
  ) {
    const authTimer = setTimeout(
      () => this.fail('client', 'No llegó el ticket a tiempo'),
      AUTH_TIMEOUT_MS,
    );
    ws.once('message', (data, isBinary) => {
      clearTimeout(authTimer);
      void this.start(data, isBinary);
    });
    ws.on('close', () => {
      clearTimeout(authTimer);
      this.close('client');
    });
    ws.on('error', () => this.close('client'));
  }

  get id(): string | null {
    return this.sessionId;
  }

  /** Para el latido: si hubo actividad desde la última vez (y la olvida). */
  takeActivity(): boolean {
    const active = this.activity;
    this.activity = false;
    return active;
  }

  /**
   * La API la corta (sesión web cerrada, persona desactivada, permiso retirado…): el motivo en
   * rojo dentro de la terminal y cierre con `revoked`.
   */
  revoke(message: string): void {
    if (this.reason) return;
    this.send({ type: 'notice', message });
    if (this.pty && this.ws.readyState === this.ws.OPEN)
      this.ws.send(Buffer.from(`\r\n\x1b[31m[InfraWard] ${message}\x1b[0m\r\n`), {
        binary: true,
      });
    this.close('revoked', message);
  }

  /** Aviso a la persona: en la terminal (en amarillo) y como mensaje de control. */
  notice(message: string): void {
    this.send({ type: 'notice', message });
    if (this.pty && this.ws.readyState === this.ws.OPEN)
      this.ws.send(Buffer.from(`\r\n\x1b[33m[InfraWard] ${message}\x1b[0m\r\n`), {
        binary: true,
      });
  }

  /**
   * Cierra la sesión con un motivo: la shell recibe SIGHUP (como al cerrar una terminal) y, si no
   * termina, se mata. Antes de conectar, corta el arranque.
   */
  close(reason: TerminalCloseReason, message?: string): void {
    if (this.reason) return;
    this.reason = reason;
    this.closeMessage = message;
    if (this.pty) {
      this.pty.hangup();
      this.hangupTimer = setTimeout(() => this.pty?.kill(), HANGUP_GRACE_MS);
    } else if (!this.starting) {
      // Aún sin ticket: nada que avisar a la API. Si está arrancando, el arranque lo ve (check).
      void this.finish(null);
    }
  }

  private async start(data: RawData, isBinary: boolean): Promise<void> {
    const auth = isBinary ? null : parseTerminalClientMessage(rawText(data));
    if (auth?.type !== 'auth') return this.fail('client', 'El primer mensaje debe ser el ticket');
    if (this.reason) return;
    this.starting = true;
    try {
      const session = await this.deps.api.redeem({
        ticket: auth.ticket,
        gateway: this.deps.gatewayName,
        sessionCookieHash: this.sessionCookieHash,
      });
      this.sessionId = session.sessionId;
      this.check();
      const user = await this.deps.slots.acquireTerminal(
        { user: session.userId },
        session.sessionId,
        this.deps.limits.perUser,
      );
      if (!user.lease)
        throw new SessionFailure(
          'limit',
          `Ya tienes ${user.running} terminales abiertas (máximo ${this.deps.limits.perUser})`,
        );
      this.leases.push(user.lease);
      const route = await this.deps.routes.resolve(
        session.assetId,
        session.account,
        session.action ?? null,
      );
      this.readOnly = route.readOnly;
      this.check();
      const host = await this.deps.slots.acquireTerminal(
        { host: route.host.id },
        session.sessionId,
        this.deps.limits.perHost,
      );
      if (!host.lease)
        throw new SessionFailure(
          'limit',
          `${route.host.name} ya tiene ${host.running} terminales abiertas (máximo ${this.deps.limits.perHost})`,
        );
      this.leases.push(host.lease);
      this.renewTimer = setInterval(
        () => void Promise.all(this.leases.map((l) => l.renew().catch(() => undefined))),
        LEASE_RENEW_MS,
      );
      const { host: address, port } = route.connection;
      const hostKey = await this.deps.hostKeys.get(address, port, route.pinned);
      this.check();
      const sessionId = session.sessionId;
      const result = await this.deps.ssh.interactive(
        route.connection,
        {
          kind: 'certificate',
          sign: async (publicKey) =>
            (await this.deps.api.certificate(sessionId, publicKey)).certificate,
          ttlSeconds: 60,
          renewMarginSeconds: 0,
        },
        hostKey,
        { command: route.command, cols: auth.cols, rows: auth.rows },
        (pty) => this.attach(pty, session.assetName, session.account),
      );
      // Si el PTY terminó mientras la API registraba la apertura, se espera a saber si se abrió.
      await this.opening;
      if (!this.opened && (result.connectError || result.exitCode === 255)) {
        this.deps.hostKeys.forget(address, port, route.pinned);
        throw new SessionFailure(
          'connect_failed',
          result.connectError ?? `No se pudo conectar por SSH con ${route.host.name}`,
        );
      }
      await this.finish(result.exitCode);
    } catch (error) {
      const failure =
        error instanceof SessionFailure
          ? error
          : error instanceof GatewayApiError
            ? new SessionFailure(error.status === 404 || error.status === 403 ? 'denied' : 'connect_failed', error.message)
            : error instanceof InteractiveRouteError || error instanceof HostKeyMismatchError
              ? new SessionFailure('connect_failed', error.message)
              : new SessionFailure(
                  'connect_failed',
                  error instanceof Error && error.name === 'SshError'
                    ? error.message
                    : 'No se pudo abrir la terminal',
                );
      if (!(error instanceof SessionFailure || error instanceof GatewayApiError))
        this.logger.warn(`Terminal ${this.sessionId ?? '(sin ticket)'}: ${failure.message}`);
      this.fail(failure.reason, failure.message);
    }
  }

  /**
   * Conecta el PTY con el WebSocket. La sesión solo cuenta como abierta cuando la API la ha
   * registrado (`/opened`): hasta entonces el cliente no recibe `ready`, lo que teclea no llega al
   * PTY y la salida se guarda. Si la API no puede registrar la apertura, se cierra con
   * `connect_failed`: nadie tiene una shell que no esté en la auditoría.
   */
  private attach(pty: PtyProcess, assetName: string, account: string): void {
    this.pty = pty;
    if (this.reason) {
      pty.hangup();
      return;
    }
    let pending: Buffer[] = [];
    let pendingBytes = 0;
    pty.onData((data) => {
      if (!this.opened) {
        // La salida temprana (banner, MOTD, prompt) espera a que se registre la apertura. Con
        // límite, para que un comando muy hablador no haga crecer el búfer si la API va lenta.
        if (pendingBytes < MAX_PENDING_OUTPUT_BYTES) {
          pending.push(data);
          pendingBytes += data.length;
        }
        this.opening ??= this.open(pty, assetName, account).then((ok) => {
          const buffered = pending;
          pending = [];
          pendingBytes = 0;
          if (ok)
            for (const chunk of buffered)
              if (this.ws.readyState === this.ws.OPEN) this.ws.send(chunk, { binary: true });
          return ok;
        });
        return;
      }
      this.touch();
      if (this.ws.readyState === this.ws.OPEN) this.ws.send(data, { binary: true });
    });
  }

  /**
   * Registra la apertura en la API y, solo si lo consigue, da la sesión por abierta: `ready` al
   * cliente, su entrada conectada al PTY y los temporizadores de inactividad y duración máxima.
   * @returns si la sesión ha quedado abierta.
   */
  private async open(pty: PtyProcess, assetName: string, account: string): Promise<boolean> {
    try {
      await this.deps.api.opened(this.sessionId!, {
        gateway: this.deps.gatewayName,
        clientIp: this.clientIp,
      });
    } catch (error) {
      this.logger.warn(
        `No se pudo registrar la apertura de ${this.sessionId}: ${(error as Error).message}`,
      );
      this.close('connect_failed', 'No se pudo registrar la apertura de la terminal');
      return false;
    }
    // Se cerró mientras esperaba a la API (el cliente se fue, se revocó o el gateway se para).
    if (this.reason) return false;
    this.opened = true;
    this.send({
      type: 'ready',
      sessionId: this.sessionId!,
      asset: assetName,
      account,
      ...(this.readOnly ? { readOnly: true } : {}),
    });
    this.ws.on('message', (data, isBinary) => {
      if (isBinary) {
        // Acción de solo lectura: se ve el comando y su salida, pero no se le escribe nada.
        if (this.readOnly) return;
        // Solo lo que teclea la persona cuenta como uso de su sesión web (la salida, no).
        this.activity = true;
        this.touch();
        pty.write(toBuffer(data));
        return;
      }
      const message = parseTerminalClientMessage(rawText(data));
      if (message?.type === 'resize') pty.resize(message.cols, message.rows);
    });
    this.startTimers();
    return true;
  }

  private startTimers(): void {
    const max = this.deps.limits.maxDurationMs;
    this.maxTimers = [
      setTimeout(
        () => this.notice('La sesión llega a su duración máxima: se cerrará en 1 minuto'),
        Math.max(0, max - WARN_BEFORE_MS),
      ),
      setTimeout(() => this.close('max_duration'), max),
    ];
    this.touch();
  }

  /** Actividad: reinicia el cierre por inactividad. */
  private touch(): void {
    if (!this.opened) return;
    clearTimeout(this.idleTimer);
    clearTimeout(this.idleWarnTimer);
    const idle = this.deps.limits.idleMs;
    this.idleWarnTimer = setTimeout(
      () => this.notice('Sin actividad: la sesión se cerrará en 1 minuto'),
      Math.max(0, idle - WARN_BEFORE_MS),
    );
    this.idleTimer = setTimeout(() => this.close('idle'), idle);
  }

  /** Se canceló mientras arrancaba (el cliente se fue o el gateway se para). */
  private check(): void {
    if (this.reason) throw new SessionFailure(this.reason, this.closeMessage ?? 'Sesión cerrada');
  }

  private fail(reason: TerminalCloseReason, message: string): void {
    this.reason ??= reason;
    this.closeMessage ??= message;
    void this.finish(null);
  }

  /** Fin: mensaje `exit`, cierre del WebSocket, aviso a la API y cupos sueltos (una vez). */
  private async finish(exitCode: number | null): Promise<void> {
    if (this.finished) return;
    this.finished = true;
    // Primero la apertura pendiente: su `ready` y la salida guardada van antes que `exit`, y la API
    // recibe `opened` antes que `closed`.
    await this.opening;
    for (const t of [this.renewTimer, this.idleTimer, this.idleWarnTimer, this.hangupTimer, ...this.maxTimers])
      clearTimeout(t);
    const reason: TerminalCloseReason = this.reason ?? 'exit';
    this.send({ type: 'exit', reason, code: exitCode, message: this.closeMessage });
    if (this.ws.readyState === this.ws.OPEN || this.ws.readyState === this.ws.CONNECTING)
      this.ws.close(reason === 'gateway_shutdown' ? 1001 : 1000, reason);
    if (this.sessionId)
      await this.deps.api
        .closed(this.sessionId, { reason, exitCode, message: this.closeMessage })
        .catch((error: Error) =>
          this.logger.warn(`No se pudo registrar el cierre de ${this.sessionId}: ${error.message}`),
        );
    await Promise.all(this.leases.map((l) => l.release().catch(() => undefined)));
    this.resolveDone();
  }

  private send(message: TerminalServerMessage): void {
    if (this.ws.readyState === this.ws.OPEN) this.ws.send(JSON.stringify(message));
  }
}

function toBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}

function rawText(data: RawData): string {
  return toBuffer(data).toString('utf8');
}
