import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SESSION_COOKIE_NAMES } from '@infraward/shared-types';
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { WebSocketServer } from 'ws';
import { HostSlots } from '../jobs/host-slots.js';
import { SshClient } from '../ssh/ssh-client.js';
import { GatewayApiClient } from './gateway-api.client.js';
import { gatewayOrigins, type GatewayEnvironment } from './gateway.env.js';
import { InteractiveRoutes } from './interactive-routes.js';
import { PinnedHostKeys } from './pinned-host-keys.js';
import { TerminalSession } from './terminal-session.js';

/** Tamaño máximo de un mensaje del cliente (lo que se teclea o pega de una vez). */
const MAX_MESSAGE_BYTES = 256 * 1024;

/**
 * Servidor del gateway (sesión 21): `GET /healthz` y el WebSocket de la terminal en `/terminal`.
 * Lleva el registro de las sesiones abiertas para la parada ordenada, el latido y los cortes
 * que pide la API (sesión 22).
 */
@Injectable()
export class GatewayServer {
  private readonly logger = new Logger(GatewayServer.name);
  private readonly sessions = new Set<TerminalSession>();
  private readonly origins: string[];
  private server?: Server;
  private wss?: WebSocketServer;
  private draining = false;

  constructor(
    private readonly config: ConfigService<GatewayEnvironment, true>,
    private readonly api: GatewayApiClient,
    private readonly routes: InteractiveRoutes,
    private readonly ssh: SshClient,
    private readonly hostKeys: PinnedHostKeys,
    private readonly slots: HostSlots,
  ) {
    this.origins = gatewayOrigins({ WEB_ORIGIN: config.get('WEB_ORIGIN', { infer: true }) });
  }

  get openSessions(): number {
    return this.sessions.size;
  }

  /** Sesiones ya canjeadas (con id), para el latido. */
  liveSessions(): TerminalSession[] {
    return [...this.sessions].filter((s) => s.id !== null);
  }

  /** Corta las sesiones de esta réplica que pide la API; las demás no son suyas. */
  revoke(sessions: readonly { id: string; message: string }[]): number {
    const byId = new Map(this.liveSessions().map((s) => [s.id!, s]));
    let cut = 0;
    for (const { id, message } of sessions) {
      const session = byId.get(id);
      if (!session) continue;
      session.revoke(message);
      cut++;
    }
    if (cut > 0) this.logger.log(`${cut} terminal(es) cortada(s) a petición de la API`);
    return cut;
  }

  /** Empieza a escuchar; devuelve el puerto (0 en la config = uno libre, para los tests). */
  async listen(gatewayName: string): Promise<number> {
    const get = <K extends keyof GatewayEnvironment>(k: K) => this.config.get(k, { infer: true });
    const limits = {
      perUser: get('TERMINAL_MAX_SESSIONS_PER_USER'),
      perHost: get('HOST_MAX_TERMINAL_SESSIONS'),
      idleMs: get('TERMINAL_IDLE_TIMEOUT') * 1000,
      maxDurationMs: get('TERMINAL_MAX_DURATION') * 1000,
    };
    const trustProxy = get('GATEWAY_TRUST_PROXY');
    this.server = createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/healthz') {
        res.writeHead(this.draining ? 503 : 200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: this.draining ? 'draining' : 'ok', sessions: this.sessions.size }));
        return;
      }
      res.writeHead(404).end();
    });
    this.wss = new WebSocketServer({
      server: this.server,
      path: '/terminal',
      maxPayload: MAX_MESSAGE_BYTES,
      verifyClient: ({ req }: { req: IncomingMessage }, done) => {
        if (this.draining) return done(false, 503, 'El gateway se está parando');
        const origin = req.headers.origin;
        // Sin Origin: un cliente que no es un navegador (el de pruebas, que manda la cookie de su
        // login igual). Con Origin, solo la web: otra página no puede abrir una terminal.
        if (origin !== undefined && !this.origins.includes(origin))
          return done(false, 403, 'Origen no permitido');
        done(true);
      },
    });
    this.wss.on('connection', (ws, req) => {
      const session = new TerminalSession(ws, clientIp(req, trustProxy), sessionCookieHash(req), {
        api: this.api,
        routes: this.routes,
        ssh: this.ssh,
        hostKeys: this.hostKeys,
        slots: this.slots,
        gatewayName,
        limits,
      });
      this.sessions.add(session);
      void session.done.then(() => this.sessions.delete(session));
    });
    const port = get('GATEWAY_PORT');
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(port, get('GATEWAY_HOST'), () => resolve());
    });
    const address = this.server.address();
    return typeof address === 'object' && address ? address.port : port;
  }

  /**
   * Parada ordenada: no acepta más conexiones, avisa a cada sesión de cuándo se cerrará y espera
   * como mucho `graceMs` (antes si terminan todas). Después las cierra con `gateway_shutdown`
   * (la shell recibe SIGHUP, el cliente un `exit` con el motivo) y espera a que se registren.
   */
  async drain(graceMs: number): Promise<void> {
    this.draining = true;
    this.wss?.close();
    this.server?.close();
    const open = [...this.sessions];
    if (open.length > 0) {
      const seconds = Math.round(graceMs / 1000);
      this.logger.log(`Parada: ${open.length} terminales abiertas; se cerrarán en ${seconds} s como mucho`);
      for (const s of open)
        s.notice(
          `El gateway se va a reiniciar: guarda tu trabajo, la sesión se cerrará en ${seconds} s`,
        );
      const all = Promise.all(open.map((s) => s.done));
      let timer: NodeJS.Timeout | undefined;
      const expired = await Promise.race([
        all.then(() => false),
        new Promise<boolean>((resolve) => (timer = setTimeout(() => resolve(true), graceMs))),
      ]);
      clearTimeout(timer);
      if (expired) {
        this.logger.log(`Cerrando ${this.sessions.size} terminales que siguen abiertas`);
        for (const s of this.sessions) s.close('gateway_shutdown', 'El gateway se ha reiniciado');
        await Promise.race([all, new Promise((r) => setTimeout(r, 10_000))]);
      }
    }
  }
}

/**
 * sha256 (hex) de la cookie de sesión de la web que viaja en el upgrade (mismo origen: la web hace
 * de proxy). Solo el hash sale de aquí; la cookie no se guarda ni se registra.
 */
export function sessionCookieHash(req: Pick<IncomingMessage, 'headers'>): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const name of SESSION_COOKIE_NAMES) {
    for (const part of header.split(';')) {
      const eq = part.indexOf('=');
      if (eq < 0 || part.slice(0, eq).trim() !== name) continue;
      const value = part.slice(eq + 1).trim();
      if (value && value.length <= 128)
        return createHash('sha256').update(value, 'utf8').digest('hex');
    }
  }
  return null;
}

/** IP del cliente (de `X-Forwarded-For` solo si se confía en el proxy). */
function clientIp(req: IncomingMessage, trustProxy: boolean): string | null {
  const forwarded = req.headers['x-forwarded-for'];
  if (trustProxy && typeof forwarded === 'string') return forwarded.split(',')[0]!.trim() || null;
  return req.socket.remoteAddress?.replace(/^::ffff:/, '') ?? null;
}
