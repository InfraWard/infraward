// Terminal interactiva a través del gateway (DESIGN §7 «Acceso interactivo de administración», §11).

import { QUEUE_PREFIX } from './jobs.js';

/**
 * Cuenta de administración que configura el script de alta con el acceso interactivo activado.
 * La terminal entra siempre con ella, nunca con `inventory`.
 */
export const ADMIN_ACCESS_USER = 'infraward-admin';

/**
 * Principal de rol de los certificados de la terminal: el servidor lo lista en el
 * `AuthorizedPrincipalsFile` de la cuenta de administración. Quién lo recibe lo decide
 * InfraWard (permiso `terminal.open`): dar o quitar acceso no exige tocar los servidores. La
 * persona va en el key_id (auth.log del servidor).
 */
export const TERMINAL_PRINCIPAL = 'infraward-operators';

/**
 * Versión de lo que instala el script para el acceso de administración (cuenta, sudoers,
 * principales y drop-in de sshd). Sube si cambia esa configuración.
 * - v1 (sesión 21): cuenta `infraward-admin` con sudo sin contraseña, solo certificados de la CA
 *   con el principal `infraward-operators` (`AuthorizedKeysFile none`, sin contraseña).
 */
export const ADMIN_ACCESS_VERSION = 1;

/** Variantes del acceso de administración. `operator`: cuenta `infraward-admin` con sudo. */
export const ADMIN_ACCESS_MODES = ['operator'] as const;
export type AdminAccessMode = (typeof ADMIN_ACCESS_MODES)[number];

/** Lo que se pide en un comando de alta: activarlo (`operator`) o retirarlo (`none`). */
export const ADMIN_ACCESS_REQUESTS = ['operator', 'none'] as const;
export type AdminAccessRequest = (typeof ADMIN_ACCESS_REQUESTS)[number];

/** Acceso de administración instalado en un servidor (`assets.admin_access`). */
export interface AdminAccess {
  mode: AdminAccessMode;
  /** Cuenta con la que entra la terminal. */
  account: string;
  /** `ADMIN_ACCESS_VERSION` del script que lo instaló. */
  version: number;
  enabledAt: string;
}

/** Tipos de asset en los que se puede abrir una terminal y cómo se llega (§11). */
export const TERMINAL_ASSET_TYPES = ['server', 'lxc', 'container'] as const;

export const TERMINAL_SESSION_STATES = [
  'pending',
  'starting',
  'active',
  'closed',
  'rejected',
] as const;
export type TerminalSessionState = (typeof TERMINAL_SESSION_STATES)[number];

/**
 * Por qué terminó una sesión: `exit` (la shell remota salió), `client` (el cliente cerró),
 * `idle` / `max_duration` (tiempos), `gateway_shutdown` (parada del gateway), `limit` (sin
 * cupo por usuario o por host), `connect_failed` (no se pudo entrar), `expired` (el ticket
 * caducó sin usarse), `denied` (el permiso o la sesión dejaron de valer al canjearlo),
 * `revoked` (se cortó con la sesión abierta: la sesión web se cerró, la persona se desactivó o
 * perdió el permiso; sesión 22) y `gateway_lost` (el gateway dejó de dar señales de vida y el
 * barrido la cerró).
 */
export const TERMINAL_CLOSE_REASONS = [
  'exit',
  'client',
  'idle',
  'max_duration',
  'gateway_shutdown',
  'limit',
  'connect_failed',
  'expired',
  'denied',
  'revoked',
  'gateway_lost',
] as const;
export type TerminalCloseReason = (typeof TERMINAL_CLOSE_REASONS)[number];

/** Vida del ticket de un solo uso que el cliente presenta al gateway (segundos). */
export const TERMINAL_TICKET_TTL_SECONDS = 60;

/** Cuerpo de `POST /terminal/sessions`. */
export interface CreateTerminalSessionRequest {
  assetId: string;
}

/** Respuesta: el ticket solo se devuelve aquí (en la BD, su sha256). */
export interface CreateTerminalSessionResponse {
  sessionId: string;
  ticket: string;
  /**
   * URL del WebSocket del gateway (`GATEWAY_PUBLIC_URL` + `/terminal`). Con una ruta relativa
   * (`/gateway/terminal`, lo normal: la web hace de proxy y la cookie de la sesión viaja en el
   * upgrade), el cliente la completa con su origen (`terminalSocketUrl`).
   */
  gatewayUrl: string;
  expiresAt: string;
}

/**
 * URL absoluta del WebSocket a partir de `gatewayUrl` y el origen de la página: una ruta
 * relativa va al mismo origen (`http` → `ws`, `https` → `wss`).
 */
export function terminalSocketUrl(gatewayUrl: string, pageOrigin: string): string {
  if (/^wss?:\/\//.test(gatewayUrl)) return gatewayUrl;
  // Sin `URL`: shared-types no depende de las librerías del navegador ni de Node.
  const match = /^(https?):\/\/([^/?#]+)/.exec(pageOrigin);
  if (!match) throw new Error(`Origen no válido: ${pageOrigin}`);
  const scheme = match[1] === 'https' ? 'wss' : 'ws';
  return `${scheme}://${match[2]}${gatewayUrl.startsWith('/') ? '' : '/'}${gatewayUrl}`;
}

/** Estado de la terminal de un asset para quien lo mira (`GET /assets/:id/terminal`). */
export interface AssetTerminalStatus {
  /** ¿Puede esta persona abrir terminal aquí? (rol o AccessPolicy). Si no, no se enseña. */
  allowed: boolean;
  /** ¿Admite terminal el asset ahora? (tipo, estado, acceso de administración del host). */
  available: boolean;
  /** Por qué no está disponible (apto para mostrarse). */
  reason: string | null;
  /** Servidor por el que se entra. */
  host: { id: string; name: string } | null;
  account: string | null;
}

// --- Protocolo del WebSocket cliente ↔ gateway -------------------------------------------------
// Datos de la terminal: frames binarios en los dos sentidos. Control: frames de texto con JSON.

export const TERMINAL_MIN_SIZE = 1;
export const TERMINAL_MAX_COLS = 1000;
export const TERMINAL_MAX_ROWS = 500;

/** Cliente → gateway. `auth` es obligatoriamente el primero. */
export type TerminalClientMessage =
  | { type: 'auth'; ticket: string; cols: number; rows: number }
  | { type: 'resize'; cols: number; rows: number };

/** Gateway → cliente. */
export type TerminalServerMessage =
  /** Conectado: la shell remota está lista. */
  | { type: 'ready'; sessionId: string; asset: string; account: string }
  /** Aviso para la persona (parada del gateway, inactividad, duración máxima). */
  | { type: 'notice'; message: string }
  /** Fin de la sesión. `code`: código de salida de la shell, si lo hay. */
  | { type: 'exit'; reason: TerminalCloseReason; code: number | null; message?: string };

function validSize(cols: unknown, rows: unknown): boolean {
  return (
    Number.isInteger(cols) &&
    Number.isInteger(rows) &&
    (cols as number) >= TERMINAL_MIN_SIZE &&
    (rows as number) >= TERMINAL_MIN_SIZE &&
    (cols as number) <= TERMINAL_MAX_COLS &&
    (rows as number) <= TERMINAL_MAX_ROWS
  );
}

/** Valida un mensaje de control del cliente (null si no es válido). */
export function parseTerminalClientMessage(text: string): TerminalClientMessage | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null) return null;
  const m = value as Record<string, unknown>;
  if (!validSize(m.cols, m.rows)) return null;
  const size = { cols: m.cols as number, rows: m.rows as number };
  if (m.type === 'auth' && typeof m.ticket === 'string' && /^[A-Za-z0-9_-]{20,128}$/.test(m.ticket))
    return { type: 'auth', ticket: m.ticket, ...size };
  if (m.type === 'resize') return { type: 'resize', ...size };
  return null;
}

// --- API interna gateway → API (`/internal/gateway/…`) -----------------------------------------

/** Cabecera `Authorization` del gateway: `Gateway <secreto compartido>`. */
export const GATEWAY_AUTH_SCHEME = 'Gateway';

/** Salto final dentro del host SSH: CT de Proxmox o contenedor Docker (§11). */
export type TerminalHop =
  | { kind: 'pct'; vmid: number }
  | { kind: 'docker'; containerId: string };

/**
 * `POST /internal/gateway/sessions/redeem`: el ticket, el gateway que lo canjea y el sha256 (hex)
 * de la cookie de sesión que llegó en el upgrade del WebSocket: la API exige que sea la misma
 * sesión web que pidió el ticket (un ticket robado no sirve sin la cookie).
 */
export interface RedeemTerminalTicketRequest {
  ticket: string;
  gateway: string;
  sessionCookieHash: string | null;
}

/** `POST /internal/gateway/sessions/redeem` → la sesión, ya en `starting` (ticket gastado). */
export interface RedeemTerminalTicketResponse {
  sessionId: string;
  userId: string;
  userEmail: string;
  assetId: string;
  assetName: string;
  /** Cuenta del servidor con la que se entra (`ADMIN_ACCESS_USER`). */
  account: string;
}

/** `POST /internal/gateway/sessions/:id/certificate` */
export interface TerminalCertificateRequest {
  publicKey: string;
}
export interface TerminalCertificateResponse {
  certificate: string;
  ttlSeconds: number;
}

/** `POST /internal/gateway/sessions/:id/opened` */
export interface TerminalOpenedRequest {
  gateway: string;
  clientIp: string | null;
}

/** `POST /internal/gateway/sessions/:id/closed` */
export interface TerminalClosedRequest {
  reason: TerminalCloseReason;
  exitCode: number | null;
  /** Mensaje apto para mostrarse (p. ej. el fallo de conexión), nunca con secretos. */
  message?: string;
}

/**
 * `POST /internal/gateway/heartbeat`: latido del gateway (cada `TERMINAL_HEARTBEAT_SECONDS`) con
 * las sesiones que atiende (`active`: hubo actividad desde el latido anterior: mantiene viva la
 * sesión web de quien la usa). La API las marca vivas y devuelve las que ya no pueden seguir.
 */
export interface GatewayHeartbeatRequest {
  gateway: string;
  sessions: { id: string; active: boolean }[];
}
export interface GatewayHeartbeatResponse {
  revoke: TerminalRevocation[];
}

/** Sesión que el gateway debe cortar, con el mensaje para la persona (dentro de la terminal). */
export interface TerminalRevocation {
  id: string;
  message: string;
}

/** Cada cuánto late el gateway y tras cuánto sin latido el barrido da la sesión por perdida. */
export const TERMINAL_HEARTBEAT_SECONDS = 15;
export const TERMINAL_HEARTBEAT_LOST_SECONDS = 60;

/**
 * Canal de Redis (pub/sub) por el que la API pide a los gateways que corten sesiones al momento:
 * mensaje `TerminalControlMessage` en JSON. El gateway corta las suyas y deja el resto.
 */
export const TERMINAL_CONTROL_CHANNEL = `${QUEUE_PREFIX}:terminal:control`;
export interface TerminalControlMessage {
  type: 'revoke';
  sessions: TerminalRevocation[];
}

/** Nombres de la cookie de sesión de la web (con y sin `Secure`). */
export const SESSION_COOKIE_NAMES = ['__Host-iw_session', 'iw_session'] as const;
