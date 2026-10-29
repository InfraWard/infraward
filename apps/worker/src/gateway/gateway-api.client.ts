import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  GATEWAY_AUTH_SCHEME,
  type GatewayHeartbeatRequest,
  type GatewayHeartbeatResponse,
  type RedeemTerminalTicketRequest,
  type RedeemTerminalTicketResponse,
  type TerminalCertificateResponse,
  type TerminalClosedRequest,
  type TerminalOpenedRequest,
} from '@infraward/shared-types';
import { readFileSync } from 'node:fs';
import type { GatewayEnvironment } from './gateway.env.js';

const TIMEOUT_MS = 10_000;

/** Fallo de la API con un mensaje apto para la persona (nunca el cuerpo de la respuesta entero). */
export class GatewayApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
    this.name = 'GatewayApiError';
  }
}

/**
 * Llamadas del gateway a la API interna (`/internal/gateway/*`) con el secreto compartido: la API
 * decide quién entra y firma los certificados; el gateway no tiene acceso al gestor de secretos.
 */
@Injectable()
export class GatewayApiClient {
  private readonly base: string;
  private readonly authorization: string;

  constructor(config: ConfigService<GatewayEnvironment, true>) {
    this.base = `${config.get('GATEWAY_API_URL', { infer: true })}/internal/gateway`;
    let secret: string;
    try {
      secret = readFileSync(config.get('GATEWAY_API_SECRET_FILE', { infer: true }), 'utf8').trim();
    } catch (error) {
      throw new Error(
        `GATEWAY_API_SECRET_FILE: no se puede leer el fichero (${(error as NodeJS.ErrnoException).code ?? 'error'})`,
        { cause: error },
      );
    }
    if (secret.length < 32)
      throw new Error('GATEWAY_API_SECRET_FILE: el secreto debe tener al menos 32 caracteres');
    this.authorization = `${GATEWAY_AUTH_SCHEME} ${secret}`;
  }

  /** Canjea el ticket; `sessionCookieHash`: sha256 de la cookie que llegó en el upgrade. */
  redeem(body: RedeemTerminalTicketRequest): Promise<RedeemTerminalTicketResponse> {
    return this.post('sessions/redeem', body) as Promise<RedeemTerminalTicketResponse>;
  }

  certificate(sessionId: string, publicKey: string): Promise<TerminalCertificateResponse> {
    return this.post(`sessions/${sessionId}/certificate`, {
      publicKey,
    }) as Promise<TerminalCertificateResponse>;
  }

  async opened(sessionId: string, body: TerminalOpenedRequest): Promise<void> {
    await this.post(`sessions/${sessionId}/opened`, body);
  }

  async closed(sessionId: string, body: TerminalClosedRequest): Promise<void> {
    await this.post(`sessions/${sessionId}/closed`, body);
  }

  /** Latido con las sesiones abiertas → las que hay que cortar. */
  heartbeat(body: GatewayHeartbeatRequest): Promise<GatewayHeartbeatResponse> {
    return this.post('heartbeat', body) as Promise<GatewayHeartbeatResponse>;
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    let res: Response;
    try {
      res = await fetch(`${this.base}/${path}`, {
        method: 'POST',
        headers: { authorization: this.authorization, 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new GatewayApiError('La API de InfraWard no responde', null);
    }
    if (res.status === 204) return null;
    const text = await res.text();
    if (!res.ok) {
      // Solo el mensaje de error de la API (la API nunca pone secretos en él), recortado.
      let message = `HTTP ${res.status}`;
      try {
        const parsed = JSON.parse(text) as { message?: unknown };
        if (typeof parsed.message === 'string') message = parsed.message.slice(0, 300);
      } catch {
        // Sin JSON: el estado basta.
      }
      throw new GatewayApiError(message, res.status);
    }
    return text ? (JSON.parse(text) as unknown) : null;
  }
}
