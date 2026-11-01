import {
  parseWebhookUrl,
  resolveWebhookTarget,
  type WebhookLookup,
  type WebhookTargetPolicy,
} from '@infraward/connectors';
import {
  ALERT_WEBHOOK_EVENT_HEADER,
  ALERT_WEBHOOK_SIGNATURE_HEADER,
  ALERT_WEBHOOK_TIMESTAMP_HEADER,
  type AlertWebhookPayload,
} from '@infraward/shared-types';
import { request as httpRequest, type RequestOptions } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { LookupFunction } from 'node:net';
import { webhookSignature } from './alert-message.js';

/** Error de un envío: el mensaje es apto para guardarlo y enseñarlo (nunca la URL ni el cuerpo). */
export class AlertSendError extends Error {
  override readonly name = 'AlertSendError';
}

export interface WebhookSendOptions extends WebhookTargetPolicy {
  /** Plazo total del envío (conectar, mandar el cuerpo y recibir las cabeceras de la respuesta). */
  timeoutMs: number;
  /** Secreto de firma (ya resuelto); sin él, sin cabecera de firma. */
  secret?: string | null;
  lookup?: WebhookLookup;
  now?: () => number;
}

/**
 * POST JSON a un webhook de alertas (DESIGN §10). Resuelve y valida el destino antes de conectar
 * (SSRF: sin loopback, enlace local ni privadas salvo que se permitan) y conecta a esa misma IP
 * (sin volver a resolver: nada de DNS rebinding). Sin redirecciones. Firma `<fecha>.<cuerpo>` con
 * HMAC-SHA256 si hay secreto. `timeoutMs` es el plazo **total** y de la respuesta solo se espera el
 * código (el cuerpo no se lee): un destino que contesta gota a gota no retiene el hueco del worker.
 */
export async function sendWebhook(
  rawUrl: string,
  payload: AlertWebhookPayload,
  options: WebhookSendOptions,
): Promise<void> {
  let url: URL;
  let target: { address: string; family: 4 | 6 };
  try {
    url = parseWebhookUrl(rawUrl, options);
    target = await resolveWebhookTarget(url, options, options.lookup);
  } catch (error) {
    throw new AlertSendError((error as Error).message);
  }
  const body = JSON.stringify(payload);
  const timestamp = Math.floor((options.now?.() ?? Date.now()) / 1000);
  const headers: Record<string, string> = {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
    'user-agent': 'InfraWard-Alerts/1',
    [ALERT_WEBHOOK_EVENT_HEADER]: payload.event === 'test' ? 'test' : payload.kind,
    [ALERT_WEBHOOK_TIMESTAMP_HEADER]: String(timestamp),
  };
  if (options.secret)
    headers[ALERT_WEBHOOK_SIGNATURE_HEADER] = webhookSignature(options.secret, timestamp, body);

  // La conexión va a la IP validada; el host (SNI, certificado, cabecera Host) sigue siendo el de la URL.
  const lookup: LookupFunction = (_hostname, opts, callback) => {
    if (typeof opts === 'object' && opts?.all)
      (callback as (e: null, a: { address: string; family: number }[]) => void)(null, [
        { address: target.address, family: target.family },
      ]);
    else callback(null, target.address, target.family);
  };
  const requestOptions: RequestOptions = {
    method: 'POST',
    host: url.hostname.replace(/^\[|\]$/g, ''),
    port: url.port || undefined,
    path: `${url.pathname}${url.search}`,
    headers,
    lookup,
  };
  const send = url.protocol === 'https:' ? httpsRequest : httpRequest;
  const status = await new Promise<number>((resolve, reject) => {
    const req = send(requestOptions, (res) => {
      clearTimeout(deadline);
      // Con las cabeceras basta: se corta sin leer el cuerpo.
      const code = res.statusCode ?? 0;
      res.destroy();
      resolve(code);
    });
    const deadline = setTimeout(
      () => req.destroy(new AlertSendError('Sin respuesta a tiempo')),
      options.timeoutMs,
    );
    req.on('error', (error: NodeJS.ErrnoException) => {
      clearTimeout(deadline);
      reject(
        error instanceof AlertSendError
          ? error
          : new AlertSendError(`No se pudo conectar (${error.code ?? error.name})`),
      );
    });
    req.end(body);
  });
  if (status >= 300 && status < 400)
    throw new AlertSendError(`HTTP ${status} (no se siguen redirecciones)`);
  if (status < 200 || status >= 300) throw new AlertSendError(`HTTP ${status}`);
}
