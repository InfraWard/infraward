import type { FastifyRequest } from 'fastify';
import type { ClientContext } from './session.service.js';

/** IP (según TRUST_PROXY) y User-Agent de la petición, para la sesión y la auditoría. */
export function clientOf(request: FastifyRequest): ClientContext {
  const ua = request.headers['user-agent'];
  return {
    ip: request.ip || null,
    userAgent: typeof ua === 'string' ? ua : null,
  };
}
