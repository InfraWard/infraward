import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';

/** Quién hace la acción y desde dónde (para el registro de auditoría). */
export interface AuditActor {
  actorId: string | null;
  actorEmail: string | null;
  ip: string | null;
  /** Hecho con un token de API (QoL-6): su prefijo, que se guarda en el detalle (`viaApi`). */
  via?: string | null;
}

export function auditActorOf(request: FastifyRequest): AuditActor {
  return {
    actorId: request.user?.id ?? null,
    actorEmail: request.user?.email ?? null,
    // Con TRUST_PROXY, Fastify ya resuelve la IP del cliente desde X-Forwarded-For.
    ip: request.ip || null,
    via: request.apiToken ? `api:${request.apiToken.prefix}` : null,
  };
}

/** Parámetro con el actor de la request (usuario autenticado e IP). */
export const AuditCtx = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AuditActor =>
    auditActorOf(context.switchToHttp().getRequest<FastifyRequest>()),
);
