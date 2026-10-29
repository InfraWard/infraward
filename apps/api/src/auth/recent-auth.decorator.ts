import { SetMetadata } from '@nestjs/common';
import type { SensitiveAction } from '@infraward/shared-types';
import type { FastifyRequest } from 'fastify';

export const RECENT_AUTH = 'recentAuth';

export interface RecentAuthRule {
  action: SensitiveAction;
  /**
   * Solo se exige si devuelve true (p. ej. `DELETE /assets/:id` solo al purgar). Recibe la
   * request ya autenticada (`request.user`) y con el cuerpo y la query sin transformar.
   */
  when?: (request: FastifyRequest) => boolean;
}

/**
 * Acción sensible (DESIGN §14): además de la sesión y el permiso, exige identidad confirmada
 * hace menos de REAUTH_MAX_AGE (TOTP o nuevo login en el proveedor OIDC). Con un token de API,
 * siempre 403. Lo comprueba `RecentAuthGuard` (global); la lista de acciones es
 * `SENSITIVE_ACTIONS` de shared-types.
 */
export const RecentAuth = (
  action: SensitiveAction,
  when?: RecentAuthRule['when'],
) => SetMetadata(RECENT_AUTH, { action, when } satisfies RecentAuthRule);
