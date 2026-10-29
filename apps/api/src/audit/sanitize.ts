import type { AuditDetails, AuditDetailValue } from '@infraward/shared-types';

/** Claves que nunca entran en el detalle de un evento, aunque alguien las pase por error. */
export const FORBIDDEN_DETAIL_KEY =
  /pass|secret|token|key|credential|hash|^code$|verifier|nonce/i;
const MAX_KEYS = 30;
const MAX_STRING = 200;
const MAX_LIST = 50;

/**
 * Deja el detalle pequeño y plano: sin claves sospechosas de llevar secretos, sin objetos
 * anidados, textos cortados y listas acotadas. Además nunca pasa un valor con pinta de clave
 * privada.
 */
export function sanitizeDetails(
  details: Record<string, unknown> = {},
): AuditDetails {
  const out: AuditDetails = {};
  for (const [key, raw] of Object.entries(details).slice(0, MAX_KEYS)) {
    if (FORBIDDEN_DETAIL_KEY.test(key)) continue;
    const value = sanitizeValue(raw);
    if (value !== undefined) out[key] = value;
  }
  return out;
}

function sanitizeValue(raw: unknown): AuditDetailValue | undefined {
  if (raw === null) return null;
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return Number.isFinite(raw) ? raw : undefined;
  if (typeof raw === 'string') return sanitizeString(raw);
  if (raw instanceof Date) return raw.toISOString();
  if (Array.isArray(raw)) {
    const list = raw
      .slice(0, MAX_LIST)
      .map((v) =>
        typeof v === 'string' || typeof v === 'number'
          ? sanitizeString(String(v))
          : undefined,
      )
      .filter((v): v is string => v !== undefined);
    return list;
  }
  return undefined;
}

/** Un JWT (p. ej. un ID token): tres segmentos base64url y cabecera JSON (`eyJ`). */
const JWT = /eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*/;

function sanitizeString(value: string): string | undefined {
  if (/PRIVATE KEY|secret:\/\//i.test(value) || JWT.test(value))
    return undefined;
  return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
}
