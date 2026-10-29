import { QueryFailedError } from 'typeorm';

/** Códigos de error de PostgreSQL que la API traduce a respuestas HTTP. */
export const PG_UNIQUE_VIOLATION = '23505';
export const PG_CHECK_VIOLATION = '23514';

export function pgErrorCode(error: unknown): string | undefined {
  return error instanceof QueryFailedError
    ? (error.driverError as { code?: string } | undefined)?.code
    : undefined;
}

export function isUniqueViolation(error: unknown): boolean {
  return pgErrorCode(error) === PG_UNIQUE_VIOLATION;
}
