import { HttpErrorResponse } from '@angular/common/http';

/** Mensaje de un error de la API (cuerpo de Nest: `message` texto o lista) o `fallback`. */
export function apiErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 0) return 'No se puede conectar con la API.';
    const body = err.error as { message?: unknown; code?: unknown } | null;
    // Un 403 con código (reautenticación, verificación en dos pasos…) trae su propio mensaje.
    if (err.status === 403 && !(typeof body?.code === 'string' && typeof body.message === 'string'))
      return 'Hace falta el rol admin.';
    const message = body?.message;
    if (typeof message === 'string' && message) return message;
    if (Array.isArray(message) && message.length > 0) return message.join('. ');
  }
  return fallback;
}
