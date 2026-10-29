import type { FastifyReply, FastifyRequest } from 'fastify';

/**
 * Cookie de sesión: httpOnly (JavaScript no la ve), SameSite=Strict, Path=/ y sin Max-Age (muere
 * al cerrar el navegador; la caducidad real la decide el servidor). Con `Secure`, el prefijo
 * `__Host-` impide que un subdominio la fije o la lea con otro Path o Domain.
 */
export function sessionCookieName(secure: boolean): string {
  return secure ? '__Host-iw_session' : 'iw_session';
}

export function readSessionCookie(
  request: FastifyRequest,
  secure: boolean,
): string | undefined {
  return request.cookies?.[sessionCookieName(secure)];
}

export function setSessionCookie(
  reply: FastifyReply,
  token: string,
  secure: boolean,
): void {
  void reply.setCookie(sessionCookieName(secure), token, {
    httpOnly: true,
    secure,
    sameSite: 'strict',
    path: '/',
  });
}

export function clearSessionCookie(reply: FastifyReply, secure: boolean): void {
  void reply.clearCookie(sessionCookieName(secure), {
    httpOnly: true,
    secure,
    sameSite: 'strict',
    path: '/',
  });
}
