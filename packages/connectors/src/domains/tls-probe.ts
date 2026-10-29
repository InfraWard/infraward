import type { LookupFunction } from 'node:net';
import { connect } from 'node:tls';
import type { X509Certificate } from 'node:crypto';

export interface TlsProbeOptions {
  port: number;
  timeoutMs: number;
  /** Resolución de nombres (por defecto la del sistema; los tests la sustituyen). */
  lookup?: LookupFunction;
}

export type TlsProbeResult =
  | {
      ok: true;
      certificate: X509Certificate;
      /** La cadena es válida para el almacén de CA del worker. */
      authorized: boolean;
      authorizationError: string | null;
      /** El certificado cubre `name`. */
      hostnameMatch: boolean;
    }
  | { ok: false; error: string };

const ERRORS: Record<string, string> = {
  ENOTFOUND: 'el nombre no resuelve',
  EAI_AGAIN: 'no se pudo resolver el nombre',
  ECONNREFUSED: 'conexión rechazada en el 443',
  ECONNRESET: 'la conexión se cortó',
  EHOSTUNREACH: 'host inalcanzable',
  ENETUNREACH: 'red inalcanzable',
  ETIMEDOUT: 'sin respuesta a tiempo',
};

/**
 * Lee el certificado que sirve `name` en el puerto TLS (SNI = `name`) sin enviar nada más: solo
 * el apretón de manos. No exige una cadena válida (así se ve también un autofirmado o uno
 * caducado), pero lo dice en `authorized`.
 */
export function probeTls(
  name: string,
  options: TlsProbeOptions,
): Promise<TlsProbeResult> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (result: TlsProbeResult): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };
    const socket = connect({
      host: name,
      port: options.port,
      servername: name,
      rejectUnauthorized: false,
      ALPNProtocols: ['http/1.1'],
      ...(options.lookup ? { lookup: options.lookup } : {}),
    });
    const timer = setTimeout(
      () => finish({ ok: false, error: ERRORS.ETIMEDOUT }),
      options.timeoutMs,
    );
    socket.once('secureConnect', () => {
      const certificate = socket.getPeerX509Certificate();
      if (!certificate) {
        finish({ ok: false, error: 'el servidor no presentó certificado' });
        return;
      }
      finish({
        ok: true,
        certificate,
        authorized: socket.authorized,
        authorizationError: socket.authorized
          ? null
          : String(socket.authorizationError ?? 'cadena no válida').slice(0, 200),
        hostnameMatch: certificate.checkHost(name) !== undefined,
      });
    });
    socket.once('error', (e: NodeJS.ErrnoException) => {
      finish({
        ok: false,
        error:
          (e.code && ERRORS[e.code]) ??
          (e.code?.startsWith('ERR_SSL') || /SSL|TLS/i.test(e.message)
            ? 'fallo en el apretón de manos TLS'
            : 'no se pudo conectar'),
      });
    });
  });
}

/** `fn` sobre cada elemento con como mucho `limit` a la vez, conservando el orden. */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    },
  );
  await Promise.all(workers);
  return out;
}
