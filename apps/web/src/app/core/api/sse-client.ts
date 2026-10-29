import { inject, Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthService } from '../auth/auth.service';
import { API_BASE_URL } from './api-base-url';

export interface SseMessage {
  type: string;
  data: string;
}

/** Error definitivo del flujo (no se reintenta): 4xx distinto de 429. */
export class SseHttpError extends Error {
  constructor(readonly status: number) {
    super(`HTTP ${status}`);
  }
}

const RETRY_BASE_MS = 1_000;
const RETRY_MAX_MS = 15_000;

/**
 * Server-Sent Events con `fetch` (la cookie de sesión va sola: mismo origen). Reconecta con
 * espera creciente si se corta (el servidor cierra cada 30 min, o al instante si la sesión se
 * revoca); un 401 cierra la sesión como el interceptor; otros 4xx terminan el flujo con
 * `SseHttpError`. Al desuscribirse, aborta la petición.
 */
@Injectable({ providedIn: 'root' })
export class SseClient {
  private readonly api = inject(API_BASE_URL);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  stream(path: string): Observable<SseMessage> {
    return new Observable<SseMessage>((subscriber) => {
      const controller = new AbortController();
      let retryTimer: ReturnType<typeof setTimeout> | undefined;
      let attempt = 0;

      const connect = async (): Promise<void> => {
        if (!this.auth.isAuthenticated()) {
          this.sessionExpired();
          subscriber.error(new SseHttpError(401));
          return;
        }
        try {
          const res = await fetch(`${this.api}${path}`, {
            headers: { Accept: 'text/event-stream' },
            credentials: 'same-origin',
            signal: controller.signal,
            cache: 'no-store',
          });
          if (res.status === 401) {
            this.sessionExpired();
            subscriber.error(new SseHttpError(401));
            return;
          }
          if (!res.ok || !res.body) {
            if (res.status >= 400 && res.status < 500 && res.status !== 429) {
              subscriber.error(new SseHttpError(res.status));
              return;
            }
            throw new SseHttpError(res.status);
          }
          attempt = 0;
          await readEvents(res.body, (m) => subscriber.next(m));
        } catch {
          // Red caída, 5xx o flujo cortado: se reintenta abajo.
        }
        if (controller.signal.aborted || subscriber.closed) return;
        // Cortado o cerrado por el servidor: reconecta.
        const delay = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** attempt++);
        retryTimer = setTimeout(() => void connect(), delay);
      };

      void connect();
      return () => {
        controller.abort();
        clearTimeout(retryTimer);
      };
    });
  }

  private sessionExpired(): void {
    this.auth.clear();
    const returnUrl = this.router.url.startsWith('/login')
      ? undefined
      : this.router.url;
    void this.router.navigate(['/login'], {
      queryParams: { ...(returnUrl ? { returnUrl } : {}), expired: 1 },
    });
  }
}

/** Lee un cuerpo `text/event-stream` y emite cada evento (ignora comentarios e `id`/`retry`). */
export async function readEvents(
  body: ReadableStream<Uint8Array>,
  emit: (message: SseMessage) => void,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser(emit);
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    parser.push(decoder.decode(value, { stream: true }));
  }
}

/** Parser incremental de SSE (los trozos pueden partir líneas y eventos). */
export class SseParser {
  private buffer = '';
  private type = '';
  private data: string[] = [];

  constructor(private readonly emit: (message: SseMessage) => void) {}

  push(chunk: string): void {
    this.buffer += chunk;
    let newline: number;
    while ((newline = this.buffer.search(/\r\n|\r|\n/)) >= 0) {
      const line = this.buffer.slice(0, newline);
      const width = this.buffer.startsWith('\r\n', newline) ? 2 : 1;
      this.buffer = this.buffer.slice(newline + width);
      this.line(line);
    }
  }

  private line(line: string): void {
    if (line === '') {
      if (this.data.length > 0) {
        this.emit({ type: this.type || 'message', data: this.data.join('\n') });
      }
      this.type = '';
      this.data = [];
      return;
    }
    if (line.startsWith(':')) return;
    const colon = line.indexOf(':');
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') this.type = value;
    else if (field === 'data') this.data.push(value);
  }
}
