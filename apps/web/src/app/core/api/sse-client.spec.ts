import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { storeSession } from '../../testing/session';
import { AuthService } from '../auth/auth.service';
import { SseClient, SseHttpError, SseParser, type SseMessage } from './sse-client';

function parse(chunks: string[]): SseMessage[] {
  const out: SseMessage[] = [];
  const parser = new SseParser((m) => out.push(m));
  for (const c of chunks) parser.push(c);
  return out;
}

function streamOf(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const c of chunks) controller.enqueue(encoder.encode(c));
      controller.close();
    },
  });
}

describe('SseParser', () => {
  it('eventos con tipo y datos, aunque los trozos partan líneas', () => {
    expect(
      parse(['event: progress\nda', 'ta: {"a":1}\n', '\nevent: heartbeat\ndata: \n\n']),
    ).toEqual([
      { type: 'progress', data: '{"a":1}' },
      { type: 'heartbeat', data: '' },
    ]);
  });

  it('varias líneas data, CRLF, comentarios e id; sin tipo = message', () => {
    expect(parse([': hola\r\nid: 3\r\ndata: a\r\ndata:b\r\n\r\n'])).toEqual([
      { type: 'message', data: 'a\nb' },
    ]);
  });

  it('un bloque sin data no emite nada y el tipo no pasa al siguiente', () => {
    expect(parse(['event: x\n\ndata: y\n\n'])).toEqual([{ type: 'message', data: 'y' }]);
  });
});

describe('SseClient', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  function setup(): SseClient {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    return TestBed.inject(SseClient);
  }

  beforeEach(() => {
    sessionStorage.clear();
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('pide el flujo con la cookie (sin token en la URL ni en cabeceras) y emite los eventos', async () => {
    storeSession('viewer', 'secreto');
    fetchMock.mockResolvedValue(
      new Response(streamOf(['event: progress\ndata: {"phase":"waiting"}\n\n']), {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      }),
    );
    const client = setup();
    const received: SseMessage[] = [];
    const sub = client.stream('/assets/a1/enrollment/events').subscribe((m) => received.push(m));
    await vi.waitFor(() => expect(received).toHaveLength(1));
    sub.unsubscribe();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/assets/a1/enrollment/events');
    expect(url).not.toContain('secreto');
    expect(init.credentials).toBe('same-origin');
    expect(JSON.stringify(init.headers)).not.toMatch(/Authorization|secreto/);
    expect(received[0]).toEqual({ type: 'progress', data: '{"phase":"waiting"}' });
  });

  it('un 404 termina el flujo sin reintentar', async () => {
    storeSession();
    fetchMock.mockResolvedValue(new Response('{}', { status: 404 }));
    const client = setup();
    const error = await new Promise<unknown>((resolve) =>
      client.stream('/x').subscribe({ error: resolve }),
    );
    expect(error).toBeInstanceOf(SseHttpError);
    expect((error as SseHttpError).status).toBe(404);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('un 401 cierra la sesión y lleva al login', async () => {
    storeSession();
    fetchMock.mockResolvedValue(new Response('{}', { status: 401 }));
    const client = setup();
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    await new Promise<unknown>((resolve) => client.stream('/x').subscribe({ error: resolve }));
    expect(TestBed.inject(AuthService).isAuthenticated()).toBe(false);
    expect(navigate).toHaveBeenCalledWith(['/login'], expect.anything());
  });

  it('si el servidor cierra el flujo, reconecta', async () => {
    storeSession();
    vi.useFakeTimers();
    fetchMock.mockImplementation(() =>
      Promise.resolve(new Response(streamOf(['data: x\n\n']), { status: 200 })),
    );
    const client = setup();
    const received: SseMessage[] = [];
    const sub = client.stream('/x').subscribe((m) => received.push(m));
    await vi.waitFor(() => expect(received).toHaveLength(1));
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.waitFor(() => expect(received).toHaveLength(2));
    sub.unsubscribe();
    vi.useRealTimers();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
