import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { MessageService } from '@openng/optimus-ui/api';
import { authInterceptor } from '../../core/auth/auth.interceptor';
import { AuthService } from '../../core/auth/auth.service';
import { storeSession } from '../../testing/session';
import { TERMINAL_ENGINE, TERMINAL_SOCKET, type TerminalView } from './terminal-engine';
import { LEAVE_QUESTION, TerminalPage } from './terminal-page';

/** WebSocket falso: guarda lo enviado y deja simular lo que llega. */
class FakeSocket {
  static last: FakeSocket;
  readonly sent: (string | Uint8Array)[] = [];
  readyState = 0;
  binaryType = 'blob';
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;
  constructor(readonly url: string) {
    FakeSocket.last = this;
  }
  send(data: string | Uint8Array): void {
    this.sent.push(data);
  }
  close(): void {
    this.closed = true;
    this.readyState = 3;
    this.onclose?.();
  }
  open(): void {
    this.readyState = 1;
    this.onopen?.();
  }
  receive(data: unknown): void {
    this.onmessage?.({ data });
  }
}

function fakeView() {
  let onData: (d: string) => void = () => undefined;
  const written: (string | Uint8Array)[] = [];
  const view: TerminalView = {
    write: (d) => void written.push(d),
    onData: (l) => (onData = l),
    fit: () => ({ cols: 100, rows: 30 }),
    setTheme: () => undefined,
    getSelection: () => 'seleccionado',
    paste: () => undefined,
    focus: () => undefined,
    onKey: () => undefined,
    dispose: () => undefined,
  };
  return { view, written, type: (d: string) => onData(d) };
}

const TICKET = { sessionId: 's1', ticket: 'T'.repeat(43), gatewayUrl: '/gateway/terminal', expiresAt: '' };

async function setup() {
  storeSession('editor');
  const fake = fakeView();
  // jsdom no trae ResizeObserver: uno que no observa nada.
  globalThis.ResizeObserver ??= class {
    observe = () => undefined;
    disconnect = () => undefined;
  } as unknown as typeof ResizeObserver;
  TestBed.configureTestingModule({
    imports: [TerminalPage],
    providers: [
      provideRouter([]),
      provideHttpClient(withInterceptors([authInterceptor])),
      provideHttpClientTesting(),
      MessageService,
      { provide: TERMINAL_ENGINE, useValue: async () => fake.view },
      { provide: TERMINAL_SOCKET, useValue: (url: string) => new FakeSocket(url) },
    ],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(TerminalPage);
  fixture.componentRef.setInput('id', 'ct1');
  fixture.detectChanges();
  await fixture.whenStable();
  http.expectOne('/api/assets/ct1').flush({ id: 'ct1', name: 'pruebas', displayName: null });
  const open = http.expectOne('/api/terminal/sessions');
  expect(open.request.body).toEqual({ assetId: 'ct1' });
  open.flush(TICKET);
  await fixture.whenStable();
  return { fixture, http, fake, el: fixture.nativeElement as HTMLElement };
}

describe('TerminalPage', () => {
  it('ticket en el primer mensaje (nunca en la URL), datos binarios y redimensionado', async () => {
    const { fixture, fake, el } = await setup();
    const socket = FakeSocket.last;
    expect(socket.url).toBe(`ws://${location.host}/gateway/terminal`);
    expect(socket.url).not.toContain(TICKET.ticket);
    expect(socket.binaryType).toBe('arraybuffer');
    socket.open();
    expect(JSON.parse(socket.sent[0] as string)).toEqual({
      type: 'auth',
      ticket: TICKET.ticket,
      cols: 100,
      rows: 30,
    });
    socket.receive(JSON.stringify({ type: 'ready', sessionId: 's1', asset: 'pruebas', account: 'infraward-admin' }));
    fixture.detectChanges();
    expect(el.querySelector('[data-terminal-state="open"]')?.textContent).toContain('infraward-admin');
    expect(document.title).toBe('Terminal · pruebas');
    socket.receive(new TextEncoder().encode('root@pruebas:~# ').buffer);
    expect(new TextDecoder().decode(fake.written.at(-1) as Uint8Array)).toBe('root@pruebas:~# ');
    fake.type('ls\r');
    expect(new TextDecoder().decode(socket.sent.at(-1) as Uint8Array)).toBe('ls\r');
  });

  it('el motivo del cierre, dentro de la terminal y en la barra; reconectar pide otro ticket', async () => {
    const { fixture, fake, el, http } = await setup();
    const first = FakeSocket.last;
    first.open();
    first.receive(JSON.stringify({ type: 'ready', sessionId: 's1', asset: 'pruebas', account: 'infraward-admin' }));
    first.receive(
      JSON.stringify({
        type: 'exit',
        reason: 'revoked',
        code: null,
        message: 'Se ha cerrado la sesión de InfraWard desde la que se abrió la terminal',
      }),
    );
    fixture.detectChanges();
    expect(String(fake.written.at(-1))).toContain('Cortada por InfraWard');
    expect(el.querySelector('[data-terminal-state="closed"]')?.textContent).toContain(
      'Se ha cerrado la sesión de InfraWard',
    );
    // Cerrada: salir no pregunta.
    expect(fixture.componentInstance.canLeave()).toBe(true);
    fixture.componentInstance.reconnect();
    http.expectOne('/api/terminal/sessions').flush({ ...TICKET, ticket: 'U'.repeat(43) });
    await fixture.whenStable();
    expect(FakeSocket.last).not.toBe(first);
  });

  it('pregunta antes de salir con la sesión abierta y la cierra al cerrar la sesión web', async () => {
    const { fixture } = await setup();
    const socket = FakeSocket.last;
    socket.open();
    socket.receive(JSON.stringify({ type: 'ready', sessionId: 's1', asset: 'pruebas', account: 'infraward-admin' }));
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    expect(fixture.componentInstance.canLeave()).toBe(false);
    expect(confirm).toHaveBeenCalledWith(LEAVE_QUESTION);
    TestBed.inject(AuthService).clear();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(socket.closed).toBe(true);
  });

  it('sin permiso: el 403 se explica y no se abre ningún WebSocket', async () => {
    storeSession('viewer');
    const fake = fakeView();
    TestBed.configureTestingModule({
      imports: [TerminalPage],
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        MessageService,
        { provide: TERMINAL_ENGINE, useValue: async () => fake.view },
        { provide: TERMINAL_SOCKET, useValue: () => { throw new Error('no debería abrirse'); } },
      ],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(TerminalPage);
    fixture.componentRef.setInput('id', 'ct1');
    fixture.detectChanges();
    await fixture.whenStable();
    http.expectOne('/api/assets/ct1').flush({ id: 'ct1', name: 'pruebas', displayName: null });
    http
      .expectOne('/api/terminal/sessions')
      .flush({ statusCode: 403, message: 'Forbidden' }, { status: 403, statusText: 'Forbidden' });
    await fixture.whenStable();
    fixture.detectChanges();
    expect(
      (fixture.nativeElement as HTMLElement).querySelector('[data-terminal-state="closed"]')
        ?.textContent,
    ).toContain('No tienes permiso');
  });
});
