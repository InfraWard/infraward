import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PtyProcess } from '../ssh/pty-bridge.js';
import {
  TerminalSession,
  type TerminalSessionDeps,
} from './terminal-session.js';

const TICKET = 'a'.repeat(32);

class FakeWs extends EventEmitter {
  readonly CONNECTING = 0;
  readonly OPEN = 1;
  readyState = 1;
  readonly sent: (string | Buffer)[] = [];
  send(data: string | Buffer): void {
    this.sent.push(data);
  }
  close(): void {
    this.readyState = 3;
  }
  /** Mensajes de control enviados al cliente, ya parseados. */
  control(): { type: string; [k: string]: unknown }[] {
    return this.sent
      .filter((d) => typeof d === 'string')
      .map((d) => JSON.parse(d as string));
  }
  binary(): string[] {
    return this.sent
      .filter((d) => Buffer.isBuffer(d))
      .map((d) => d.toString('utf8'));
  }
}

class FakePty implements PtyProcess {
  readonly pid = 1;
  readonly written: string[] = [];
  hangup = vi.fn(() => this.exit(129));
  kill = vi.fn();
  resize = vi.fn();
  private dataListener?: (data: Buffer) => void;
  private exitListener?: (code: number | null) => void;
  write(data: Buffer | string): void {
    this.written.push(data.toString());
  }
  onData(listener: (data: Buffer) => void): void {
    this.dataListener = listener;
  }
  onExit(listener: (code: number | null) => void): void {
    this.exitListener = listener;
  }
  emit(text: string): void {
    this.dataListener?.(Buffer.from(text));
  }
  exit(code: number | null): void {
    this.exitListener?.(code);
  }
}

function setup(opened: () => Promise<void>, readOnly = false) {
  const ws = new FakeWs();
  const pty = new FakePty();
  const lease = {
    renew: vi.fn(async () => undefined),
    release: vi.fn(async () => undefined),
  };
  const api = {
    redeem: vi.fn(async () => ({
      sessionId: 's1',
      userId: 'u1',
      assetId: 'a1',
      assetName: 'web-1',
      account: 'admin',
    })),
    opened: vi.fn(opened),
    closed: vi.fn(async () => undefined),
    certificate: vi.fn(),
  };
  const ssh = {
    interactive: vi.fn(
      (
        _c: unknown,
        _i: unknown,
        _h: unknown,
        _o: unknown,
        onStart: (p: PtyProcess) => void,
      ) =>
        new Promise((resolve) => {
          pty.onExit((code) => resolve({ exitCode: code, connectError: null }));
          onStart(pty);
        }),
    ),
  };
  const deps = {
    api,
    routes: {
      resolve: vi.fn(async () => ({
        host: { id: 'h1', name: 'host-1' },
        connection: { host: '192.0.2.10', port: 22, user: 'admin' },
        pinned: 'pin',
        command: [],
        readOnly,
      })),
    },
    ssh,
    hostKeys: { get: vi.fn(async () => ({})), forget: vi.fn() },
    slots: { acquireTerminal: vi.fn(async () => ({ lease, running: 0 })) },
    gatewayName: 'gw-1',
    limits: {
      perUser: 2,
      perHost: 2,
      idleMs: 600_000,
      maxDurationMs: 3_600_000,
    },
  } as unknown as TerminalSessionDeps;
  const session = new TerminalSession(
    ws as never,
    '198.51.100.7',
    'hash',
    deps,
  );
  ws.emit(
    'message',
    Buffer.from(
      JSON.stringify({ type: 'auth', ticket: TICKET, cols: 80, rows: 24 }),
    ),
    false,
  );
  return { ws, pty, api, session };
}

/** Deja avanzar las promesas pendientes (canje, cupos, rutas…). */
const flush = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

describe('TerminalSession: apertura', () => {
  afterEach(() => vi.useRealTimers());

  it('ready, la salida guardada y la entrada solo después de que /opened responda', async () => {
    let release!: () => void;
    const { ws, pty, api } = setup(
      () => new Promise<void>((r) => (release = r)),
    );
    await flush();
    pty.emit('banner\r\n');
    pty.emit('$ ');
    ws.emit('message', Buffer.from('ls\n'), true);
    await flush();
    expect(api.opened).toHaveBeenCalledTimes(1);
    expect(api.opened).toHaveBeenCalledWith('s1', {
      gateway: 'gw-1',
      clientIp: '198.51.100.7',
    });
    expect(ws.control().some((m) => m.type === 'ready')).toBe(false);
    expect(ws.binary()).toEqual([]);
    expect(pty.written).toEqual([]);

    release();
    await flush();
    expect(ws.control()).toContainEqual({
      type: 'ready',
      sessionId: 's1',
      asset: 'web-1',
      account: 'admin',
    });
    expect(ws.binary()).toEqual(['banner\r\n', '$ ']);
    ws.emit('message', Buffer.from('id\n'), true);
    pty.emit('uid=0\r\n');
    expect(pty.written).toEqual(['id\n']);
    expect(ws.binary()).toEqual(['banner\r\n', '$ ', 'uid=0\r\n']);
  });

  it('si /opened falla, cierra con connect_failed y nunca manda ready', async () => {
    const { ws, pty, api, session } = setup(async () => {
      throw new Error('API unavailable');
    });
    await flush();
    pty.emit('banner\r\n');
    ws.emit('message', Buffer.from('id\n'), true);
    await session.done;
    expect(pty.hangup).toHaveBeenCalled();
    expect(pty.written).toEqual([]);
    expect(ws.binary()).toEqual([]);
    const control = ws.control();
    expect(control.some((m) => m.type === 'ready')).toBe(false);
    expect(control).toContainEqual(
      expect.objectContaining({ type: 'exit', reason: 'connect_failed' }),
    );
    expect(api.closed).toHaveBeenCalledWith(
      's1',
      expect.objectContaining({ reason: 'connect_failed' }),
    );
  });

  it('no se abre si el cliente se va mientras /opened está pendiente', async () => {
    let release!: () => void;
    const { ws, pty, api, session } = setup(
      () => new Promise<void>((r) => (release = r)),
    );
    await flush();
    pty.emit('banner\r\n');
    await flush();
    ws.emit('close');
    release();
    await session.done;
    expect(ws.control().some((m) => m.type === 'ready')).toBe(false);
    expect(ws.binary()).toEqual([]);
    expect(api.closed).toHaveBeenCalledWith(
      's1',
      expect.objectContaining({ reason: 'client' }),
    );
  });

  it('un comando que escribe y sale antes de /opened: su salida llega antes de exit y la API recibe opened antes que closed', async () => {
    let release!: () => void;
    const { ws, pty, api, session } = setup(
      () => new Promise<void>((r) => (release = r)),
    );
    await flush();
    pty.emit('Error: container web-1 is not running\r\n');
    pty.exit(1);
    await flush();
    expect(api.closed).not.toHaveBeenCalled();
    release();
    await session.done;
    expect(ws.binary()).toEqual(['Error: container web-1 is not running\r\n']);
    expect(ws.control().map((m) => m.type)).toEqual(['ready', 'exit']);
    expect(ws.control()[1]).toMatchObject({ reason: 'exit', code: 1 });
    expect(api.opened.mock.invocationCallOrder[0]).toBeLessThan(
      api.closed.mock.invocationCallOrder[0],
    );
    expect(api.closed).toHaveBeenCalledWith(
      's1',
      expect.objectContaining({ reason: 'exit', exitCode: 1 }),
    );
  });

  it('ssh sale con 255 tras escribir algo y la apertura queda registrada: es una sesión que terminó, no un fallo de conexión', async () => {
    let release!: () => void;
    const { ws, pty, api, session } = setup(
      () => new Promise<void>((r) => (release = r)),
    );
    await flush();
    pty.emit('$ ');
    pty.exit(255);
    await flush();
    release();
    await session.done;
    expect(ws.control().map((m) => m.type)).toEqual(['ready', 'exit']);
    expect(api.closed).toHaveBeenCalledWith(
      's1',
      expect.objectContaining({ reason: 'exit', exitCode: 255 }),
    );
  });
});

describe('TerminalSession: acción de solo lectura', () => {
  it('ready con readOnly, la salida llega y lo que se teclea no llega al PTY (el tamaño sí)', async () => {
    const { ws, pty } = setup(async () => undefined, true);
    await flush();
    pty.emit('== alice (uid 1000)\r\n');
    await flush();
    expect(ws.control()).toContainEqual({
      type: 'ready',
      sessionId: 's1',
      asset: 'web-1',
      account: 'admin',
      readOnly: true,
    });
    ws.emit('message', Buffer.from('rm -rf /\n'), true);
    ws.emit('message', Buffer.from(JSON.stringify({ type: 'resize', cols: 100, rows: 30 })), false);
    pty.emit('Listo\r\n');
    expect(pty.written).toEqual([]);
    expect(pty.resize).toHaveBeenCalledWith(100, 30);
    expect(ws.binary()).toEqual(['== alice (uid 1000)\r\n', 'Listo\r\n']);
  });
});
