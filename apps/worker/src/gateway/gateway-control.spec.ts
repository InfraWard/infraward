import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { GatewayControl } from './gateway-control.js';
import { sessionCookieHash } from './gateway.server.js';

const sha = (v: string) => createHash('sha256').update(v).digest('hex');

describe('sessionCookieHash', () => {
  it('solo el hash de la cookie de sesión de la web (con o sin __Host-)', () => {
    expect(sessionCookieHash({ headers: { cookie: 'a=1; __Host-iw_session=tok; b=2' } })).toBe(
      sha('tok'),
    );
    expect(sessionCookieHash({ headers: { cookie: 'iw_session=dev' } })).toBe(sha('dev'));
    expect(sessionCookieHash({ headers: { cookie: 'otra=tok' } })).toBeNull();
    expect(sessionCookieHash({ headers: {} })).toBeNull();
    expect(sessionCookieHash({ headers: { cookie: `iw_session=${'x'.repeat(200)}` } })).toBeNull();
  });
});

function control(live: { id: string; active: boolean }[], revoke: { id: string; message: string }[]) {
  const sessions = live.map((l) => ({ id: l.id, takeActivity: () => l.active }));
  const server = { liveSessions: () => sessions, revoke: vi.fn() };
  const api = { heartbeat: vi.fn(async () => ({ revoke })) };
  const c = new GatewayControl(
    { get: () => 15 } as never,
    {} as never,
    api as never,
    server as never,
  );
  return { c, server, api };
}

describe('GatewayControl', () => {
  it('el latido manda las sesiones con su actividad y corta las que dice la API', async () => {
    const { c, server, api } = control(
      [
        { id: 's1', active: true },
        { id: 's2', active: false },
      ],
      [{ id: 's2', message: 'Ya no tienes permiso' }],
    );
    await c.beat('gateway-1');
    expect(api.heartbeat).toHaveBeenCalledWith({
      gateway: 'gateway-1',
      sessions: [
        { id: 's1', active: true },
        { id: 's2', active: false },
      ],
    });
    expect(server.revoke).toHaveBeenCalledWith([{ id: 's2', message: 'Ya no tienes permiso' }]);
  });

  it('sin sesiones no llama a la API; si la API falla, no corta nada', async () => {
    const empty = control([], []);
    await empty.c.beat('gateway-1');
    expect(empty.api.heartbeat).not.toHaveBeenCalled();
    const failing = control([{ id: 's1', active: false }], []);
    failing.api.heartbeat.mockRejectedValueOnce(new Error('no responde'));
    await failing.c.beat('gateway-1');
    expect(failing.server.revoke).not.toHaveBeenCalled();
  });

  it('los avisos del canal: solo los bien formados', () => {
    const { c, server } = control([], []);
    const onMessage = (c as unknown as { onMessage(raw: string): void }).onMessage.bind(c);
    onMessage('no es json');
    onMessage(JSON.stringify({ type: 'otro', sessions: [] }));
    onMessage(
      JSON.stringify({ type: 'revoke', sessions: [{ id: 's1', message: 'm' }, { id: 5 }] }),
    );
    expect(server.revoke).toHaveBeenCalledTimes(1);
    expect(server.revoke).toHaveBeenCalledWith([{ id: 's1', message: 'm' }]);
  });
});
