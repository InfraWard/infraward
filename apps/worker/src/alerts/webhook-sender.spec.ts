import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { networkInterfaces } from 'node:os';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { webhookPayload, webhookSignature } from './alert-message.js';
import { AlertSendError, sendWebhook } from './webhook-sender.js';

/** Una IPv4 de la máquina que no sea loopback (los webhooks a 127.0.0.1 no se admiten nunca). */
const lanIp = Object.values(networkInterfaces())
  .flat()
  .find((i) => i && i.family === 'IPv4' && !i.internal)?.address;

const payload = webhookPayload(
  {
    id: 'n1',
    kind: 'asset_created',
    assetId: null,
    assetName: 'pve',
    message: 'pve: 1 nuevo — ct (lxc)',
    items: [],
    total: 1,
    createdAt: new Date('2026-10-29T10:00:00Z'),
  },
  undefined,
);

describe.skipIf(!lanIp)('sendWebhook', () => {
  let server: Server;
  let port: number;
  let status = 200;
  /** `slow`: no contesta nunca; `drip`: cabeceras al momento y el cuerpo gota a gota, sin fin. */
  let mode: 'normal' | 'slow' | 'drip' = 'normal';
  const received: { req: IncomingMessage; body: string }[] = [];
  const drips: NodeJS.Timeout[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        received.push({ req, body });
        if (mode === 'slow') return;
        if (mode === 'drip') {
          res.writeHead(200);
          drips.push(setInterval(() => res.write('.'), 50));
          return;
        }
        res.writeHead(status, status === 302 ? { location: 'http://169.254.169.254/' } : {});
        res.end('ok');
      });
    });
    await new Promise<void>((r) => server.listen(0, '0.0.0.0', r));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(() => {
    drips.forEach(clearInterval);
    server.closeAllConnections();
    return new Promise<void>((r) => server.close(() => r()));
  });

  const url = () => `http://${lanIp}:${port}/hook?x=1`;
  const allowed = { allowHttp: true, allowPrivate: true, timeoutMs: 5000 };

  it('POST JSON firmado', async () => {
    status = 200;
    await sendWebhook(url(), payload, { ...allowed, secret: 's3cr3t', now: () => 1_700_000_000_000 });
    const { req, body } = received.at(-1)!;
    expect(req.method).toBe('POST');
    expect(req.url).toBe('/hook?x=1');
    expect(JSON.parse(body)).toEqual(payload);
    expect(req.headers['x-infraward-event']).toBe('asset_created');
    expect(req.headers['x-infraward-timestamp']).toBe('1700000000');
    expect(req.headers['x-infraward-signature']).toBe(webhookSignature('s3cr3t', 1_700_000_000, body));
  });

  it('sin secreto, sin firma', async () => {
    await sendWebhook(url(), payload, allowed);
    expect(received.at(-1)!.req.headers['x-infraward-signature']).toBeUndefined();
  });

  it('un error HTTP o una redirección fallan (sin seguirla)', async () => {
    status = 500;
    await expect(sendWebhook(url(), payload, allowed)).rejects.toThrow('HTTP 500');
    status = 302;
    const before = received.length;
    await expect(sendWebhook(url(), payload, allowed)).rejects.toThrow(/redirecciones/);
    expect(received.length).toBe(before + 1);
  });

  it('el plazo es total: sin respuesta, falla a tiempo; con cabeceras, no espera al cuerpo', async () => {
    mode = 'slow';
    const start = Date.now();
    await expect(sendWebhook(url(), payload, { ...allowed, timeoutMs: 1000 })).rejects.toThrow(
      'Sin respuesta a tiempo',
    );
    expect(Date.now() - start).toBeLessThan(3000);
    // Un cuerpo que no acaba nunca (y que reiniciaría un plazo de inactividad) no retiene el envío.
    mode = 'drip';
    const dripStart = Date.now();
    await sendWebhook(url(), payload, { ...allowed, timeoutMs: 1000 });
    expect(Date.now() - dripStart).toBeLessThan(1000);
    mode = 'normal';
  });

  it('el destino se valida antes de conectar', async () => {
    const before = received.length;
    await expect(sendWebhook(url(), payload, { timeoutMs: 5000 })).rejects.toThrow(AlertSendError);
    await expect(
      sendWebhook(url(), payload, { allowHttp: true, timeoutMs: 5000 }),
    ).rejects.toThrow(/privada/);
    await expect(
      sendWebhook(`http://127.0.0.1:${port}/`, payload, allowed),
    ).rejects.toThrow(/no permitida/);
    expect(received.length).toBe(before);
  });
});
