import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer as createNetServer, type LookupFunction, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server as TlsServer } from 'node:tls';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { x509Facts } from '../plesk/certificate.js';
import { mapLimit, probeTls } from './tls-probe.js';

// Cualquier nombre resuelve a 127.0.0.1: los tests no dependen del DNS.
const lookup: LookupFunction = (_host, options, cb) => {
  if (options.all) cb(null, [{ address: '127.0.0.1', family: 4 }]);
  else cb(null, '127.0.0.1', 4);
};

let dir: string;
let tls: TlsServer;
let silent: Server;
let tlsPort: number;
let silentPort: number;

const listen = (s: Server): Promise<number> =>
  new Promise((resolve) =>
    s.listen(0, '127.0.0.1', () => resolve((s.address() as { port: number }).port)),
  );

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'infraward-tls-'));
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '30',
    '-subj', '/CN=www.ejemplo.test', '-addext', 'subjectAltName=DNS:www.ejemplo.test',
  ], { stdio: 'ignore' });
  tls = createServer({
    key: readFileSync(join(dir, 'key.pem')),
    cert: readFileSync(join(dir, 'cert.pem')),
  });
  tlsPort = await listen(tls);
  // Acepta la conexión TCP y no contesta nunca al apretón de manos.
  silent = createNetServer(() => undefined);
  silentPort = await listen(silent);
});

afterAll(() => {
  tls?.close();
  silent?.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('probeTls', () => {
  it('lee el certificado con SNI aunque sea autofirmado, y dice que no es de confianza', async () => {
    const r = await probeTls('www.ejemplo.test', { port: tlsPort, timeoutMs: 3000, lookup });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r).toMatchObject({ authorized: false, hostnameMatch: true });
    expect(r.authorizationError).toMatch(/SELF_SIGNED|self.signed/i);
    const facts = x509Facts(r.certificate);
    expect(facts.subject).toBe('CN=www.ejemplo.test');
    expect(facts.selfSigned).toBe(true);
    expect(Date.parse(facts.notAfter!)).toBeGreaterThan(Date.now());
  });

  it('nombre que el certificado no cubre', async () => {
    const r = await probeTls('otro.ejemplo.test', { port: tlsPort, timeoutMs: 3000, lookup });
    expect(r).toMatchObject({ ok: true, hostnameMatch: false });
  });

  it('conexión rechazada y servidor mudo (timeout)', async () => {
    const closed = createNetServer();
    const port = await listen(closed);
    await new Promise((r) => closed.close(r));
    expect(await probeTls('x.test', { port, timeoutMs: 3000, lookup })).toEqual({
      ok: false,
      error: 'conexión rechazada en el 443',
    });
    expect(await probeTls('x.test', { port: silentPort, timeoutMs: 200, lookup })).toEqual({
      ok: false,
      error: 'sin respuesta a tiempo',
    });
  });
});

describe('mapLimit', () => {
  it('respeta el límite y el orden', async () => {
    let running = 0;
    let peak = 0;
    const out = await mapLimit([5, 1, 3, 2, 4], 2, async (n) => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, n * 3));
      running--;
      return n * 10;
    });
    expect(out).toEqual([50, 10, 30, 20, 40]);
    expect(peak).toBe(2);
  });
});
