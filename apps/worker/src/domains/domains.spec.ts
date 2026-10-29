import { DomainApiError } from '@infraward/connectors';
import { describe, expect, it, vi } from 'vitest';
import { BearerApi, getJson, type FetchFn } from './domain-http.js';
import { classifyLookup, dnsServers } from './dns-resolver.js';
import { crossedThresholds, expiryPhrase } from './expiry-alerts.js';

const TOKEN = 'CENTINELA-TOKEN-0123456789abcdef0123456789';

const reply = (status: number, body: unknown): FetchFn =>
  vi.fn(() =>
    Promise.resolve(new Response(JSON.stringify(body), { status })),
  ) as unknown as FetchFn;

describe('BearerApi', () => {
  it('manda el token como Bearer y la consulta en la URL', async () => {
    const fetchFn = reply(200, { success: true, result: [] });
    const api = new BearerApi('https://api.example/client/v4/', TOKEN, 1000, fetchFn);
    await api.getJson('/zones', { page: 2, per_page: 50 });
    const [url, init] = (fetchFn as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('https://api.example/client/v4/zones?page=2&per_page=50');
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
    expect(init.redirect).toBe('error');
  });

  it('los errores llevan el estado y el código del proveedor, nunca el cuerpo ni el token', async () => {
    const api = new BearerApi(
      'https://api.example',
      TOKEN,
      1000,
      reply(403, { success: false, errors: [{ code: 10000, message: `token ${TOKEN} sin permiso` }] }),
    );
    const error = await api.getJson('/zones').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(DomainApiError);
    expect((error as Error).message).toBe('HTTP 403 (código 10000)');
    expect(JSON.stringify(error)).not.toContain(TOKEN);
    expect(JSON.stringify(api)).not.toContain(TOKEN);
    expect(String((error as Error).stack)).not.toContain(TOKEN);
  });

  it('timeout, sin red y respuesta que no es JSON', async () => {
    const timeout = vi.fn(() =>
      Promise.reject(Object.assign(new Error('x'), { name: 'TimeoutError' })),
    ) as unknown as FetchFn;
    await expect(getJson('https://x', {}, 1500, timeout)).rejects.toThrow('sin respuesta en 1500 ms');
    const down = vi.fn(() => Promise.reject(new TypeError('fetch failed'))) as unknown as FetchFn;
    await expect(getJson('https://x', {}, 1500, down)).rejects.toThrow('no se pudo conectar');
    const html = vi.fn(() => Promise.resolve(new Response('<html>', { status: 200 }))) as unknown as FetchFn;
    await expect(getJson('https://x', {}, 1500, html)).rejects.toThrow('respuesta que no es JSON');
  });
});

describe('avisos de caducidad', () => {
  const NOW = new Date('2026-10-14T00:00:00Z');
  const inDays = (d: number) => new Date(NOW.getTime() + d * 86_400_000);

  it('umbrales cruzados (0 = caducado)', () => {
    expect(crossedThresholds(inDays(40), [30, 7], NOW)).toEqual([]);
    expect(crossedThresholds(inDays(20), [30, 7], NOW)).toEqual([30]);
    expect(crossedThresholds(inDays(3), [30, 7], NOW)).toEqual([30, 7]);
    expect(crossedThresholds(inDays(-1), [30, 7], NOW)).toEqual([30, 7, 0]);
  });

  it('frases', () => {
    expect(expiryPhrase(inDays(6), NOW)).toBe('caduca en 6 días');
    expect(expiryPhrase(inDays(0.5), NOW)).toBe('caduca en menos de un día');
    expect(expiryPhrase(inDays(-2), NOW)).toBe('caducó hace 2 días');
  });
});

describe('classifyLookup (CNAME externos)', () => {
  it('solo NXDOMAIN en todo es «no existe»; un nombre con solo TXT (DKIM) existe', () => {
    expect(classifyLookup(['ENOTFOUND', 'ENOTFOUND', 'ENOTFOUND'])).toBe('nxdomain');
    // dkim.smtp2go.net: sin A, AAAA ni CNAME, pero existe (tiene TXT).
    expect(classifyLookup(['ENODATA', 'ENODATA', 'ENODATA'])).toBe('exists');
    expect(classifyLookup(['ENOTFOUND', 'ENODATA', 'ENOTFOUND'])).toBe('exists');
    expect(classifyLookup([null, 'ENODATA', 'ENODATA'])).toBe('exists');
    expect(classifyLookup(['ETIMEOUT', 'ENOTFOUND', 'ENOTFOUND'])).toBe('error');
    expect(classifyLookup(['ESERVFAIL', 'ESERVFAIL', 'ESERVFAIL'])).toBe('error');
  });
});

describe('DOMAINS_DNS_SERVERS', () => {
  it('lista o null', () => {
    expect(dnsServers(undefined)).toBeNull();
    expect(dnsServers('127.0.0.1:5353, [::1]:53')).toEqual(['127.0.0.1:5353', '[::1]:53']);
  });
});
