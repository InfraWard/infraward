import { describe, expect, it } from 'vitest';
import { CloudflareProvider } from './cloudflare.js';
import { DomainApiError, type DomainApi } from './domain-provider.js';

const Z1 = '023e105f4ecef8ad9ca31a8372d0c353';
const Z2 = '9a7806061c88ada191ed06f989cc3dac';
const rid = (n: number) => n.toString(16).padStart(32, '0');

type Handler = (
  path: string,
  query: Record<string, string | number>,
) => unknown;

function api(handler: Handler): DomainApi & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    getJson(path, query = {}) {
      calls.push(`${path}?${new URLSearchParams(query as never)}`);
      return Promise.resolve().then(() => handler(path, query));
    },
  };
}

const ok = (result: unknown, totalPages = 1) => ({
  success: true,
  errors: [],
  result,
  result_info: { total_pages: totalPages },
});

const zone = (id: string, name: string) => ({
  id,
  name,
  status: 'active',
  paused: false,
  name_servers: ['ada.ns.cloudflare.com.', 'bob.ns.cloudflare.com'],
  plan: { name: 'Free Website' },
  account: { id: 'acc1', name: 'Pruebas' },
});

const record = (n: number, name: string, type: string, content: string, extra = {}) => ({
  id: rid(n),
  name,
  type,
  content,
  ttl: 1,
  proxied: false,
  comment: 'nota privada que no se guarda',
  ...extra,
});

describe('CloudflareProvider', () => {
  const cf = new CloudflareProvider();

  it('lista zonas y registros de todas las páginas, normalizados y sin comentarios', async () => {
    const a = api((path, q) => {
      if (path === '/zones')
        return q.page === 1
          ? ok([zone(Z1, 'Ejemplo.dev')], 2)
          : ok([zone(Z2, 'otro.net')], 2);
      if (path === `/zones/${Z1}/dns_records`)
        return q.page === 1
          ? ok([record(1, 'WWW.ejemplo.dev.', 'A', '203.0.113.10', { proxied: true })], 2)
          : ok([record(2, 'mx.ejemplo.dev', 'MX', 'mail.ejemplo.dev', { priority: 10 })], 2);
      return ok([record(3, 'otro.net', 'CNAME', 'x.herokuapp.com')]);
    });
    const listing = await cf.list(a);
    expect(listing.complete).toBe(true);
    expect(listing.zones.map((z) => [z.name, z.nameServers, z.account])).toEqual([
      ['ejemplo.dev', ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'], { id: 'acc1', name: 'Pruebas' }],
      ['otro.net', ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'], { id: 'acc1', name: 'Pruebas' }],
    ]);
    expect(listing.records).toEqual([
      { id: rid(1), zoneId: Z1, name: 'www.ejemplo.dev', type: 'A', content: '203.0.113.10', ttl: 1, proxied: true, priority: null },
      { id: rid(2), zoneId: Z1, name: 'mx.ejemplo.dev', type: 'MX', content: 'mail.ejemplo.dev', ttl: 1, proxied: false, priority: 10 },
      { id: rid(3), zoneId: Z2, name: 'otro.net', type: 'CNAME', content: 'x.herokuapp.com', ttl: 1, proxied: false, priority: null },
    ]);
    expect(JSON.stringify(listing)).not.toContain('nota privada');
    expect(a.calls).toContain(`/zones/${Z1}/dns_records?page=2&per_page=1000`);
  });

  it('una zona que falla o un registro raro dejan el listado incompleto (nada a missing)', async () => {
    const listing = await cf.list(
      api((path) => {
        if (path === '/zones') return ok([zone(Z1, 'ejemplo.dev'), zone(Z2, 'otro.net')]);
        if (path.includes(Z1)) throw new DomainApiError('HTTP 403 (código 10000)', 403, 10000);
        return ok([record(1, 'otro.net', 'A', '1.2.3.4'), { id: 'x', type: 'A' }]);
      }),
    );
    expect(listing.complete).toBe(false);
    expect(listing.records).toHaveLength(1);
    expect(listing.warnings).toEqual([
      'ejemplo.dev: no se pudieron listar los registros (HTTP 403 (código 10000))',
      'otro.net: registro que no se entiende',
    ]);
  });

  it('ignora los tipos que no se inventarían y rechaza nombres no válidos', async () => {
    const listing = await cf.list(
      api((path) =>
        path === '/zones'
          ? ok([zone(Z1, 'ejemplo.dev'), zone('mal', 'x.dev'), zone(Z2, 'a b.dev')])
          : ok([record(1, 'ejemplo.dev', 'OPENPGPKEY', 'x'), record(2, '*.ejemplo.dev', 'A', '1.2.3.4')]),
      ),
    );
    expect(listing.zones.map((z) => z.name)).toEqual(['ejemplo.dev']);
    expect(listing.records.map((r) => r.name)).toEqual(['*.ejemplo.dev']);
    expect(listing.complete).toBe(false);
  });

  it('verify: token de usuario activo con zonas y permiso DNS', async () => {
    const v = await cf.verify(
      api((path) => {
        if (path === '/user/tokens/verify') return ok({ id: 't', status: 'active', expires_on: '2027-01-01T00:00:00Z' });
        if (path === '/zones') return ok([zone(Z1, 'ejemplo.dev')]);
        return ok([]);
      }),
    );
    expect(v).toEqual({
      ok: true,
      error: null,
      tokenStatus: 'active',
      tokenExpiresAt: '2027-01-01T00:00:00Z',
      accounts: ['Pruebas'],
      zones: 1,
      warnings: [],
    });
  });

  it('verify: token de cuenta (falla el de usuario y vale el de su cuenta)', async () => {
    const a = api((path) => {
      if (path === '/user/tokens/verify') throw new DomainApiError('HTTP 401 (código 1000)', 401, 1000);
      if (path === '/accounts/acc1/tokens/verify') return ok({ id: 't', status: 'active' });
      if (path === '/zones') return ok([zone(Z1, 'ejemplo.dev')]);
      return ok([]);
    });
    const v = await cf.verify(a);
    expect(v.ok).toBe(true);
    expect(a.calls).toContain('/accounts/acc1/tokens/verify?');
  });

  it('verify: token inválido, sin Zone:Read, sin DNS:Read o caducado', async () => {
    const denied = () => {
      throw new DomainApiError('HTTP 401 (código 1000)', 401, 1000);
    };
    expect(await cf.verify(api(denied))).toMatchObject({ ok: false, error: 'HTTP 401 (código 1000)' });

    const noZones = await cf.verify(
      api((path) => (path === '/user/tokens/verify' ? ok({ status: 'active' }) : denied())),
    );
    expect(noZones.ok).toBe(false);
    expect(noZones.error).toContain('Zone:Read');

    const noDns = await cf.verify(
      api((path) => {
        if (path === '/user/tokens/verify') return ok({ status: 'active' });
        if (path === '/zones') return ok([zone(Z1, 'ejemplo.dev')]);
        return denied();
      }),
    );
    expect(noDns.ok).toBe(true);
    expect(noDns.warnings[0]).toContain('DNS:Read');

    const expired = await cf.verify(
      api((path) => (path === '/user/tokens/verify' ? ok({ status: 'expired' }) : ok([]))),
    );
    expect(expired).toMatchObject({ ok: false, tokenStatus: 'expired', error: 'el token está expired' });
  });
});

describe('túneles de Cloudflare (QoL-5b)', () => {
  const ACCOUNT = 'a'.repeat(32);
  const TUNNEL = '0b1c2d3e-1111-2222-3333-444455556666';
  const config = {
    config: {
      ingress: [
        {
          hostname: 'App.Example.com',
          service: 'http://user:centinela-url@web:8080',
          originRequest: {
            httpHostHeader: 'centinela-cabecera',
            access: { required: true, audTag: ['centinela-aud'] },
          },
        },
        { hostname: 'ssh.example.com', service: 'ssh://localhost:22' },
        { hostname: 'bad host', service: 'http://x' },
        { service: 'http_status:404' },
      ],
      warp_routing: { enabled: false },
    },
  };
  const api = (failTunnels = false) => ({
    getJson: (path: string) => {
      if (path === `/accounts/${ACCOUNT}/cfd_tunnel`) {
        if (failTunnels)
          return Promise.reject(new DomainApiError('HTTP 403', 403, 10000));
        return Promise.resolve({
          success: true,
          result: [
            { id: TUNNEL, name: 'casa', status: 'healthy', remote_config: true },
            { id: '1b1c2d3e-1111-2222-3333-444455556666', name: 'local', status: 'down', remote_config: false },
          ],
          result_info: { total_pages: 1 },
        });
      }
      if (path === `/accounts/${ACCOUNT}/cfd_tunnel/${TUNNEL}/configurations`)
        return Promise.resolve({ success: true, result: config });
      return Promise.reject(new Error(`inesperado: ${path}`));
    },
  });

  it('solo nombre, ruta y servicio de cada regla; nunca originRequest ni credenciales', async () => {
    const out = await new CloudflareProvider().tunnels(api(), [ACCOUNT]);
    expect(JSON.stringify(out)).not.toContain('centinela');
    expect(out).toEqual({
      complete: true,
      error: null,
      items: [
        {
          id: TUNNEL,
          name: 'casa',
          status: 'healthy',
          ingress: [
            { hostname: 'app.example.com', path: null, service: 'http://web:8080' },
            { hostname: 'ssh.example.com', path: null, service: 'ssh://localhost:22' },
            { hostname: null, path: null, service: 'http_status:404' },
          ],
        },
        {
          id: '1b1c2d3e-1111-2222-3333-444455556666',
          name: 'local',
          status: 'down',
          ingress: null,
        },
      ],
    });
  });

  it('sin el permiso opcional: sin túneles y el motivo', async () => {
    const out = await new CloudflareProvider().tunnels(api(true), [ACCOUNT]);
    expect(out.items).toEqual([]);
    expect(out.complete).toBe(false);
    expect(out.error).toContain('Cloudflare Tunnel · Read');
  });
});
