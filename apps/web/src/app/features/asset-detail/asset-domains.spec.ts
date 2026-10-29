import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { AssetDomains, DnsRecordCheck } from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { AssetDomainsCard } from './asset-domains';
import { DnsCheckCard } from './dns-check';
import { dnsRecordItems, zoneItems } from './facts-summary';

const ID = '00000000-0000-4000-8000-000000000001';
const rec = (id: string, name: string, type: string) => ({ id, name: `${name} · ${type}`, type: 'dns_record' as const, status: 'active' as const });

function configure(component: unknown) {
  TestBed.configureTestingModule({
    imports: [component as never],
    providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting(), MessageService],
  });
  return TestBed.inject(HttpTestingController);
}

describe('AssetDomainsCard', () => {
  it('«Dominios que le apuntan»: directos y por CNAME, con la caducidad del certificado', () => {
    storeSession('viewer');
    const http = configure(AssetDomainsCard);
    const fixture = TestBed.createComponent(AssetDomainsCard);
    fixture.componentRef.setInput('assetId', ID);
    fixture.detectChanges();
    http.expectOne('/api/settings/expiry-warnings').flush({ days: [30, 7] });
    const soon = new Date(Date.now() + 5 * 86_400_000).toISOString();
    const body: AssetDomains = {
      records: [
        {
          record: rec('r1', 'ejemplo.dev', 'A'),
          domain: { id: 'd', name: 'ejemplo.dev', type: 'domain', status: 'active' },
          dns: { name: 'ejemplo.dev', type: 'A', content: '203.0.113.10', proxied: true },
          hops: 1,
          via: [],
          certificate: { id: 'c', name: 'ejemplo.dev', notAfter: soon },
        },
        {
          record: rec('r2', 'www.ejemplo.dev', 'CNAME'),
          domain: null,
          dns: { name: 'www.ejemplo.dev', type: 'CNAME', content: 'ejemplo.dev', proxied: false },
          hops: 2,
          via: [rec('r1', 'ejemplo.dev', 'A')],
          certificate: null,
        },
      ],
    };
    http.expectOne(`/api/assets/${ID}/domains`).flush(body);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-section="domains"]')?.textContent).toContain('Dominios que le apuntan (2)');
    expect(el.querySelector('[data-record="www.ejemplo.dev"]')?.textContent).toContain('vía ejemplo.dev');
    expect(el.querySelector('[data-record="ejemplo.dev"] [data-cert-expiry]')?.textContent).toContain('caduca en');
    http.verify();
  });

  it('sin registros no pinta nada', () => {
    storeSession('viewer');
    const http = configure(AssetDomainsCard);
    const fixture = TestBed.createComponent(AssetDomainsCard);
    fixture.componentRef.setInput('assetId', ID);
    fixture.detectChanges();
    http.match('/api/settings/expiry-warnings').forEach((r) => r.flush({ days: [30, 7] }));
    http.expectOne(`/api/assets/${ID}/domains`).flush({ records: [] });
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-section="domains"]')).toBeNull();
  });
});

describe('DnsCheckCard', () => {
  const check: DnsRecordCheck = {
    level: 'high',
    reason: 'cname_nxdomain',
    target: 'viejo.herokuapp.com',
    ambiguous: false,
    takeoverService: 'Heroku',
    checkedAt: '2026-10-14T10:00:00.000Z',
    sameTarget: 0,
    accepted: null,
  };

  it('colgante con su motivo y «Marcar como esperado»', () => {
    storeSession('admin');
    const http = configure(DnsCheckCard);
    const fixture = TestBed.createComponent(DnsCheckCard);
    fixture.componentRef.setInput('assetId', ID);
    fixture.detectChanges();
    http.expectOne(`/api/assets/${ID}/dns-check`).flush(check);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-dns-level="high"]')).not.toBeNull();
    expect(el.querySelector('[data-dns-reason]')?.textContent).toContain('subdomain takeover');
    expect(el.textContent).toContain('Servicio: Heroku');
    (el.querySelector('[data-action="accept-dns"] button') as HTMLButtonElement).click();
    const req = http.expectOne(`/api/assets/${ID}/dns-check/acceptance`);
    expect(req.request.method).toBe('POST');
    req.flush({ ...check, accepted: { at: '2026-10-14T11:00:00.000Z', by: 'admin@example.com' } });
    fixture.detectChanges();
    expect(el.querySelector('[data-dns-level="accepted"]')).not.toBeNull();
    expect(el.querySelector('[data-action="reopen-dns"]')).not.toBeNull();
    http.verify();
  });

  it('informativo con más registros a la misma IP: «marcar los N» en bloque (nunca en uno alto)', () => {
    storeSession('admin');
    const http = configure(DnsCheckCard);
    const fixture = TestBed.createComponent(DnsCheckCard);
    fixture.componentRef.setInput('assetId', ID);
    fixture.detectChanges();
    http.expectOne(`/api/assets/${ID}/dns-check`).flush({
      ...check,
      level: 'info',
      reason: 'public_unknown',
      target: '79.117.125.88',
      takeoverService: null,
      sameTarget: 28,
    });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const bulk = el.querySelector('[data-action="accept-dns-target"] button') as HTMLButtonElement;
    expect(bulk.textContent).toContain('Marcar los 28 que apuntan a 79.117.125.88');
    bulk.click();
    const req = http.expectOne('/api/dns-checks/acceptance');
    expect(req.request.body).toEqual({ target: '79.117.125.88' });
    req.flush({ accepted: 28 });
    http.expectOne(`/api/assets/${ID}/dns-check`).flush({ ...check, level: 'info', sameTarget: 0, accepted: { at: 'x', by: 'a' } });
    http.verify();
  });

  it('un lector ve el aviso sin poder marcarlo', () => {
    storeSession('viewer');
    const http = configure(DnsCheckCard);
    const fixture = TestBed.createComponent(DnsCheckCard);
    fixture.componentRef.setInput('assetId', ID);
    fixture.detectChanges();
    http.expectOne(`/api/assets/${ID}/dns-check`).flush(check);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-action="accept-dns"]')).toBeNull();
  });
});

describe('Resumen de dominios y registros', () => {
  it('dominio: caducidad por RDAP (o «sin RDAP»), registrador y nameservers', () => {
    const items = zoneItems({
      zone: { provider: 'cloudflare', status: 'active', paused: false, nameServers: ['ada.ns.cloudflare.com'], plan: 'Free', account: 'Pruebas' },
      registration: { source: 'rdap', state: 'ok', expiresAt: '2027-03-01T00:00:00Z', registrar: 'Cloudflare, Inc.', statuses: ['client transfer prohibited'], checkedAt: '2026-10-14T10:00:00Z' },
    });
    const byLabel = Object.fromEntries(items.map((i) => [i.label, i.value]));
    expect(byLabel['Registrador']).toBe('Cloudflare, Inc.');
    expect(byLabel['Nameservers']).toBe('ada.ns.cloudflare.com');
    expect(byLabel['Estados']).toBe('transferencia bloqueada');
    expect(byLabel['Caduca el']).toBeTruthy();
    const es = zoneItems({ registration: { source: 'rdap', state: 'unsupported', statuses: [], checkedAt: '2026-10-14T10:00:00Z' } });
    expect(es[0].value).toContain('sin RDAP');
  });

  it('registro: valor, proxy y lectura del 443', () => {
    const items = dnsRecordItems({
      dns: { provider: 'cloudflare', name: 'www.ejemplo.dev', type: 'A', content: '203.0.113.10', truncated: false, ttl: 1, proxied: true, priority: null },
      tls: { status: 'ok', authorized: false, authorizationError: 'SELF_SIGNED_CERT', hostnameMatch: false, checkedAt: '2026-10-14T10:00:00Z' },
    });
    const byLabel = Object.fromEntries(items.map((i) => [i.label, i.value]));
    expect(byLabel['TTL']).toBe('automático');
    expect(byLabel['Proxy de Cloudflare']).toContain('sí');
    expect(byLabel['TLS en el 443']).toContain('no cubre el nombre');
  });
});
