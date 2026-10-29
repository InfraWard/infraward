import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { ServicePathView } from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { storeSession } from '../../testing/session';
import { DomainServicePathsCard, ServedDomainsCard } from './served-domains';
import { ServicePathCard } from './service-path';

const ID = '00000000-0000-4000-8000-000000000001';
const asset = (id: string, name: string, type: 'lxc' | 'container' = 'container') => ({
  id,
  name,
  type,
  status: 'active' as const,
});

const complete: ServicePathView = {
  recordId: ID,
  record: 'app.example.com',
  status: 'complete',
  confidence: 'confirmed',
  cutReason: null,
  final: asset('app', 'app'),
  hops: [
    { assetId: null, asset: null, label: '203.0.113.7:443', port: 443, resolver: 'dns', source: 'A app.example.com → 203.0.113.7', confidence: 'confirmed' },
    { assetId: 'ct', asset: asset('ct', 'ct-docker', 'lxc'), label: 'ct-docker:443', port: 443, resolver: 'nat', source: 'reenvío NAT 203.0.113.7:443 → ct-docker:443', confidence: 'confirmed' },
    { assetId: 'npm', asset: asset('npm', 'npm'), label: 'npm:443', port: 443, resolver: 'docker-proxy', source: 'ct-docker:443 publicado → npm:443', confidence: 'confirmed' },
    { assetId: 'app', asset: asset('app', 'app'), label: 'app:3000', port: 3000, resolver: 'npm', source: 'npm: server_name app.example.com → 172.18.0.5:3000', confidence: 'confirmed' },
  ],
  pinned: null,
  computedAt: '2026-10-15T10:00:00Z',
};

function configure(component: unknown) {
  TestBed.configureTestingModule({
    imports: [component as never],
    providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting(), MessageService],
  });
  return TestBed.inject(HttpTestingController);
}

describe('ServicePathCard', () => {
  it('camino completo: cada eslabón con su origen y el destino final', () => {
    storeSession('viewer');
    const http = configure(ServicePathCard);
    const fixture = TestBed.createComponent(ServicePathCard);
    fixture.componentRef.setInput('assetId', ID);
    fixture.detectChanges();
    http.expectOne(`/api/assets/${ID}/service-path`).flush(complete);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-path-status]')?.textContent).toContain('Completo');
    expect(el.querySelector('[data-path-final]')?.textContent).toContain('app');
    expect([...el.querySelectorAll('[data-hop]')].map((h) => h.getAttribute('data-hop'))).toEqual([
      'dns',
      'nat',
      'docker-proxy',
      'npm',
    ]);
    expect(el.querySelector('[data-hop="npm"]')?.textContent).toContain('server_name app.example.com');
    expect(el.querySelector('[data-path-cut]')).toBeNull();
    // Un lector no puede fijar el destino.
    expect(el.querySelector('[data-action="pin-path"]')).toBeNull();
    http.verify();
  });

  it('cortado: hasta dónde llegó, por qué, y «Fijar el destino» con el buscador', () => {
    storeSession('admin');
    const http = configure(ServicePathCard);
    const fixture = TestBed.createComponent(ServicePathCard);
    fixture.componentRef.setInput('assetId', ID);
    fixture.detectChanges();
    http.expectOne(`/api/assets/${ID}/service-path`).flush({
      ...complete,
      status: 'partial',
      final: null,
      cutReason: 'proxy_unreadable',
      hops: complete.hops.slice(0, 3),
    } satisfies ServicePathView);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-path-status]')?.textContent).toContain('Cortado');
    expect(el.querySelector('[data-path-cut]')?.textContent).toContain('sudoers anterior a la v5');
    (el.querySelector('[data-action="pin-path"] button') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-asset-picker]')).not.toBeNull();
    http.verify();
  });
});

describe('ServedDomainsCard y DomainServicePathsCard', () => {
  it('dominios que sirve un asset y los que pasan por él', () => {
    storeSession('viewer');
    const http = configure(ServedDomainsCard);
    const fixture = TestBed.createComponent(ServedDomainsCard);
    fixture.componentRef.setInput('assetId', 'npm');
    fixture.detectChanges();
    http.expectOne('/api/assets/npm/served-domains').flush({
      records: [
        { record: { id: 'r1', name: 'npm.example.com', type: 'dns_record', status: 'active' }, role: 'final', status: 'complete', confidence: 'confirmed', final: asset('npm', 'npm') },
        { record: { id: 'r2', name: 'app.example.com', type: 'dns_record', status: 'active' }, role: 'via', status: 'complete', confidence: 'confirmed', final: asset('app', 'app') },
      ],
    });
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-served="final"]')?.textContent).toContain('npm.example.com');
    expect(el.querySelector('[data-served="via"]')?.textContent).toMatch(/app\.example\.com\s*→\s*app/);
    http.verify();
  });

  it('qué sirve cada nombre de un dominio: los que llegan primero', () => {
    storeSession('viewer');
    const http = configure(DomainServicePathsCard);
    const fixture = TestBed.createComponent(DomainServicePathsCard);
    fixture.componentRef.setInput('assetId', 'd');
    fixture.detectChanges();
    http.expectOne('/api/assets/d/service-paths').flush({
      paths: [
        { ...complete, recordId: 'r0', record: 'mail.example.com', status: 'none', final: null, hops: [], cutReason: 'no_target', confidence: null },
        complete,
      ],
    });
    fixture.detectChanges();
    const rows = [...(fixture.nativeElement as HTMLElement).querySelectorAll('[data-path-record]')];
    expect(rows.map((r) => r.getAttribute('data-path-record'))).toEqual(['app.example.com', 'mail.example.com']);
    expect(rows[0].textContent).toContain('app');
    http.verify();
  });
});
