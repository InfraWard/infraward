import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, provideRouter, Router } from '@angular/router';
import type {
  AssetVulnerabilitiesPage,
  VulnerabilityGroup,
} from '@infraward/shared-types';
import {
  AssetFindings,
  DEFAULT_FINDINGS_FILTER,
  packagesLabel,
  showAll,
  toQuery,
} from './asset-findings';

const pkg = (name: string, fixed: string | null = '3.0.15-1~deb12u1') => ({
  findingId: `f-${name}`,
  packageName: name,
  installedVersion: '3.0.11-1~deb12u2',
  fixedVersion: fixed,
  pkgPath: null,
  status: 'open' as const,
  priority: 40,
  noiseReason: null,
});

const group: VulnerabilityGroup = {
  vulnerabilityId: 'CVE-2024-37371',
  severity: 'CRITICAL',
  title: 'krb5: GSS message token handling',
  primaryUrl: 'javascript:alert(1)',
  fixable: true,
  packages: [pkg('libgssapi-krb5-2'), pkg('libk5crypto3'), pkg('libkrb5-3'), pkg('libkrb5support0', null)],
  priority: { score: 43, band: 'medium', reasons: [{ code: 'fix' }, { code: 'cvss', score: 9.8 }] },
  noiseReason: null,
  kev: false,
  epss: null,
  cvss: 9.8,
};

const page = (items: VulnerabilityGroup[]): AssetVulnerabilitiesPage => ({
  items,
  total: items.length,
  image: {
    assetId: 'img',
    imageId: `sha256:${'1'.repeat(64)}`,
    repoDigests: [],
    repoTags: ['nginx:1.25'],
    platform: 'linux/amd64',
    scanStatus: 'scanned',
    scanReason: null,
    scannedAt: '2026-10-10T00:00:00.000Z',
    scanSource: 'docker_save',
    trivyVersion: '0.75.0',
    dbUpdatedAt: null,
    vulnerabilityCount: 791,
  },
  sbom: null,
});

describe('filtro de vulnerabilidades', () => {
  it('por defecto: la vista principal (abiertas, prioridad media o más); «ver todas» quita los filtros', () => {
    expect(toQuery(DEFAULT_FINDINGS_FILTER, { offset: 0, limit: 25 })).toEqual({
      status: 'open',
      minPriority: 'medium',
      limit: 25,
      offset: 0,
    });
    expect(
      toQuery(
        { ...DEFAULT_FINDINGS_FILTER, kev: true, minEpss: 0.1, exposed: true, fixable: true },
        { offset: 0, limit: 25 },
      ),
    ).toMatchObject({ kev: true, minEpss: 0.1, exposure: 'any', fixable: true });
    expect(toQuery(showAll(DEFAULT_FINDINGS_FILTER), { offset: 25, limit: 25 })).toEqual({
      status: 'open',
      limit: 25,
      offset: 25,
    });
  });

  it('resume los paquetes de un CVE', () => {
    expect(packagesLabel(group)).toBe('libgssapi-krb5-2, libk5crypto3 +2');
    expect(packagesLabel({ ...group, packages: [pkg('openssl')] })).toBe('openssl');
  });
});

describe('AssetFindings', () => {
  it('una fila por CVE con sus paquetes dentro; «Ver todas» vuelve a pedir sin filtros', async () => {
    TestBed.configureTestingModule({
      imports: [AssetFindings],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AssetFindings);
    fixture.componentRef.setInput('assetId', 'web1');
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;

    const first = http.expectOne((r) => r.url === '/api/assets/web1/vulnerabilities');
    expect(first.request.params.toString()).toBe(
      'status=open&minPriority=medium&limit=25&offset=0',
    );
    first.flush(page([group]));
    await fixture.whenStable();
    expect(el.querySelectorAll('[data-vulnerability="CVE-2024-37371"]')).toHaveLength(1);
    const row = el.querySelector('[data-vulnerability="CVE-2024-37371"]')!;
    expect(row.textContent).toContain('4 paquetes');
    expect(row.textContent).toContain('Disponible');
    expect(row.querySelector('[data-priority]')?.textContent?.trim()).toContain('43');
    expect(row.querySelector('[data-reasons]')?.textContent).toContain('parche disponible');
    // El CVE lleva a su ficha en la app (no a la referencia externa de Trivy).
    expect(row.querySelector('a')?.getAttribute('href')).toBe('/vulnerabilities/CVE-2024-37371');
    expect(el.querySelector('[data-scan]')?.textContent).toContain('nginx:1.25');

    // Al desplegar, la tabla de paquetes.
    row.querySelector<HTMLButtonElement>('button')!.click();
    await fixture.whenStable();
    const packages = el.querySelector('[data-packages="CVE-2024-37371"]')!;
    expect(packages.querySelectorAll(':scope > tbody > tr')).toHaveLength(4);
    expect(packages.textContent).toContain('libkrb5support0');
    expect(packages.textContent).toContain('sin parche');

    el.querySelector<HTMLButtonElement>('[data-action="show-all"] button')!.click();
    const all = http.expectOne((r) => r.url === '/api/assets/web1/vulnerabilities');
    expect(all.request.params.toString()).toBe('status=open&limit=25&offset=0');
    all.flush(page([{ ...group, primaryUrl: 'https://avd.aquasec.com/nvd/cve-2024-37371' }]));
    await fixture.whenStable();
    const link = el.querySelector<HTMLAnchorElement>('[data-vulnerability="CVE-2024-37371"] a')!;
    expect(link.getAttribute('href')).toBe('/vulnerabilities/CVE-2024-37371');
    expect(link.getAttribute('target')).toBeNull();
    expect(el.querySelector('[data-action="defaults"]')).not.toBeNull();
    http.verify();
  });

  it('servidor: resumen de su SBOM y, si aún no tiene, cómo se genera', async () => {
    TestBed.configureTestingModule({
      imports: [AssetFindings],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AssetFindings);
    fixture.componentRef.setInput('assetId', 'srv');
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    // Mientras carga, nada de «sin SBOM».
    expect(el.querySelector('[data-sbom]')).toBeNull();
    http.expectOne((r) => r.url === '/api/assets/srv/vulnerabilities').flush({
      ...page([group]),
      image: null,
      sbom: {
        assetId: 'srv',
        source: 'rootfs',
        format: 'cyclonedx',
        specVersion: '1.7',
        os: { family: 'debian', name: '13.1' },
        packageCount: 145,
        sizeBytes: 90_000,
        trivyVersion: '0.75.0',
        generatedAt: '2026-10-11T10:00:00.000Z',
        evaluatedAt: '2026-10-11T10:00:00.000Z',
        dbUpdatedAt: '2026-10-11T06:00:00.000Z',
        vulnerabilityCount: 444,
        evaluationError: null,
      },
    });
    await fixture.whenStable();
    const sbom = el.querySelector('[data-sbom]')!.textContent!;
    expect(sbom).toContain('SBOM: 145 paquetes');
    expect(sbom).toContain('debian 13.1');
    expect(el.querySelector('[data-scan]')).toBeNull();

    el.querySelector<HTMLButtonElement>('[data-action="show-all"] button')!.click();
    http
      .expectOne((r) => r.url === '/api/assets/srv/vulnerabilities')
      .flush({ ...page([]), image: null, sbom: null });
    await fixture.whenStable();
    expect(el.querySelector('[data-sbom]')!.textContent).toContain('Sin SBOM todavía');
    http.verify();
  });

  it('el filtro sale de la URL y vuelve a ella; el CVE lleva a su ficha recordando de dónde se viene', async () => {
    TestBed.configureTestingModule({
      imports: [AssetFindings],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParams: { tab: 'findings', prio: 'any' } } },
        },
      ],
    });
    const http = TestBed.inject(HttpTestingController);
    const router = TestBed.inject(Router);
    vi.spyOn(router, 'url', 'get').mockReturnValue('/assets/web1?tab=findings&prio=any');
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const navigateByUrl = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    const fixture = TestBed.createComponent(AssetFindings);
    fixture.componentRef.setInput('assetId', 'web1');
    fixture.componentRef.setInput('assetName', 'web1');
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;

    // «Ver todas» de la URL: sin prioridad mínima.
    const first = http.expectOne((r) => r.url === '/api/assets/web1/vulnerabilities');
    expect(first.request.params.toString()).toBe('status=open&limit=25&offset=0');
    first.flush(page([group]));
    await fixture.whenStable();

    el.querySelector<HTMLAnchorElement>('[data-vulnerability="CVE-2024-37371"] a')!.click();
    expect(navigateByUrl).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        state: { from: { url: '/assets/web1?tab=findings&prio=any', label: 'web1' } },
      }),
    );

    el.querySelector<HTMLButtonElement>('[data-action="defaults"] button')!.click();
    expect(navigate).toHaveBeenCalledWith([], expect.objectContaining({
      queryParams: {
        status: null,
        min: null,
        fixable: null,
        prio: null,
        kev: null,
        epss: null,
        exposed: null,
      },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    }));
    http.expectOne((r) => r.url === '/api/assets/web1/vulnerabilities').flush(page([]));
  });
});

