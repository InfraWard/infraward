import { TestBed } from '@angular/core/testing';
import type { ProjectStats } from '@infraward/shared-types';
import { AssetTypeChips, SeverityBar } from './project-visuals';
import { severitySegments } from './project-stats';

const stats: ProjectStats = {
  assets: 6,
  assetsByType: { container: 3, server: 1, lxc: 2 },
  openFindings: { CRITICAL: 2, HIGH: 6, MEDIUM: 0, LOW: 2, UNKNOWN: 0 },
  fixableFindings: { CRITICAL: 1, HIGH: 4 },
  openVulnerabilities: 9,
};

describe('Tarjeta de proyecto', () => {
  it('tramos de la barra de más a menos grave, sin los vacíos, con su proporción', () => {
    expect(severitySegments(stats.openFindings)).toEqual([
      { severity: 'CRITICAL', count: 2, share: 0.2 },
      { severity: 'HIGH', count: 6, share: 0.6 },
      { severity: 'LOW', count: 2, share: 0.2 },
    ]);
    expect(severitySegments({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 })).toEqual([]);
  });

  it('la barra lleva leyenda con nombre y número (nunca solo color) y un resumen accesible', async () => {
    const fixture = TestBed.createComponent(SeverityBar);
    fixture.componentRef.setInput('stats', stats);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect([...el.querySelectorAll('[data-severity]')].map((s) => s.getAttribute('data-severity'))).toEqual([
      'CRITICAL',
      'HIGH',
      'LOW',
    ]);
    expect(
      [...el.querySelectorAll('.legend li')].map((li) => li.textContent?.replace(/\s+/g, ' ').trim()),
    ).toEqual(['Críticas 2', 'Altas 6', 'Bajas 2']);
    expect(el.querySelector('.bar[role="img"]')?.getAttribute('aria-label')).toBe(
      'Vulnerabilidades abiertas: 2 críticas, 6 altas, 2 bajas',
    );
  });

  it('chips de tipos en el orden de siempre, con su icono y cuántos', async () => {
    const fixture = TestBed.createComponent(AssetTypeChips);
    fixture.componentRef.setInput('stats', stats);
    await fixture.whenStable();
    const chips = [...(fixture.nativeElement as HTMLElement).querySelectorAll('li')];
    expect(chips.map((c) => c.textContent?.replace(/\s+/g, ' ').trim())).toEqual([
      '1 Servidor',
      '2 CT (LXC)',
      '3 Contenedor',
    ]);
    expect(chips[0].querySelector('i')?.className).toContain('bi-hdd-rack');
  });
});
