import { TestBed } from '@angular/core/testing';
import type { TrendData } from '@infraward/shared-types';
import { niceTicks, seriesLabel } from './trend-chart';
import { TrendWidget } from './trend-widget';

const data: TrendData = {
  metric: 'open-findings',
  bucket: 'day',
  approximate: true,
  since: '2026-10-09T22:36:29.000Z',
  ignoredFilters: false,
  series: [
    { key: 'CRITICAL', label: 'CRITICAL', severity: 'CRITICAL' },
    { key: 'HIGH', label: 'HIGH', severity: 'HIGH' },
  ],
  points: [
    { day: '2026-10-18', values: { CRITICAL: 3, HIGH: 10 } },
    { day: '2026-10-19', values: { CRITICAL: 4, HIGH: 12 } },
    { day: '2026-10-20', values: { CRITICAL: 2, HIGH: 9 } },
  ],
};

describe('TrendChart', () => {
  it('marcas redondas desde 0 que cubren el máximo', () => {
    expect(niceTicks(0)).toEqual([0, 1]);
    expect(niceTicks(16)).toEqual([0, 10, 20]);
    expect(niceTicks(2730)).toEqual([0, 1000, 2000, 3000]);
    for (const max of [1, 7, 99, 12_345])
      expect(niceTicks(max).at(-1)!).toBeGreaterThanOrEqual(max);
  });

  it('etiquetas en español de severidades, bandas y estados', () => {
    expect(seriesLabel('CRITICAL', 'x')).toBe('Críticas');
    expect(seriesLabel('urgent', 'x')).toBe('Urgente');
    expect(seriesLabel('missing', 'x')).toBe('Desaparecido');
    expect(seriesLabel('opened', 'Nuevos')).toBe('Nuevos');
  });

  it('desde cuándo, la marca de aproximado, la leyenda con el último valor y la tabla', () => {
    const fixture = TestBed.createComponent(TrendWidget);
    fixture.componentRef.setInput('data', data);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-trend-since]')?.textContent).toContain(
      '2026',
    );
    expect(el.querySelector('[data-trend-approximate]')).not.toBeNull();
    const legend = el
      .querySelector('.legend')!
      .textContent!.replace(/\s+/g, ' ');
    expect(legend).toContain('Críticas 2');
    expect(legend).toContain('Altas 9');
    expect(el.querySelectorAll('path.area').length).toBe(2);
    expect(el.querySelectorAll('table tr').length).toBe(4);
  });
});
