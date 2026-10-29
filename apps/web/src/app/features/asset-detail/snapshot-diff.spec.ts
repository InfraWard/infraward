import { TestBed } from '@angular/core/testing';
import type { SnapshotDiff } from '@infraward/shared-types';
import { changeLabel, changeValue, SnapshotDiffView, summaryText } from './snapshot-diff';

const DIFF: SnapshotDiff = {
  changes: [
    { path: 'packages[curl:amd64]', kind: 'removed', before: { name: 'curl' } },
    { path: 'packages[openssl:amd64].version', kind: 'changed', before: '3.0.11', after: '3.0.12' },
    { path: 'proxmox.config.memory', kind: 'changed', before: 512, after: 1024 },
  ],
  summary: [
    { section: 'packages', added: 0, removed: 1, changed: 1 },
    { section: 'proxmox', added: 0, removed: 0, changed: 1 },
  ],
  truncated: false,
};

describe('SnapshotDiffView', () => {
  it('agrupa por sección con su resumen y cada cambio con antes → después', async () => {
    const fixture = TestBed.createComponent(SnapshotDiffView);
    fixture.componentRef.setInput('diff', DIFF);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const sections = [...el.querySelectorAll('[data-diff-section]')];
    expect(sections.map((s) => s.getAttribute('data-diff-section'))).toEqual(['packages', 'proxmox']);
    expect(sections[0].querySelector('h4')?.textContent).toContain('Paquetes');
    expect(sections[0].querySelector('h4')?.textContent).toContain('−1 ~1');
    const proxmox = sections[1].textContent!;
    expect(proxmox).toContain('config.memory');
    expect(proxmox).toContain('512');
    expect(proxmox).toContain('1024');
  });

  it('sin diff: primer snapshot o anterior al cálculo', async () => {
    const fixture = TestBed.createComponent(SnapshotDiffView);
    fixture.componentRef.setInput('first', true);
    await fixture.whenStable();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Primer snapshot');
  });

  it('utilidades: resumen, etiqueta y valor recortado', () => {
    expect(summaryText({ section: 'x', added: 3, removed: 0, changed: 5 })).toBe('+3 ~5');
    expect(changeLabel('packages[openssl:amd64].version', 'packages')).toBe('openssl:amd64 · version');
    expect(changeLabel('ports[tcp 0.0.0.0:80]', 'ports')).toBe('tcp 0.0.0.0:80');
    expect(changeLabel('proxmox.config.memory', 'proxmox')).toBe('config.memory');
    expect(changeValue({ a: 1 })).toBe('{"a":1}');
    expect(changeValue('x'.repeat(200))).toHaveLength(158);
  });
});
