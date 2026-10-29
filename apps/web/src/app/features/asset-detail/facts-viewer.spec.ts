import { TestBed } from '@angular/core/testing';
import { FACTS_PAGE, FactsViewer } from './facts-viewer';

async function render(value: unknown) {
  const fixture = TestBed.createComponent(FactsViewer);
  fixture.componentRef.setInput('value', value);
  fixture.componentRef.setInput('name', 'facts');
  await fixture.whenStable();
  return fixture;
}

describe('FactsViewer', () => {
  it('abre el primer nivel y deja cerrados los demás', async () => {
    const fixture = await render({ os: { kernel: '6.1' }, machineId: 'abc' });
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('{2 claves}');
    expect(el.textContent).toContain('machineId:');
    expect(el.textContent).toContain('"abc"');
    expect(el.textContent).not.toContain('kernel');
    const osToggle = [...el.querySelectorAll<HTMLButtonElement>('button.toggle')].find((b) =>
      b.textContent?.includes('os'),
    )!;
    expect(osToggle.getAttribute('aria-expanded')).toBe('false');
    osToggle.click();
    await fixture.whenStable();
    expect(el.textContent).toContain('kernel');
  });

  it('pinta el contenido como texto, nunca como HTML', async () => {
    const fixture = await render({ evil: '<img src=x onerror=alert(1)>' });
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('img')).toBeNull();
    expect(el.textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('las listas grandes se muestran por páginas', async () => {
    const fixture = await render(Array.from({ length: FACTS_PAGE + 30 }, (_, i) => i));
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('li .entry').length).toBe(FACTS_PAGE);
    const more = el.querySelector<HTMLButtonElement>('button.more')!;
    expect(more.textContent).toContain('quedan 30');
    more.click();
    await fixture.whenStable();
    expect(el.querySelectorAll('li .entry').length).toBe(FACTS_PAGE + 30);
    expect(el.querySelector('button.more')).toBeNull();
  });
});
