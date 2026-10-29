import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { newWidget, type DashboardWidget } from '@infraward/shared-types';
import { WidgetConfig } from './widget-dialogs';

const PROJECT = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

function open(widget: DashboardWidget, locked?: string) {
  TestBed.configureTestingModule({
    imports: [WidgetConfig],
    providers: [provideHttpClient(), provideHttpClientTesting()],
  });
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(WidgetConfig);
  const saved: DashboardWidget[] = [];
  fixture.componentInstance.saved.subscribe((w) => saved.push(w));
  fixture.componentRef.setInput('widget', widget);
  if (locked) fixture.componentRef.setInput('lockedProject', locked);
  fixture.detectChanges();
  // Tags y proyectos se piden al abrir.
  http.expectOne('/api/tags').flush([{ tag: 'prod', color: null, assets: 2 }]);
  http.expectOne('/api/projects').flush([]);
  fixture.detectChanges();
  return {
    fixture,
    saved,
    form: document.querySelector('[data-widget-config]') as HTMLFormElement,
  };
}

describe('WidgetConfig', () => {
  it('en el panel de un proyecto, el proyecto va fijado y no se puede cambiar', () => {
    const { saved, form } = open(newWidget('expirations', [], 'w1'), PROJECT);
    expect(
      (document.getElementById('cfg-project') as HTMLInputElement).disabled,
    ).toBe(true);
    // Las opciones del tipo salen del catálogo.
    expect(form.querySelector('[data-config="horizonDays"]')).not.toBeNull();
    expect(form.querySelector('[data-config="types"]')).toBeNull();
    form.dispatchEvent(new Event('submit'));
    expect(saved[0]).toMatchObject({
      id: 'w1',
      type: 'expirations',
      filters: { projectId: PROJECT },
      options: {
        kinds: ['domain', 'certificate'],
        horizonDays: null,
        limit: '10',
      },
    });
  });

  it('el título vacío vuelve al del catálogo y el sitio queda deshabilitado', () => {
    const widget = { ...newWidget('trend', [], 'w2'), title: 'Viejo' };
    const { fixture, saved, form } = open(widget);
    expect(
      (document.getElementById('cfg-site') as HTMLInputElement).disabled,
    ).toBe(true);
    (
      fixture.componentInstance as unknown as {
        title: { set(v: string): void };
      }
    ).title.set('  ');
    form.dispatchEvent(new Event('submit'));
    expect(saved[0]!.title).toBeUndefined();
    expect(saved[0]!.options).toEqual({
      metric: 'open-findings',
      range: '90d',
    });
  });
});
