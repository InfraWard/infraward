import { describe, expect, it } from 'vitest';
import {
  DASHBOARD_COLUMNS,
  DASHBOARD_MAX_WIDGETS,
  DASHBOARD_WIDGETS,
  DEFAULT_DASHBOARD,
  findOverlap,
  newWidget,
  packWidgets,
  projectDashboardTemplate,
  validateDashboardLayout,
  widgetOptions,
  widgetRequestParams,
  WIDGET_TYPES,
  type DashboardWidget,
} from './dashboards.js';

const PROJECT = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const OTHER = '16fd2706-8baf-433b-82eb-8c7fada847da';

const w = (over: Partial<DashboardWidget> = {}): DashboardWidget => ({
  id: 'a',
  type: 'top-vulnerabilities',
  x: 0,
  y: 0,
  w: 4,
  h: 5,
  filters: {},
  options: {},
  ...over,
});

const layout = (...widgets: unknown[]) => ({ schema: 1, widgets });

describe('catálogo', () => {
  it('cada tipo cabe en la rejilla y su tamaño por defecto respeta el mínimo', () => {
    for (const type of WIDGET_TYPES) {
      const def = DASHBOARD_WIDGETS[type];
      expect(def.size.w).toBeGreaterThanOrEqual(def.min.w);
      expect(def.size.h).toBeGreaterThanOrEqual(def.min.h);
      expect(def.size.w).toBeLessThanOrEqual(DASHBOARD_COLUMNS);
      // Los valores por defecto de las opciones son válidos.
      expect(widgetOptions(type, {})).toEqual(
        widgetOptions(type, widgetOptions(type, {})),
      );
    }
  });

  it('los paneles por defecto son válidos y no se solapan', () => {
    expect(validateDashboardLayout(DEFAULT_DASHBOARD)).toEqual({
      ok: true,
      layout: DEFAULT_DASHBOARD,
    });
    const template = projectDashboardTemplate(PROJECT);
    const v = validateDashboardLayout(template, PROJECT);
    expect(v.ok).toBe(true);
    if (v.ok)
      for (const widget of v.layout.widgets)
        expect(widget.filters.projectId).toBe(PROJECT);
  });
});

describe('validateDashboardLayout', () => {
  it('rechaza lo que no es un diseño', () => {
    expect(validateDashboardLayout(null).ok).toBe(false);
    expect(validateDashboardLayout({ schema: 2, widgets: [] }).ok).toBe(false);
    expect(validateDashboardLayout({ schema: 1 }).ok).toBe(false);
  });

  it.each([
    ['tipo desconocido', w({ type: 'nope' as never })],
    ['id no válido', w({ id: 'con espacios' })],
    ['ancho menor que el mínimo', w({ w: 1 })],
    ['se sale de la rejilla', w({ x: 10, w: 4 })],
    ['alto excesivo', w({ h: 40 })],
    ['título largo', w({ title: 'x'.repeat(81) })],
    ['opción no permitida', w({ options: { limit: '7' } })],
    ['proyecto no válido', w({ filters: { projectId: 'nope' } })],
    ['tipo de asset no válido', w({ filters: { types: ['ufo' as never] } })],
    [
      'demasiados tags',
      w({ filters: { tags: Array.from({ length: 11 }, (_, i) => `t${i}`) } }),
    ],
  ])('rechaza: %s', (_, widget) => {
    const v = validateDashboardLayout(layout(widget));
    expect(v.ok).toBe(false);
  });

  it('rechaza ids repetidos, solapes y demasiados widgets', () => {
    expect(validateDashboardLayout(layout(w(), w({ x: 4 }))).ok).toBe(false);
    const overlap = validateDashboardLayout(layout(w(), w({ id: 'b', x: 2 })));
    expect(overlap).toEqual({
      ok: false,
      error: 'Los widgets a y b se solapan',
    });
    const many = Array.from({ length: DASHBOARD_MAX_WIDGETS + 1 }, (_, i) =>
      w({ id: `w${i}`, x: 0, y: i * 5 }),
    );
    expect(validateDashboardLayout(layout(...many)).ok).toBe(false);
  });

  it('normaliza: opciones por defecto, sin claves desconocidas, filtros que el tipo no admite fuera y orden de lectura', () => {
    const v = validateDashboardLayout(
      layout(
        {
          ...w({ id: 'b', x: 4, type: 'running-jobs', w: 4, h: 2 }),
          extra: 1,
          filters: { tags: ['prod'] },
        },
        w({
          title: '  Mío  ',
          filters: {
            tags: [' prod ', 'prod'],
            projectId: PROJECT.toUpperCase(),
          },
        }),
      ),
    );
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    const [a, b] = v.layout.widgets;
    expect(a).toEqual({
      id: 'a',
      type: 'top-vulnerabilities',
      x: 0,
      y: 0,
      w: 4,
      h: 5,
      title: 'Mío',
      filters: { tags: ['prod'], projectId: PROJECT },
      options: { limit: '5', minPriority: 'medium' },
    });
    expect(b).not.toHaveProperty('extra');
    // `running-jobs` no filtra por tags.
    expect(b!.filters).toEqual({});
  });

  it('en el panel de un proyecto fija todos los widgets a ese proyecto', () => {
    const v = validateDashboardLayout(
      layout(w({ filters: { projectId: OTHER } })),
      PROJECT,
    );
    expect(v.ok && v.layout.widgets[0]!.filters.projectId).toBe(PROJECT);
  });

  it('acepta el sitio (sin efecto) y los valores de varias opciones en el orden del catálogo', () => {
    const v = validateDashboardLayout(
      layout(
        w({
          type: 'attention',
          filters: { site: 'madrid' },
          options: { kinds: ['failedJobs', 'duplicates'] },
        }),
      ),
    );
    expect(v.ok && v.layout.widgets[0]).toMatchObject({
      filters: { site: 'madrid' },
      options: { kinds: ['duplicates', 'failedJobs'] },
    });
    expect(
      validateDashboardLayout(
        layout(w({ type: 'attention', options: { kinds: [] } })),
      ).ok,
    ).toBe(false);
  });
});

describe('colocación', () => {
  it('packWidgets coloca en orden sin solapes ni huecos a la izquierda', () => {
    const packed = packWidgets([
      w({ id: 'a', w: 8, h: 2 }),
      w({ id: 'b', w: 4, h: 4 }),
      w({ id: 'c', w: 6, h: 2 }),
      w({ id: 'd', w: 12, h: 1 }),
    ]);
    expect(packed.map(({ id, x, y }) => [id, x, y])).toEqual([
      ['a', 0, 0],
      ['b', 8, 0],
      ['c', 0, 4],
      ['d', 0, 6],
    ]);
    expect(findOverlap(packed)).toBeNull();
  });

  it('newWidget va debajo de todo con el tamaño y las opciones por defecto', () => {
    const n = newWidget('trend', DEFAULT_DASHBOARD.widgets, 'x1');
    expect(n).toMatchObject({
      x: 0,
      y: 11,
      w: 6,
      h: 4,
      options: { metric: 'open-findings', range: '90d' },
    });
    expect(findOverlap([...DEFAULT_DASHBOARD.widgets, n])).toBeNull();
  });
});

describe('widgetRequestParams', () => {
  it('manda solo los filtros que admite el tipo, las opciones y el proyecto que lo sustituye', () => {
    const widget = w({
      type: 'attention',
      filters: {
        projectId: OTHER,
        tags: ['a', 'b'],
        types: ['server'],
        site: 'x',
      },
      options: { kinds: ['duplicates'] },
    });
    expect(widgetRequestParams(widget, PROJECT)).toEqual({
      projectId: PROJECT,
      tag: ['a', 'b'],
      type: ['server'],
      kinds: ['duplicates'],
    });
    expect(
      widgetRequestParams(
        w({ type: 'running-jobs', filters: { tags: ['a'] } }),
      ),
    ).toEqual({});
    // El número vacío no se manda.
    expect(widgetRequestParams(w({ type: 'expirations' }))).toEqual({
      kinds: ['domain', 'certificate'],
      limit: '10',
    });
  });
});
