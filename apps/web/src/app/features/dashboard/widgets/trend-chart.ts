import { DatePipe, DecimalPipe } from '@angular/common';
import {
  Component,
  computed,
  DestroyRef,
  ElementRef,
  inject,
  input,
  signal,
} from '@angular/core';
import {
  PRIORITY_BAND_LABELS,
  type AssetStatus,
  type PriorityBand,
  type TrendData,
} from '@infraward/shared-types';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { ASSET_STATUS_LABELS } from '../../../shared/labels';

const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: 'Críticas',
  HIGH: 'Altas',
  MEDIUM: 'Medias',
  LOW: 'Bajas',
  UNKNOWN: 'Sin clasificar',
};

const PAD = { top: 8, right: 8, bottom: 20, left: 40 };

/** Etiqueta de una serie en español. */
export function seriesLabel(key: string, fallback: string): string {
  return (
    SEVERITY_LABELS[key] ??
    PRIORITY_BAND_LABELS[key as PriorityBand] ??
    ASSET_STATUS_LABELS[key as AssetStatus] ??
    fallback
  );
}

/** 0 y un máximo «redondo» con dos marcas intermedias. */
export function niceTicks(max: number): number[] {
  if (max <= 0) return [0, 1];
  const raw = max / 3;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * pow).find((s) => s >= raw)!;
  const top = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let v = 0; v <= top + step / 2; v += step) ticks.push(Math.round(v));
  return ticks;
}

/**
 * Gráfico de evolución (DESIGN §15): áreas apiladas para las partes de un total (hallazgos por
 * severidad, CVE por banda; la severidad es un orden, así que un solo tono rojo) y líneas para el
 * resto. Un solo eje; leyenda con el último valor (nunca solo el color); al pasar por encima, una
 * línea vertical y el valor de cada serie; y una tabla para los lectores de pantalla.
 */
@Component({
  selector: 'app-trend-chart',
  imports: [DatePipe, DecimalPipe, TooltipModule],
  template: `
    @let g = geometry();
    <div
      class="plot"
      (pointermove)="hover($event)"
      (pointerleave)="active.set(null)"
    >
      <svg
        [attr.viewBox]="'0 0 ' + size().w + ' ' + size().h"
        [attr.width]="size().w"
        [attr.height]="size().h"
        role="img"
        [attr.aria-label]="summary()"
      >
        @for (t of g.ticks; track t) {
          <line
            class="grid"
            [attr.x1]="pad.left"
            [attr.x2]="size().w - pad.right"
            [attr.y1]="g.y(t)"
            [attr.y2]="g.y(t)"
          />
          <text
            class="axis"
            [attr.x]="pad.left - 6"
            [attr.y]="g.y(t) + 4"
            text-anchor="end"
          >
            {{ t | number }}
          </text>
        }
        @for (s of g.shapes; track s.key) {
          @if (stacked()) {
            <path class="area s-{{ s.key }}" [attr.d]="s.area" />
          } @else {
            <path class="line s-{{ s.key }}" [attr.d]="s.line" />
          }
          @if (data().points.length === 1) {
            <circle
              class="dot s-{{ s.key }}"
              [attr.cx]="g.x(0)"
              [attr.cy]="s.lastY"
              r="4"
            />
          }
        }
        @for (l of g.xLabels; track l.i) {
          <text
            class="axis"
            [attr.x]="g.x(l.i)"
            [attr.y]="size().h - 4"
            [attr.text-anchor]="l.anchor"
          >
            {{ l.day | date: 'd MMM' }}
          </text>
        }
        @if (active(); as i) {
          <line
            class="cursor"
            [attr.x1]="g.x(i - 1)"
            [attr.x2]="g.x(i - 1)"
            [attr.y1]="pad.top"
            [attr.y2]="size().h - pad.bottom"
          />
        }
      </svg>
      @if (active(); as i) {
        @let p = data().points[i - 1];
        <div
          class="tip"
          [style.left.px]="g.x(i - 1)"
          [class.flip]="g.x(i - 1) > size().w / 2"
        >
          <strong>{{
            p.day
              | date
                : (data().bucket === 'week'
                    ? "'Semana hasta el' d MMM"
                    : 'EEE d MMM')
          }}</strong>
          @for (s of series(); track s.key) {
            <span
              ><i class="sw s-{{ s.key }}" aria-hidden="true"></i>{{ s.label }}
              <b>{{ p.values[s.key] ?? 0 | number }}</b></span
            >
          }
        </div>
      }
    </div>
    <ul class="legend">
      @for (s of series(); track s.key) {
        <li>
          <i class="sw s-{{ s.key }}" aria-hidden="true"></i>{{ s.label }}
          <b>{{ last()?.values?.[s.key] ?? 0 | number }}</b>
        </li>
      }
    </ul>
    <div class="sr-only">
      <table>
        <caption>
          {{
            summary()
          }}
        </caption>
        <tr>
          <th scope="col">Día</th>
          @for (s of series(); track s.key) {
            <th scope="col">{{ s.label }}</th>
          }
        </tr>
        @for (p of data().points; track p.day) {
          <tr>
            <th scope="row">{{ p.day }}</th>
            @for (s of series(); track s.key) {
              <td>{{ p.values[s.key] ?? 0 }}</td>
            }
          </tr>
        }
      </table>
    </div>
  `,
  styles: `
    :host {
      position: relative;
      display: flex;
      flex-direction: column;
      min-height: 0;
      flex: 1;
      --s-CRITICAL: light-dark(var(--p-red-800), var(--p-red-400));
      --s-HIGH: var(--p-red-600);
      --s-MEDIUM: light-dark(var(--p-red-400), var(--p-red-800));
      --s-LOW: light-dark(var(--p-red-200), var(--p-red-950));
      --s-UNKNOWN: var(--p-content-border-color);
      --s-urgent: var(--s-CRITICAL);
      --s-high: var(--s-HIGH);
      --s-medium: var(--s-MEDIUM);
      --s-opened: light-dark(var(--p-red-600), var(--p-red-500));
      --s-fixed: var(--p-teal-600);
      --s-active: var(--p-teal-600);
      --s-pending_enrollment: var(--p-violet-600);
      --s-missing: var(--p-amber-600);
    }
    .plot {
      position: relative;
      flex: 1;
      min-height: 6rem;
    }
    svg {
      position: absolute;
      inset: 0;
      overflow: visible;
    }
    .grid {
      stroke: var(--p-content-border-color);
      stroke-width: 1;
    }
    .axis {
      fill: var(--p-text-muted-color);
      font-size: 11px;
    }
    .area {
      stroke: var(--p-content-background);
      stroke-width: 1.5;
    }
    .line {
      fill: none;
      stroke-width: 2;
      stroke-linejoin: round;
    }
    .dot {
      stroke: var(--p-content-background);
      stroke-width: 2;
    }
    .cursor {
      stroke: var(--p-text-muted-color);
      stroke-dasharray: 3 3;
    }
    @each $k in CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, urgent, high, medium,
      opened, fixed, active, pending_enrollment, missing
    {
      .area.s-#{$k},
      .dot.s-#{$k},
      .sw.s-#{$k} {
        fill: var(--s-#{$k});
        background: var(--s-#{$k});
      }
      .line.s-#{$k} {
        stroke: var(--s-#{$k});
      }
    }
    .tip {
      position: absolute;
      top: 0;
      transform: translateX(8px);
      z-index: 2;
      pointer-events: none;
      display: grid;
      gap: 0.1rem;
      padding: 0.4rem 0.55rem;
      font-size: 0.78rem;
      white-space: nowrap;
      background: var(--p-content-background);
      border: 1px solid var(--p-content-border-color);
      border-radius: 6px;
      box-shadow: 0 2px 8px rgb(0 0 0 / 0.12);
    }
    .tip.flip {
      transform: translateX(calc(-100% - 8px));
    }
    .tip span,
    .legend li {
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
    }
    .sw {
      display: inline-block;
      width: 0.6rem;
      height: 0.6rem;
      border-radius: 2px;
    }
    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 0.1rem 0.75rem;
      margin: 0.35rem 0 0;
      padding: 0;
      list-style: none;
      font-size: 0.78rem;
      color: var(--p-text-muted-color);
    }
    b {
      color: var(--p-text-color);
      font-weight: 600;
    }
    .sr-only {
      position: absolute;
      top: 0;
      left: 0;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
    }
  `,
})
export class TrendChart {
  readonly data = input.required<TrendData>();
  protected readonly pad = PAD;
  protected readonly size = signal({ w: 300, h: 120 });
  /** Índice + 1 del punto bajo el cursor (0 sería falso en `@if`). */
  protected readonly active = signal<number | null>(null);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);

  constructor() {
    const observer = new ResizeObserver(([entry]) => {
      const plot = this.host.nativeElement.querySelector('.plot');
      const box = plot?.getBoundingClientRect() ?? entry!.contentRect;
      if (box.width > 0 && box.height > 0)
        this.size.set({ w: Math.round(box.width), h: Math.round(box.height) });
    });
    observer.observe(this.host.nativeElement);
    inject(DestroyRef).onDestroy(() => observer.disconnect());
  }

  protected readonly stacked = computed(
    () =>
      this.data().metric === 'open-findings' ||
      this.data().metric === 'cves-by-band',
  );
  protected readonly series = computed(() =>
    this.data().series.map((s) => ({
      key: s.key,
      label: seriesLabel(s.key, s.label),
    })),
  );
  protected readonly last = computed(() => this.data().points.at(-1));

  protected readonly geometry = computed(() => {
    const { w, h } = this.size();
    const points = this.data().points;
    const keys = this.data().series.map((s) => s.key);
    const stacked = this.stacked();
    // Acumulado por punto (de abajo arriba, en el orden de las series: lo más grave abajo).
    const tops = points.map((p) => {
      let acc = 0;
      return keys.map((k) => {
        const v = p.values[k] ?? 0;
        acc = stacked ? acc + v : v;
        return acc;
      });
    });
    const max = Math.max(0, ...tops.flat());
    const ticks = niceTicks(max);
    const top = ticks.at(-1)!;
    const innerW = Math.max(1, w - PAD.left - PAD.right);
    const innerH = Math.max(1, h - PAD.top - PAD.bottom);
    const n = points.length;
    const x = (i: number) =>
      PAD.left + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
    const y = (v: number) => PAD.top + innerH - (v / top) * innerH;
    const shapes = keys.map((key, k) => {
      const upper = tops.map(
        (t, i) => `${x(i).toFixed(1)},${y(t[k]!).toFixed(1)}`,
      );
      const lower = tops
        .map(
          (t, i) =>
            `${x(i).toFixed(1)},${y(k === 0 ? 0 : t[k - 1]!).toFixed(1)}`,
        )
        .reverse();
      return {
        key,
        line: n ? `M${upper.join('L')}` : '',
        area: n ? `M${upper.join('L')}L${lower.join('L')}Z` : '',
        lastY: n ? y(tops[n - 1]![k]!) : 0,
      };
    });
    // Para pintar las áreas, la de arriba primero no tapa a las de abajo: se dibuja de arriba abajo.
    if (stacked) shapes.reverse();
    const xLabels =
      n === 0
        ? []
        : [
            { i: 0, day: points[0]!.day, anchor: n === 1 ? 'middle' : 'start' },
            ...(n > 2
              ? [
                  {
                    i: Math.floor((n - 1) / 2),
                    day: points[Math.floor((n - 1) / 2)]!.day,
                    anchor: 'middle',
                  },
                ]
              : []),
            ...(n > 1
              ? [{ i: n - 1, day: points[n - 1]!.day, anchor: 'end' }]
              : []),
          ];
    return { ticks, x, y, shapes, xLabels };
  });

  protected readonly summary = computed(() => {
    const last = this.last();
    if (!last) return 'Sin datos';
    return (
      `${this.data().points.length} puntos hasta el ${last.day}. Último: ` +
      this.series()
        .map((s) => `${s.label} ${last.values[s.key] ?? 0}`)
        .join(', ')
    );
  });

  protected hover(event: PointerEvent): void {
    const n = this.data().points.length;
    if (!n) return;
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const innerW = rect.width - PAD.left - PAD.right;
    const rel = (event.clientX - rect.left - PAD.left) / Math.max(1, innerW);
    const i = n === 1 ? 0 : Math.round(Math.min(1, Math.max(0, rel)) * (n - 1));
    this.active.set(i + 1);
  }
}
