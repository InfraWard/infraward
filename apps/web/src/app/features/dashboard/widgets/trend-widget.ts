import { DatePipe } from '@angular/common';
import { Component, input } from '@angular/core';
import type { TrendData } from '@infraward/shared-types';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { TrendChart } from './trend-chart';

const APPROXIMATE =
  'Reconstruido con las fechas de apertura y corrección de cada hallazgo (sin ruido): un hallazgo ' +
  'que se reabrió pierde sus ciclos anteriores y los de assets purgados ya no están.';

@Component({
  selector: 'app-trend-widget',
  imports: [DatePipe, TooltipModule, TrendChart],
  template: `
    @let d = data();
    <p class="dw-meta">
      @if (d.since) {
        <span data-trend-since
          >Datos desde el {{ d.since | date: 'mediumDate' }}</span
        >
      }
      @if (d.approximate) {
        <span
          class="dw-badge"
          [pTooltip]="approximate"
          tooltipPosition="top"
          tabindex="0"
          data-trend-approximate
        >
          <i class="bi bi-info-circle" aria-hidden="true"></i> aproximado
        </span>
      }
      @if (d.ignoredFilters) {
        <span
          class="dw-badge warn"
          pTooltip="Las muestras diarias solo se guardan por proyecto: los tags y tipos no se aplican"
          tooltipPosition="top"
          tabindex="0"
        >
          <i class="bi bi-funnel" aria-hidden="true"></i> solo por proyecto
        </span>
      }
    </p>
    @if (d.points.length) {
      <app-trend-chart [data]="d" />
      @if (d.points.length === 1) {
        <p class="dw-muted">
          Una sola muestra por ahora: el gráfico crecerá cada día.
        </p>
      }
    } @else {
      <p class="dw-muted">Aún no hay datos para este gráfico.</p>
    }
  `,
  styles: `
    :host {
      display: flex;
      flex-direction: column;
      min-height: 0;
      flex: 1;
    }
  `,
})
export class TrendWidget {
  readonly data = input.required<TrendData>();
  protected readonly approximate = APPROXIMATE;
}
