import { DecimalPipe } from '@angular/common';
import { Component, computed, input } from '@angular/core';
import type { ProjectStats } from '@infraward/shared-types';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { ASSET_TYPE_ICONS, ASSET_TYPE_LABELS } from '../../shared/labels';
import { assetTypeCounts, severitySegments } from './project-stats';

const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: 'Críticas',
  HIGH: 'Altas',
  MEDIUM: 'Medias',
  LOW: 'Bajas',
  UNKNOWN: 'Sin clasificar',
};

/**
 * Findings abiertos por severidad en una barra apilada. La severidad es un orden: un solo tono
 * (rojo) de más oscuro (crítica) a más claro (baja), sin clasificar en gris; cada tramo lleva su
 * nombre y su número en la leyenda (nunca solo el color) y en el tooltip.
 */
@Component({
  selector: 'app-severity-bar',
  imports: [DecimalPipe, TooltipModule],
  template: `
    @if (!compact()) {
      <p class="caption" title="Un hallazgo es un CVE en un asset y paquete concretos: hay más hallazgos que CVE distintos">
        Hallazgos abiertos por severidad
      </p>
    }
    <div class="bar" role="img" [attr.aria-label]="summary()">
      @for (s of segments(); track s.severity) {
        <span
          class="seg sev-{{ s.severity }}"
          [style.flex-grow]="s.share"
          [pTooltip]="labels[s.severity] + ': ' + (s.count | number)"
          tooltipPosition="top"
          [attr.data-severity]="s.severity"
        ></span>
      }
    </div>
    @if (!compact()) {
      <ul class="legend">
        @for (s of segments(); track s.severity) {
          <li><span class="swatch sev-{{ s.severity }}" aria-hidden="true"></span>{{ labels[s.severity] }} <strong>{{ s.count | number }}</strong></li>
        }
      </ul>
    }
  `,
  styles: `
    :host {
      display: block;
      /* Rampa de un solo tono: lo más grave, lo que más destaca sobre el fondo (oscuro en claro,
         vivo en oscuro); lo leve se acerca al fondo. */
      --sev-CRITICAL: light-dark(var(--p-red-800), var(--p-red-400));
      --sev-HIGH: light-dark(var(--p-red-600), var(--p-red-600));
      --sev-MEDIUM: light-dark(var(--p-red-400), var(--p-red-800));
      --sev-LOW: light-dark(var(--p-red-200), var(--p-red-950));
      --sev-UNKNOWN: var(--p-content-border-color);
    }
    .caption {
      margin: 0 0 0.3rem;
      font-size: 0.75rem;
      color: var(--p-text-muted-color);
    }
    .bar {
      display: flex;
      gap: 2px;
      height: 0.6rem;
      border-radius: 4px;
      overflow: hidden;
      background: var(--p-content-border-color);
    }
    .seg { min-width: 4px; }
    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 0.15rem 0.75rem;
      margin: 0.4rem 0 0;
      padding: 0;
      list-style: none;
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
    }
    .legend li { display: inline-flex; align-items: center; gap: 0.3rem; }
    .legend strong { color: var(--p-text-color); font-weight: 600; }
    .swatch { width: 0.6rem; height: 0.6rem; border-radius: 2px; }
    .sev-CRITICAL { background: var(--sev-CRITICAL); }
    .sev-HIGH { background: var(--sev-HIGH); }
    .sev-MEDIUM { background: var(--sev-MEDIUM); }
    .sev-LOW { background: var(--sev-LOW); }
    .sev-UNKNOWN { background: var(--sev-UNKNOWN); }
  `,
})
export class SeverityBar {
  readonly stats = input.required<ProjectStats>();
  /** Solo la barra (sin título ni leyenda; el detalle, en los tooltips). */
  readonly compact = input(false);
  protected readonly labels = SEVERITY_LABELS;
  protected readonly segments = computed(() =>
    severitySegments(this.stats().openFindings),
  );
  protected readonly summary = computed(
    () =>
      'Vulnerabilidades abiertas: ' +
      this.segments()
        .map((s) => `${s.count} ${SEVERITY_LABELS[s.severity].toLowerCase()}`)
        .join(', '),
  );
}

/** Tipos de asset del proyecto como chips con su icono y cuántos hay. */
@Component({
  selector: 'app-asset-type-chips',
  imports: [TooltipModule],
  template: `
    <ul class="types" aria-label="Assets por tipo">
      @for (t of shown(); track t.type) {
        <li [attr.data-type]="t.type" [class.compact]="compact()"
          [pTooltip]="compact() ? t.count + ' ' + labels[t.type] : undefined" tooltipPosition="top">
          <i class="bi {{ icons[t.type] }}" aria-hidden="true"></i>
          <strong>{{ t.count }}</strong>
          @if (!compact()) {
            {{ labels[t.type] }}
          } @else {
            <span class="sr-only">{{ labels[t.type] }}</span>
          }
        </li>
      }
      @if (hidden(); as h) {
        <li class="compact more" [pTooltip]="h.label" tooltipPosition="top">+{{ h.count }}</li>
      }
    </ul>
  `,
  styles: `
    .types {
      display: flex;
      flex-wrap: wrap;
      gap: 0.3rem;
      margin: 0;
      padding: 0;
      list-style: none;
    }
    li {
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      border: 1px solid var(--p-content-border-color);
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
      white-space: nowrap;
    }
    li strong { color: var(--p-text-color); font-weight: 600; }
    i { color: var(--p-primary-color); }
    :host(.one-line) .types {
      flex-wrap: nowrap;
      overflow: hidden;
    }
    li.compact {
      border: 0;
      padding: 0.15rem 0.45rem;
      background: var(--p-app-background);
    }
    .more { color: var(--p-text-muted-color); }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
    }
  `,
})
export class AssetTypeChips {
  readonly stats = input.required<ProjectStats>();
  /** Solo icono y número (el nombre en el tooltip), y como mucho `max` tipos. */
  readonly compact = input(false);
  readonly max = input(Infinity);
  protected readonly icons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
  protected readonly labels: Readonly<Record<string, string>> = ASSET_TYPE_LABELS;
  protected readonly types = computed(() => assetTypeCounts(this.stats()));
  protected readonly shown = computed(() => this.types().slice(0, this.max()));
  /** Los que no caben: cuántos assets y cuáles, para el tooltip. */
  protected readonly hidden = computed(() => {
    const rest = this.types().slice(this.max());
    if (!rest.length) return null;
    return {
      count: rest.reduce((n, t) => n + t.count, 0),
      label: rest.map((t) => `${t.count} ${ASSET_TYPE_LABELS[t.type]}`).join(' · '),
    };
  });
}

/**
 * Anillo con los hallazgos abiertos por severidad (misma rampa que la barra) y, en el centro, los
 * CRITICAL y HIGH con parche: lo que se puede arreglar ya. El detalle va en el tooltip y en la
 * etiqueta accesible, nunca solo en el color.
 */
@Component({
  selector: 'app-severity-ring',
  imports: [DecimalPipe, TooltipModule],
  template: `
    <div class="ring" [style.background]="gradient()" role="img" [attr.aria-label]="summary()"
      [pTooltip]="summary()" tooltipPosition="top">
      <div class="hole">
        <span class="value" [class.ok]="!fixable()">{{ fixable() | number }}</span>
        <span class="label">con parche</span>
      </div>
    </div>
  `,
  styles: `
    :host {
      display: block;
      --sev-CRITICAL: light-dark(var(--p-red-800), var(--p-red-400));
      --sev-HIGH: light-dark(var(--p-red-600), var(--p-red-600));
      --sev-MEDIUM: light-dark(var(--p-red-400), var(--p-red-800));
      --sev-LOW: light-dark(var(--p-red-200), var(--p-red-950));
      --sev-UNKNOWN: var(--p-content-border-color);
    }
    .ring {
      width: 6.5rem;
      height: 6.5rem;
      border-radius: 50%;
      display: grid;
      place-items: center;
    }
    .hole {
      width: 4.9rem;
      height: 4.9rem;
      border-radius: 50%;
      background: var(--p-content-background);
      display: grid;
      place-content: center;
      text-align: center;
    }
    .value {
      font-size: 1.35rem;
      font-weight: 700;
      line-height: 1.1;
      color: var(--p-app-danger-color);
    }
    .value.ok {
      color: var(--p-app-success-color);
    }
    .label {
      font-size: 0.7rem;
      color: var(--p-text-muted-color);
    }
  `,
})
export class SeverityRing {
  readonly stats = input.required<ProjectStats>();
  protected readonly fixable = computed(
    () => this.stats().fixableFindings.CRITICAL + this.stats().fixableFindings.HIGH,
  );
  /** conic-gradient con un tramo por severidad (sin hallazgos, el anillo en gris). */
  protected readonly gradient = computed(() => {
    const segments = severitySegments(this.stats().openFindings);
    if (!segments.length) return 'var(--p-content-border-color)';
    let at = 0;
    const stops = segments.map((s) => {
      const from = at;
      at += s.share * 100;
      return `var(--sev-${s.severity}) ${from.toFixed(2)}% ${at.toFixed(2)}%`;
    });
    return `conic-gradient(${stops.join(', ')})`;
  });
  protected readonly summary = computed(() => {
    const segments = severitySegments(this.stats().openFindings);
    const open = segments.length
      ? segments.map((s) => `${s.count} ${SEVERITY_LABELS[s.severity].toLowerCase()}`).join(', ')
      : 'ninguno';
    return `Hallazgos abiertos: ${open}. Críticas y altas con parche: ${this.fixable()}`;
  });
}
