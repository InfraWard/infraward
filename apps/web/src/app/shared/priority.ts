import { Component, computed, input } from '@angular/core';
import {
  NOISE_REASON_CODES,
  PRIORITY_BAND_LABELS,
  priorityExplanation,
  priorityReasonText,
  type PriorityBand,
  type PriorityInfo,
  type PriorityReason,
  type PriorityReasonCode,
} from '@infraward/shared-types';
import { TooltipModule } from '@openng/optimus-ui/tooltip';

/** Icono de cada motivo (DESIGN §9). */
export const PRIORITY_REASON_ICONS: Record<PriorityReasonCode, string> = {
  kev: 'bi-fire',
  epss: 'bi-graph-up-arrow',
  port: 'bi-broadcast',
  public: 'bi-globe2',
  service: 'bi-gear',
  container: 'bi-box',
  fix: 'bi-bandaid',
  no_fix: 'bi-hourglass-split',
  cvss: 'bi-speedometer2',
  severity: 'bi-speedometer2',
  unused_image: 'bi-moon',
  no_process_data: 'bi-info-circle',
  kernel_other: 'bi-eye-slash',
  kernel_aux: 'bi-eye-slash',
  kernel_guest: 'bi-eye-slash',
  no_fix_planned: 'bi-eye-slash',
};

/** Motivos que pesan (se pintan en el color de la banda alta). */
const STRONG: ReadonlySet<PriorityReasonCode> = new Set([
  'kev',
  'port',
  'public',
]);

/** Explicación completa (tooltip, accesible). */
export function priorityTitle(p: PriorityInfo): string {
  return `Prioridad ${p.score} (${PRIORITY_BAND_LABELS[p.band].toLowerCase()}): ${priorityExplanation(p.reasons, 20)}`;
}

/**
 * Puntuación de prioridad con su banda: «92 Urgente». El color va con la banda (y el texto la
 * dice, no solo el color). Sin prioridad (aún no calculada), un guion.
 */
@Component({
  selector: 'app-priority-score',
  imports: [TooltipModule],
  template: `
    @if (priority(); as p) {
      <span
        class="score band-{{ p.band }}"
        [class.compact]="compact()"
        [pTooltip]="title()"
        tooltipPosition="top"
        [attr.aria-label]="title()"
        [attr.data-priority]="p.score"
        [attr.data-band]="p.band"
      >
        <strong>{{ p.score }}</strong>
        @if (!compact()) {
          <span class="label">{{ labels[p.band] }}</span>
        }
      </span>
    } @else {
      <span class="none" title="Prioridad aún sin calcular">—</span>
    }
  `,
  styles: `
    :host {
      display: inline-flex;
    }
    .score {
      --band: var(--p-text-muted-color);
      display: inline-flex;
      align-items: baseline;
      gap: 0.3rem;
      padding: 0.1rem 0.45rem;
      border-radius: 999px;
      border: 1px solid color-mix(in srgb, var(--band) 45%, transparent);
      background: color-mix(in srgb, var(--band) 14%, transparent);
      color: var(--p-text-color);
      font-size: 0.8rem;
      line-height: 1.3;
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
    }
    .score strong {
      color: var(--band);
      font-weight: 700;
      min-width: 1.4em;
      text-align: right;
    }
    .label {
      font-size: 0.75rem;
    }
    .band-urgent {
      --band: var(--p-app-danger-color);
    }
    .band-high {
      --band: var(--p-app-warn-color);
    }
    .band-medium {
      --band: var(--p-app-info-color);
    }
    .none {
      color: var(--p-text-muted-color);
    }
  `,
})
export class PriorityScore {
  readonly priority = input<PriorityInfo | null | undefined>(null);
  /** Solo el número (tablas estrechas). */
  readonly compact = input(false);
  protected readonly labels: Record<PriorityBand, string> =
    PRIORITY_BAND_LABELS;
  protected readonly title = computed(() => {
    const p = this.priority();
    return p ? priorityTitle(p) : '';
  });
}

/**
 * El porqué de una prioridad en una línea: «en KEV · expuesto en 443 (nginx) · parche
 * disponible». Por defecto sin la base (CVSS o severidad), que ya se ve en su columna.
 */
@Component({
  selector: 'app-priority-reasons',
  template: `
    @if (shown().length) {
      <span class="reasons" data-reasons>
        @for (r of shown(); track $index) {
          <span
            class="reason"
            [class.strong]="strong.has(r.code)"
            [class.noise]="noiseCodes.has(r.code)"
            [attr.data-reason]="r.code"
          >
            <i class="bi {{ icons[r.code] }}" aria-hidden="true"></i
            >{{ text(r) }}
          </span>
        }
        @if (rest() > 0) {
          <span class="more">+{{ rest() }}</span>
        }
      </span>
    }
  `,
  styles: `
    :host {
      display: block;
      min-width: 0;
    }
    .reasons {
      display: flex;
      flex-wrap: wrap;
      gap: 0.15rem 0.7rem;
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
    }
    .reason {
      display: inline-flex;
      align-items: baseline;
      gap: 0.3rem;
      overflow-wrap: anywhere;
    }
    .reason.strong {
      color: var(--p-app-danger-color);
      font-weight: 600;
    }
    .reason.noise {
      font-style: italic;
    }
    .more {
      opacity: 0.8;
    }
  `,
})
export class PriorityReasons {
  readonly reasons = input<readonly PriorityReason[] | null | undefined>([]);
  readonly max = input(4);
  /** Incluir la base (CVSS o severidad sin CVSS). */
  readonly withBase = input(false);
  protected readonly icons = PRIORITY_REASON_ICONS;
  protected readonly strong = STRONG;
  protected readonly noiseCodes: ReadonlySet<PriorityReasonCode> = new Set(
    NOISE_REASON_CODES,
  );
  protected readonly text = priorityReasonText;
  private readonly visible = computed(() =>
    (this.reasons() ?? []).filter(
      (r) => this.withBase() || (r.code !== 'cvss' && r.code !== 'severity'),
    ),
  );
  protected readonly shown = computed(() =>
    this.visible().slice(0, this.max()),
  );
  protected readonly rest = computed(
    () => this.visible().length - this.shown().length,
  );
}
