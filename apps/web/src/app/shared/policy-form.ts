import { Component, computed, input, model } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { InventoryPolicyFields, ScanExclusions } from '@infraward/shared-types';
import { SelectModule } from '@openng/optimus-ui/select';
import { formatInterval } from './maintenance-labels';
import { ScanExclusionsForm } from './scan-exclusions-form';

interface Option<T> {
  label: string;
  value: T;
}

/** Intervalos que se ofrecen (minutos; 0 = nunca). */
export const INTERVAL_PRESETS = [5, 15, 30, 60, 120, 360, 720, 1440, 10080];

/** Marca de «heredar» en los desplegables (null en el valor). */
const INHERIT = 'inherit';

/**
 * Los tres campos de la política de inventario (DESIGN §10) como desplegables y, debajo, las
 * exclusiones del escaneo (QoL-6b). Con `allowInherit`, cada campo puede «heredar» (null en la
 * regla); la global los fija siempre.
 */
@Component({
  selector: 'app-policy-form',
  imports: [FormsModule, SelectModule, ScanExclusionsForm],
  template: `
    <div class="policy-form">
      <label [for]="id() + '-interval'">Reconciliación</label>
      <p-select
        [inputId]="id() + '-interval'"
        [options]="intervalOptions()"
        optionLabel="label"
        optionValue="value"
        [ngModelOptions]="{ standalone: true }"
        [ngModel]="toOption(value().reconcileIntervalMinutes)"
        (ngModelChange)="set('reconcileIntervalMinutes', $event)"
        appendTo="body"
        data-field="reconcileIntervalMinutes"
      />
      <label [for]="id() + '-scan'">Escaneo de vulnerabilidades</label>
      <p-select
        [inputId]="id() + '-scan'"
        [options]="scanOptions()"
        optionLabel="label"
        optionValue="value"
        [ngModelOptions]="{ standalone: true }"
        [ngModel]="toOption(value().scanEnabled)"
        (ngModelChange)="set('scanEnabled', $event)"
        appendTo="body"
        data-field="scanEnabled"
      />
      <label [for]="id() + '-periodic'">Escaneo automático</label>
      <p-select
        [inputId]="id() + '-periodic'"
        [options]="periodicOptions()"
        optionLabel="label"
        optionValue="value"
        [ngModelOptions]="{ standalone: true }"
        [ngModel]="toOption(value().scanPeriodic)"
        (ngModelChange)="set('scanPeriodic', $event)"
        appendTo="body"
        data-field="scanPeriodic"
      />
    </div>
    @if (showExclusions()) {
      <app-scan-exclusions-form
        class="exclusions"
        [id]="id() + '-exclusions'"
        [value]="value().scanExclusions"
        (valueChange)="setExclusions($event)"
      />
    }
  `,
  styles: `
    .policy-form {
      display: grid;
      grid-template-columns: minmax(10rem, max-content) minmax(0, 16rem);
      gap: 0.6rem 1rem;
      align-items: center;
    }
    label {
      font-weight: 600;
    }
    .exclusions {
      display: block;
      margin-top: 1rem;
    }
    :host ::ng-deep .p-select {
      width: 100%;
    }
    @media (max-width: 599.98px) {
      .policy-form {
        grid-template-columns: minmax(0, 1fr);
        gap: 0.3rem;
      }
      label:not(:first-child) {
        margin-top: 0.5rem;
      }
    }
  `,
})
export class PolicyForm {
  readonly value = model.required<InventoryPolicyFields>();
  readonly allowInherit = input(true);
  /** Prefijo de los ids de los controles (para las etiquetas). */
  readonly id = input('policy');
  /** Enseña las exclusiones del escaneo (todas las reglas las admiten). */
  readonly showExclusions = input(true);

  private readonly inherit = computed<Option<string>[]>(() =>
    this.allowInherit() ? [{ label: 'Heredar', value: INHERIT }] : [],
  );

  protected readonly intervalOptions = computed<Option<string | number>[]>(() => {
    const current = this.value().reconcileIntervalMinutes;
    const presets = [...INTERVAL_PRESETS];
    // Un valor fijado por la API que no está en la lista también se ofrece.
    if (typeof current === 'number' && current > 0 && !presets.includes(current))
      presets.push(current);
    presets.sort((a, b) => a - b);
    return [
      ...this.inherit(),
      { label: 'Nunca', value: 0 },
      ...presets.map((m) => ({ label: formatInterval(m), value: m })),
    ];
  });
  protected readonly scanOptions = computed<Option<string | boolean>[]>(() => [
    ...this.inherit(),
    { label: 'Activado', value: true },
    { label: 'Desactivado', value: false },
  ]);
  protected readonly periodicOptions = computed<Option<string | boolean>[]>(() => [
    ...this.inherit(),
    { label: 'Sí (tras recoger y descubrir)', value: true },
    { label: 'Solo bajo demanda', value: false },
  ]);

  protected toOption(value: number | boolean | null | undefined): unknown {
    return value ?? INHERIT;
  }

  protected setExclusions(exclusions: ScanExclusions | null | undefined): void {
    this.value.update((v) => ({ ...v, scanExclusions: exclusions ?? null }));
  }

  protected set(field: keyof InventoryPolicyFields, option: unknown): void {
    this.value.update((v) => ({
      ...v,
      [field]: option === INHERIT ? null : option,
    }));
  }
}
