import {
  Component,
  effect,
  inject,
  input,
  model,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  SCAN_EXCLUDABLE_TYPES,
  SCAN_EXCLUDABLE_TYPE_LABELS,
  SCAN_EXCLUSION_ASSETS_MAX,
  SCAN_EXCLUSION_PATTERN,
  SCAN_EXCLUSION_PATTERN_MAX,
  SCAN_EXCLUSION_PATTERNS_MAX,
  normalizeScanExclusions,
  type AssetSummary,
  type ScanExcludableType,
  type ScanExclusions,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { InventoryApi } from '../core/api/inventory-api';
import { AssetPicker } from './asset-picker';

/**
 * Exclusiones del escaneo de una regla (QoL-6b, DESIGN §10): tipos, patrones de nombre y assets
 * concretos. Lo excluido sigue inventariado, pero no se escanea.
 */
@Component({
  selector: 'app-scan-exclusions-form',
  imports: [
    FormsModule,
    ButtonModule,
    InputTextModule,
    MultiSelectModule,
    AssetPicker,
  ],
  template: `
    <fieldset class="exclusions" data-scan-exclusions>
      <legend>Excluir del escaneo</legend>
      <p class="hint">
        Lo excluido sigue en el inventario, pero no se escanea. Se suma a lo que
        excluyan las demás reglas que lo alcanzan (antepasados, etiquetas,
        proyectos y la global). Volúmenes y redes no se escanean nunca.
      </p>
      <label [for]="id() + '-types'">Tipos</label>
      <p-multiselect
        [inputId]="id() + '-types'"
        [options]="typeOptions"
        optionLabel="label"
        optionValue="value"
        [ngModelOptions]="{ standalone: true }"
        [ngModel]="value()?.types ?? []"
        (ngModelChange)="setTypes($event)"
        placeholder="Ninguno"
        [showToggleAll]="false"
        [filter]="false"
        appendTo="body"
        display="chip"
        data-field="excludeTypes"
      />
      <label [for]="id() + '-pattern'">Nombre (patrón)</label>
      <div class="patterns">
        <span class="add">
          <input
            pInputText
            [id]="id() + '-pattern'"
            [ngModelOptions]="{ standalone: true }"
            [ngModel]="draft()"
            (ngModelChange)="draft.set($event); patternError.set(null)"
            (keydown.enter)="$event.preventDefault(); addPattern()"
            placeholder="bitnami/*  ·  *-test"
            [attr.maxlength]="patternMax"
            data-field="excludePattern"
          />
          <p-button
            label="Añadir"
            severity="secondary"
            size="small"
            [outlined]="true"
            (onClick)="addPattern()"
            [disabled]="!draft().trim()"
            data-action="add-pattern"
          />
        </span>
        @if (patternError(); as message) {
          <small class="error" role="alert">{{ message }}</small>
        }
        @if (value()?.namePatterns?.length) {
          <ul class="list" aria-label="Patrones excluidos">
            @for (p of value()!.namePatterns!; track p) {
              <li class="item" data-excluded-pattern>
                <code>{{ p }}</code>
                <button
                  type="button"
                  [attr.aria-label]="'Quitar ' + p"
                  (click)="removePattern(p)"
                >
                  <i class="bi bi-x" aria-hidden="true"></i>
                </button>
              </li>
            }
          </ul>
        }
      </div>
      <label [for]="id() + '-asset'">Assets</label>
      <div class="assets">
        <app-asset-picker
          [inputId]="id() + '-asset'"
          [types]="assetTypes"
          placeholder="Busca un servidor, CT o imagen"
          (picked)="addAsset($event)"
        />
        @if (value()?.assetIds?.length) {
          <ul class="list" aria-label="Assets excluidos">
            @for (assetId of value()!.assetIds!; track assetId) {
              <li class="item" data-excluded-asset>
                <span>{{ names()[assetId] ?? 'Asset' }}</span>
                <button
                  type="button"
                  [attr.aria-label]="
                    'Quitar ' + (names()[assetId] ?? 'el asset')
                  "
                  (click)="removeAsset(assetId)"
                >
                  <i class="bi bi-x" aria-hidden="true"></i>
                </button>
              </li>
            }
          </ul>
        }
      </div>
    </fieldset>
  `,
  styles: `
    .exclusions {
      display: grid;
      grid-template-columns: minmax(10rem, max-content) minmax(0, 22rem);
      gap: 0.6rem 1rem;
      align-items: start;
      border: 1px solid var(--p-content-border-color);
      border-radius: var(--p-content-border-radius, 6px);
      padding: 0.75rem 1rem 1rem;
      margin: 0;
      min-width: 0;
    }
    legend {
      font-weight: 600;
      padding: 0 0.35rem;
    }
    .hint {
      grid-column: 1 / -1;
      margin: 0;
      color: var(--p-text-muted-color);
      font-size: 0.85rem;
    }
    label {
      font-weight: 600;
      padding-top: 0.45rem;
    }
    .patterns,
    .assets {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      min-width: 0;
    }
    .add {
      display: flex;
      gap: 0.4rem;
      min-width: 0;
    }
    .add input {
      flex: 1;
      min-width: 0;
    }
    .list {
      display: flex;
      flex-wrap: wrap;
      gap: 0.3rem;
      list-style: none;
      margin: 0;
      padding: 0;
    }
    .item {
      display: inline-flex;
      align-items: center;
      gap: 0.2rem;
      max-width: 100%;
      padding: 0.05rem 0.15rem 0.05rem 0.55rem;
      border-radius: 999px;
      border: 1px solid var(--p-content-border-color);
      font-size: 0.8rem;
    }
    .item span,
    .item code {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .item button {
      background: none;
      border: 0;
      color: inherit;
      cursor: pointer;
      padding: 0 0.2rem;
    }
    .item button:hover,
    .item button:focus-visible {
      color: var(--p-primary-color);
    }
    .error {
      color: var(--p-app-danger-color);
      font-size: 0.75rem;
    }
    :host ::ng-deep .p-multiselect {
      width: 100%;
    }
    @media (max-width: 599.98px) {
      .exclusions {
        grid-template-columns: minmax(0, 1fr);
        gap: 0.3rem;
        padding: 0.6rem 0.75rem 0.75rem;
      }
      label {
        margin-top: 0.4rem;
      }
    }
  `,
})
export class ScanExclusionsForm {
  private readonly inventory = inject(InventoryApi);
  private readonly picker = viewChild(AssetPicker);
  readonly value = model<ScanExclusions | null | undefined>(null);
  readonly id = input('exclusions');

  protected readonly typeOptions = SCAN_EXCLUDABLE_TYPES.map((t) => ({
    value: t,
    label:
      SCAN_EXCLUDABLE_TYPE_LABELS[t][0]!.toUpperCase() +
      SCAN_EXCLUDABLE_TYPE_LABELS[t].slice(1),
  }));
  protected readonly assetTypes = [...SCAN_EXCLUDABLE_TYPES];
  protected readonly patternMax = SCAN_EXCLUSION_PATTERN_MAX;
  protected readonly draft = signal('');
  protected readonly patternError = signal<string | null>(null);
  /** Nombres de los assets excluidos (los ya guardados se piden una vez). */
  protected readonly names = signal<Record<string, string>>({});

  constructor() {
    effect(() => {
      const known = this.names();
      for (const assetId of this.value()?.assetIds ?? []) {
        if (known[assetId]) continue;
        this.names.update((n) => ({ ...n, [assetId]: '…' }));
        this.inventory.asset(assetId).subscribe({
          next: (a) => this.names.update((n) => ({ ...n, [assetId]: a.name })),
          error: () =>
            this.names.update((n) => ({
              ...n,
              [assetId]: 'Asset que ya no existe',
            })),
        });
      }
    });
  }

  private patch(change: Partial<ScanExclusions>): void {
    this.value.set(
      normalizeScanExclusions({ ...this.value(), ...change }),
    );
  }

  protected setTypes(types: ScanExcludableType[] | null): void {
    this.patch({ types: types ?? [] });
  }

  protected addPattern(): void {
    const pattern = this.draft().trim();
    if (!pattern) return;
    const current = this.value()?.namePatterns ?? [];
    if (!SCAN_EXCLUSION_PATTERN.test(pattern)) {
      this.patternError.set(
        'Solo letras, números, espacios y . _ : @ / - + y los comodines * y ?',
      );
      return;
    }
    if (current.length >= SCAN_EXCLUSION_PATTERNS_MAX) {
      this.patternError.set(
        `Como mucho ${SCAN_EXCLUSION_PATTERNS_MAX} patrones`,
      );
      return;
    }
    this.patch({ namePatterns: [...current, pattern] });
    this.draft.set('');
  }

  protected removePattern(pattern: string): void {
    this.patch({
      namePatterns: (this.value()?.namePatterns ?? []).filter(
        (p) => p !== pattern,
      ),
    });
  }

  protected addAsset(asset: AssetSummary): void {
    const current = this.value()?.assetIds ?? [];
    if (current.length >= SCAN_EXCLUSION_ASSETS_MAX) return;
    this.names.update((n) => ({ ...n, [asset.id]: asset.name }));
    this.patch({ assetIds: [...current, asset.id] });
    this.picker()?.clear();
  }

  protected removeAsset(assetId: string): void {
    this.patch({
      assetIds: (this.value()?.assetIds ?? []).filter((a) => a !== assetId),
    });
  }
}
