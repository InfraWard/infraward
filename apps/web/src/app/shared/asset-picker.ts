import { Component, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { AssetSummary, AssetType } from '@infraward/shared-types';
import { AutoCompleteModule } from '@openng/optimus-ui/autocomplete';
import type { AutoCompleteCompleteEvent } from '@openng/optimus-ui/types/autocomplete';
import { OrganizationApi } from '../core/api/organization-api';
import { ASSET_TYPE_ICONS, ASSET_TYPE_LABELS } from './labels';

/** Buscador de un asset por nombre (solo de los tipos dados y no retirados). */
@Component({
  selector: 'app-asset-picker',
  imports: [FormsModule, AutoCompleteModule],
  template: `
    <p-autocomplete
      [inputId]="inputId()"
      [ngModelOptions]="{ standalone: true }"
      [ngModel]="value()"
      (ngModelChange)="value.set($event)"
      [suggestions]="suggestions()"
      (completeMethod)="complete($event)"
      (onSelect)="pick($any($event.value))"
      optionLabel="name"
      [delay]="200"
      [minLength]="1"
      [placeholder]="placeholder()"
      [fluid]="true"
      appendTo="body"
      data-asset-picker
    >
      <ng-template #item let-a>
        <span class="opt" [attr.data-option]="a.name">
          <i class="bi {{ typeIcons[a.type] }}" aria-hidden="true"></i>
          {{ a.name }} <span class="muted small">{{ typeLabels[a.type] }}</span>
        </span>
      </ng-template>
    </p-autocomplete>
  `,
  styles: `
    .opt { display: inline-flex; gap: 0.4rem; align-items: center; }
    .muted { color: var(--p-text-muted-color); }
    .small { font-size: 0.85em; }
  `,
})
export class AssetPicker {
  private readonly api = inject(OrganizationApi);
  readonly inputId = input.required<string>();
  readonly types = input.required<readonly AssetType[]>();
  readonly placeholder = input('Busca por nombre');
  readonly picked = output<AssetSummary>();

  protected readonly typeIcons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
  protected readonly typeLabels: Readonly<Record<string, string>> = ASSET_TYPE_LABELS;
  protected readonly value = signal<AssetSummary | string | null>(null);
  protected readonly suggestions = signal<AssetSummary[]>([]);

  protected complete(event: AutoCompleteCompleteEvent): void {
    const allowed = new Set<string>(this.types());
    this.api.searchAssets((event.query ?? '').trim(), 50).subscribe({
      next: (page) =>
        this.suggestions.set(
          page.items
            .filter((a) => allowed.has(a.type) && a.status !== 'retired')
            .slice(0, 20),
        ),
    });
  }

  protected pick(asset: AssetSummary): void {
    this.value.set(asset);
    this.picked.emit(asset);
  }

  /** Vacía el campo (tras usar el valor). */
  clear(): void {
    this.value.set(null);
  }
}
