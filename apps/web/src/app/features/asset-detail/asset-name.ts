import { Component, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { Asset } from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { OrganizationApi } from '../../core/api/organization-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { ASSET_TYPE_ICONS } from '../../shared/labels';

/**
 * Título de la ficha con el nombre visible, «descubierto como …» si está renombrado y, con
 * `assets.write`, «Renombrar» (en el sitio) y «Volver al nombre descubierto».
 */
@Component({
  selector: 'app-asset-name',
  imports: [FormsModule, ButtonModule, InputTextModule, TooltipModule],
  template: `
    @let a = asset();
    @if (editing()) {
      <form class="edit" (ngSubmit)="save()" data-rename-form>
        <i class="bi {{ typeIcons[a.type] }}" aria-hidden="true"></i>
        <input
          pInputText
          id="asset-display-name"
          name="displayName"
          maxlength="255"
          aria-label="Nombre visible"
          [ngModel]="draft()"
          (ngModelChange)="draft.set($event)"
          (keydown.escape)="editing.set(false)"
        />
        <p-button type="submit" icon="bi bi-check-lg" label="Guardar" [loading]="saving()" />
        <p-button
          icon="bi bi-x-lg"
          label="Cancelar"
          severity="secondary"
          [text]="true"
          (onClick)="editing.set(false)"
        />
      </form>
      <small class="muted">Vacío o igual al descubierto ({{ a.discoveredName }}): vuelve al descubierto.</small>
    } @else {
      <h1>
        <i class="bi {{ typeIcons[a.type] }}" aria-hidden="true"></i>
        <span data-name>{{ a.name }}</span>
        @if (auth.can('assets.write')) {
          <p-button
            icon="bi bi-pencil"
            severity="secondary"
            [text]="true"
            [rounded]="true"
            size="small"
            ariaLabel="Renombrar"
            pTooltip="Renombrar"
            (onClick)="start()"
            data-action="rename"
          />
        }
      </h1>
      @if (a.displayName) {
        <p class="discovered" data-discovered>
          Descubierto como <strong>{{ a.discoveredName }}</strong>
          @if (auth.can('assets.write')) {
            ·
            <button type="button" class="link" [disabled]="saving()" (click)="restore()" data-action="restore-name">
              Volver al nombre descubierto
            </button>
          }
        </p>
      }
    }
  `,
  styles: `
    h1 {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin: 0;
      font-size: 1.6rem;
      overflow-wrap: anywhere;
    }
    .edit {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
      font-size: 1.25rem;
    }
    .edit input {
      flex: 1 1 14rem;
      min-width: 0;
      max-width: 28rem;
    }
    .discovered,
    .muted {
      margin: 0.15rem 0 0;
      color: var(--p-text-muted-color);
      font-size: 0.875rem;
    }
    .link {
      border: 0;
      padding: 0;
      background: none;
      color: var(--p-primary-color);
      cursor: pointer;
      font: inherit;
    }
    .link:hover {
      text-decoration: underline;
    }
  `,
})
export class AssetName {
  private readonly api = inject(OrganizationApi);
  private readonly messages = inject(MessageService);
  protected readonly auth = inject(AuthService);
  protected readonly typeIcons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;

  readonly asset = input.required<Asset>();
  readonly changed = output<Asset>();

  protected readonly editing = signal(false);
  protected readonly draft = signal('');
  protected readonly saving = signal(false);

  start(): void {
    this.draft.set(this.asset().name);
    this.editing.set(true);
    queueMicrotask(() =>
      document.querySelector<HTMLInputElement>('#asset-display-name')?.select(),
    );
  }

  save(): void {
    const a = this.asset();
    const text = this.draft().trim();
    const displayName = !text || text === a.discoveredName ? null : text;
    if (displayName === a.displayName) {
      this.editing.set(false);
      return;
    }
    this.update(displayName, displayName ? 'Nombre guardado' : 'Vuelve al nombre descubierto');
  }

  restore(): void {
    this.update(null, 'Vuelve al nombre descubierto');
  }

  private update(displayName: string | null, done: string): void {
    this.saving.set(true);
    this.api.updateAsset(this.asset().id, { displayName }).subscribe({
      next: (asset) => {
        this.saving.set(false);
        this.editing.set(false);
        this.messages.add({ severity: 'success', summary: done, life: 2500 });
        this.changed.emit(asset);
      },
      error: (err: unknown) => {
        this.saving.set(false);
        this.messages.add({
          severity: 'error',
          summary: 'No se pudo renombrar',
          detail: apiErrorMessage(err, 'Inténtalo de nuevo.'),
        });
      },
    });
  }
}
