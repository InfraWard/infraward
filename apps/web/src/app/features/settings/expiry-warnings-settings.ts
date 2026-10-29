import { Component, inject, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  EXPIRY_WARNING_MAX_DAYS,
  EXPIRY_WARNING_MAX_THRESHOLDS,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { DomainsApi } from '../../core/api/domains-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';

/**
 * Ajustes > Inventario > Avisos de caducidad (DESIGN §13): días antes de que caduque un dominio
 * (RDAP) o un certificado en los que se avisa. El mayor marca «caduca pronto» en el árbol y el
 * panel; cada umbral cruzado genera una notificación. Editable con `policy.write`.
 */
@Component({
  selector: 'app-expiry-warnings-settings',
  imports: [FormsModule, ButtonModule, CardModule, InputNumberModule, MessageModule, TagModule],
  template: `
    <p-card styleClass="block" data-block="expiry-warnings">
      <ng-template #title>Avisos de caducidad</ng-template>
      <p class="text-muted intro">
        Días antes de que caduque un dominio o un certificado en los que se avisa. El mayor marca
        «caduca pronto» en el inventario y el panel; cada umbral cruzado manda una notificación.
      </p>
      <div class="days" data-days>
        @for (d of days(); track d) {
          <p-tag [value]="d + (d === 1 ? ' día' : ' días')" severity="secondary"
            [attr.data-threshold]="d">
            @if (canEdit) {
              <button type="button" class="remove" [attr.aria-label]="'Quitar ' + d + ' días'"
                (click)="remove(d)" [disabled]="days().length === 1">
                <i class="bi bi-x" aria-hidden="true"></i>
              </button>
            }
          </p-tag>
        }
      </div>
      @if (canEdit) {
        <div class="add">
          <label for="expiry-add" class="sr-only">Nuevo umbral en días</label>
          <!-- onInput: el modelo de p-inputnumber solo cambia al salir del campo. -->
          <p-inputnumber inputId="expiry-add" [(ngModel)]="draft" [min]="1" [max]="maxDays"
            [showButtons]="false" placeholder="Días" size="small" [inputStyle]="{ width: '6rem' }"
            (onInput)="draft = toDays($event.value)" (keydown.enter)="add()" />
          <p-button label="Añadir" icon="bi bi-plus-lg" size="small" severity="secondary"
            [disabled]="!draft || days().length >= maxThresholds" (onClick)="add()" data-action="add-threshold" />
          <p-button label="Guardar" icon="bi bi-check-lg" size="small" [disabled]="!dirty()"
            [loading]="busy()" (onClick)="save()" data-action="save-thresholds" />
        </div>
        <small class="text-muted">Hasta {{ maxThresholds }} umbrales, de 1 a {{ maxDays }} días.</small>
      }
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      }
    </p-card>
  `,
  styles: `
    .intro {
      margin: 0 0 0.75rem;
    }
    .days {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      margin-bottom: 0.75rem;
    }
    .remove {
      border: 0;
      background: none;
      color: inherit;
      cursor: pointer;
      padding: 0 0 0 0.25rem;
      line-height: 1;
    }
    .remove:disabled {
      opacity: 0.4;
      cursor: default;
    }
    .add {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.4rem;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
    }
  `,
})
export class ExpiryWarningsSettings implements OnInit {
  private readonly api = inject(DomainsApi);
  private readonly messages = inject(MessageService);
  protected readonly canEdit = inject(AuthService).can('policy.write');
  protected readonly maxDays = EXPIRY_WARNING_MAX_DAYS;
  protected readonly maxThresholds = EXPIRY_WARNING_MAX_THRESHOLDS;

  protected readonly days = signal<number[]>([]);
  protected readonly dirty = signal(false);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected draft: number | null = null;

  ngOnInit(): void {
    this.api.expiryWarnings().subscribe({
      next: (s) => this.days.set(s.days),
      error: (err: unknown) =>
        this.error.set(apiErrorMessage(err, 'No se pudieron leer los umbrales.')),
    });
  }

  protected toDays(value: unknown): number | null {
    const n = Number(value);
    return Number.isInteger(n) && n >= 1 && n <= this.maxDays ? n : null;
  }

  protected add(): void {
    const d = this.draft;
    if (!d || this.days().includes(d)) return;
    this.days.update((list) => [...list, d].sort((a, b) => b - a));
    this.draft = null;
    this.dirty.set(true);
  }

  protected remove(d: number): void {
    this.days.update((list) => list.filter((x) => x !== d));
    this.dirty.set(true);
  }

  protected save(): void {
    this.busy.set(true);
    this.api.setExpiryWarnings(this.days()).subscribe({
      next: (s) => {
        this.busy.set(false);
        this.days.set(s.days);
        this.dirty.set(false);
        this.error.set(null);
        this.messages.add({ severity: 'success', summary: 'Umbrales guardados', life: 3000 });
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudieron guardar los umbrales.'));
      },
    });
  }
}
