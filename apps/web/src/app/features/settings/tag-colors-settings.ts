import { Component, inject, signal } from '@angular/core';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { OrganizationApi } from '../../core/api/organization-api';
import { AuthService } from '../../core/auth/auth.service';
import { OrganizationStore } from '../../core/organization-store';
import { apiErrorMessage } from '../../shared/api-errors';
import { ColorSwatches } from '../../shared/color-swatches';
import { TagChip } from '../../shared/tag-chip';

/**
 * Tags en Ajustes > Inventario: su color (opcional) y borrarlos de todos los assets; las dos cosas
 * piden `assets.write`.
 */
@Component({
  selector: 'app-tag-colors-settings',
  imports: [ButtonModule, CardModule, ColorSwatches, TagChip, TooltipModule],
  template: `
    <p-card styleClass="block" data-block="tag-colors">
      <ng-template #title>Tags</ng-template>
      <p class="text-muted intro">
        Los tags se ponen y se quitan en el inventario y en la ficha de cada asset; aquí, su color
        (opcional) en todas las vistas, o borrarlos de todos los assets a la vez.
      </p>
      @if (store.tags().length) {
        <ul class="tags">
          @for (t of store.tags(); track t.tag) {
            <li [attr.data-tag-color]="t.tag">
              <span class="tag">
                <app-tag-chip [tag]="t.tag" [color]="t.color" />
                <span class="text-muted small">{{ t.assets }} {{ t.assets === 1 ? 'asset' : 'assets' }}</span>
              </span>
              @if (auth.can('assets.write')) {
                <span class="edit" [class.busy]="busy() === t.tag">
                  <app-color-swatches
                    [value]="t.color"
                    (valueChange)="setColor(t.tag, $event)"
                    [label]="'Color del tag ' + t.tag"
                  />
                  <p-button
                    icon="bi bi-trash"
                    severity="danger"
                    [text]="true"
                    size="small"
                    [ariaLabel]="'Borrar el tag ' + t.tag"
                    [pTooltip]="'Borrar ' + t.tag + ' de todos los assets'"
                    data-action="delete-tag"
                    (onClick)="remove(t.tag, t.assets)"
                  />
                </span>
              }
            </li>
          }
        </ul>
      } @else {
        <p class="text-muted">Aún no hay tags.</p>
      }
    </p-card>
  `,
  styles: `
    .intro {
      margin-top: 0;
    }
    .tags {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 0.6rem;
    }
    li {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem 1rem;
    }
    .tag {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }
    .small {
      font-size: 0.85rem;
    }
    .edit {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }
    .busy {
      opacity: 0.5;
      pointer-events: none;
    }
  `,
})
export class TagColorsSettings {
  private readonly api = inject(OrganizationApi);
  private readonly messages = inject(MessageService);
  private readonly confirmation = inject(ConfirmationService);
  protected readonly store = inject(OrganizationStore);
  protected readonly auth = inject(AuthService);
  protected readonly busy = signal<string | null>(null);

  constructor() {
    this.store.reloadTags();
  }

  protected remove(tag: string, assets: number): void {
    this.confirmation.confirm({
      header: `Borrar el tag ${tag}`,
      message:
        assets > 0
          ? `Se quita de ${assets} ${assets === 1 ? 'asset' : 'assets'} (y se olvida su color). Las reglas de política y de acceso por esta etiqueta se conservan: vuelven a valer si se pone otra vez. ¿Borrarlo?`
          : 'Ningún asset lo lleva: se olvida su color. ¿Borrarlo?',
      icon: 'bi bi-trash',
      acceptLabel: 'Borrar',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () => {
        this.busy.set(tag);
        this.api.deleteTag(tag).subscribe({
          next: ({ assets: n }) => {
            this.busy.set(null);
            this.store.reloadTags();
            this.messages.add({
              severity: 'success',
              summary: `Tag ${tag} borrado`,
              detail: `Quitado de ${n} ${n === 1 ? 'asset' : 'assets'}.`,
            });
          },
          error: (err: unknown) => {
            this.busy.set(null);
            this.messages.add({
              severity: 'error',
              summary: 'No se pudo borrar el tag',
              detail: apiErrorMessage(err, 'Inténtalo de nuevo.'),
            });
          },
        });
      },
    });
  }

  protected setColor(tag: string, color: string | null): void {
    this.busy.set(tag);
    this.api.setTagColor(tag, color).subscribe({
      next: () => {
        this.busy.set(null);
        this.store.reloadTags();
      },
      error: (err: unknown) => {
        this.busy.set(null);
        this.messages.add({
          severity: 'error',
          summary: 'No se pudo cambiar el color',
          detail: apiErrorMessage(err, 'Inténtalo de nuevo.'),
        });
      },
    });
  }
}
