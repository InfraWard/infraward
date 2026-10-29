import { Component, computed, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ASSET_NOTES_MAX, type Asset } from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { SelectButtonModule } from '@openng/optimus-ui/selectbutton';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { OrganizationApi } from '../../core/api/organization-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { renderMarkdown } from '../../shared/markdown';

/**
 * Tarjeta «Notas» del Resumen: Markdown del asset ya pintado y, con `assets.write`, «Editar» con
 * el texto y una vista previa.
 */
@Component({
  selector: 'app-asset-notes',
  imports: [FormsModule, ButtonModule, CardModule, SelectButtonModule, TextareaModule],
  template: `
    <p-card styleClass="card" data-section="notes">
      <ng-template #title>
        <i class="bi bi-journal-text" aria-hidden="true"></i> Notas
        @if (!editing() && auth.can('assets.write')) {
          <span class="spacer"></span>
          <p-button
            [label]="html() ? 'Editar' : 'Añadir notas'"
            [icon]="html() ? 'bi bi-pencil' : 'bi bi-plus-lg'"
            severity="secondary"
            [text]="true"
            size="small"
            (onClick)="start()"
            data-action="edit-notes"
          />
        }
      </ng-template>
      @if (editing()) {
        <p-selectbutton
          [options]="modes"
          optionLabel="label"
          optionValue="value"
          [ngModel]="mode()"
          (ngModelChange)="mode.set($event)"
          [allowEmpty]="false"
          size="small"
          aria-label="Escribir o vista previa"
        />
        @if (mode() === 'write') {
          <textarea
            pTextarea
            class="editor"
            rows="10"
            [attr.maxlength]="max"
            aria-label="Notas en Markdown"
            placeholder="Markdown: # título, **negrita**, - listas, [enlace](https://…)"
            [ngModel]="draft()"
            (ngModelChange)="draft.set($event)"
            data-notes-input
          ></textarea>
          <small class="muted">{{ draft().length }} / {{ max }} · Markdown</small>
        } @else {
          <div class="markdown preview" [innerHTML]="preview()" data-notes-preview></div>
        }
        <div class="actions">
          <p-button
            label="Cancelar"
            severity="secondary"
            [text]="true"
            (onClick)="editing.set(false)"
          />
          <p-button
            label="Guardar"
            icon="bi bi-check-lg"
            [loading]="saving()"
            (onClick)="save()"
            data-action="save-notes"
          />
        </div>
      } @else if (html()) {
        <div class="markdown" [innerHTML]="html()" data-notes></div>
      } @else {
        <p class="muted">Sin notas.</p>
      }
    </p-card>
  `,
  styles: `
    .spacer {
      flex: 1;
    }
    .editor {
      width: 100%;
      margin-top: 0.5rem;
      font-family: var(--p-font-family-mono, ui-monospace, monospace);
      font-size: 0.875rem;
      resize: vertical;
    }
    .preview {
      margin-top: 0.5rem;
      min-height: 6rem;
      padding: 0.5rem 0.75rem;
      border: 1px dashed var(--p-content-border-color);
      border-radius: 6px;
    }
    .actions {
      display: flex;
      justify-content: flex-end;
      gap: 0.5rem;
      margin-top: 0.5rem;
    }
    .muted {
      color: var(--p-text-muted-color);
      margin: 0;
    }
    .markdown {
      overflow-wrap: anywhere;
    }
    .markdown ::ng-deep {
      h1,
      h2,
      h3 {
        font-size: 1.05rem;
        margin: 0.75rem 0 0.35rem;
      }
      > :first-child {
        margin-top: 0;
      }
      p,
      ul,
      ol {
        margin: 0 0 0.5rem;
      }
      ul,
      ol {
        padding-left: 1.25rem;
      }
      ul {
        list-style: disc;
      }
      ol {
        list-style: decimal;
      }
      a {
        color: var(--p-primary-color);
        text-decoration: underline;
      }
      code,
      pre {
        background: var(--p-app-code-background);
        border-radius: 4px;
        font-size: 0.85em;
      }
      code {
        padding: 0 0.25rem;
      }
      pre {
        padding: 0.5rem;
        overflow-x: auto;
      }
      blockquote {
        margin: 0 0 0.5rem;
        padding-left: 0.75rem;
        border-left: 3px solid var(--p-content-border-color);
        color: var(--p-text-muted-color);
      }
      table {
        border-collapse: collapse;
      }
      th,
      td {
        border: 1px solid var(--p-content-border-color);
        padding: 0.2rem 0.5rem;
      }
    }
  `,
})
export class AssetNotes {
  private readonly api = inject(OrganizationApi);
  private readonly messages = inject(MessageService);
  protected readonly auth = inject(AuthService);
  protected readonly max = ASSET_NOTES_MAX;
  protected readonly modes = [
    { label: 'Escribir', value: 'write' },
    { label: 'Vista previa', value: 'preview' },
  ];

  readonly asset = input.required<Asset>();
  readonly changed = output<Asset>();

  protected readonly editing = signal(false);
  protected readonly mode = signal<'write' | 'preview'>('write');
  protected readonly draft = signal('');
  protected readonly saving = signal(false);
  protected readonly html = computed(() => renderMarkdown(this.asset().notes));
  protected readonly preview = computed(() => renderMarkdown(this.draft()));

  start(): void {
    this.draft.set(this.asset().notes ?? '');
    this.mode.set('write');
    this.editing.set(true);
  }

  save(): void {
    this.saving.set(true);
    const notes = this.draft().trim() ? this.draft() : null;
    this.api.updateAsset(this.asset().id, { notes }).subscribe({
      next: (asset) => {
        this.saving.set(false);
        this.editing.set(false);
        this.messages.add({ severity: 'success', summary: 'Notas guardadas', life: 2500 });
        this.changed.emit(asset);
      },
      error: (err: unknown) => {
        this.saving.set(false);
        this.messages.add({
          severity: 'error',
          summary: 'No se pudieron guardar las notas',
          detail: apiErrorMessage(err, 'Inténtalo de nuevo.'),
        });
      },
    });
  }
}
