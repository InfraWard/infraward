import {
  Component,
  computed,
  ElementRef,
  inject,
  input,
  model,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AutoCompleteModule } from '@openng/optimus-ui/autocomplete';
import type { AutoCompleteCompleteEvent } from '@openng/optimus-ui/types/autocomplete';
import { OrganizationStore } from '../core/organization-store';
import { TagChip } from './tag-chip';

/** Mismo formato que la API: sin espacios, empieza por letra o número. */
export const TAG_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N}._:/-]*$/u;
export const TAG_MAX = 64;

/**
 * Tags de un asset con su color. Con `editable`: «x» para quitar y «+» para añadir con
 * autocompletado de los tags que ya existen. Emite la lista nueva (quien lo usa la guarda).
 */
@Component({
  selector: 'app-tag-editor',
  imports: [FormsModule, AutoCompleteModule, TagChip],
  template: `
    <span class="tag-editor" [class.compact]="compact()" data-tag-editor>
      @for (tag of tags(); track tag) {
        <app-tag-chip
          [tag]="tag"
          [color]="store.tagColors().get(tag)"
          [removable]="editable() && !busy()"
          (remove)="removeTag(tag)"
        />
      }
      @if (editable()) {
        @if (adding()) {
          <span class="add">
            <p-autocomplete
              #input
              [ngModelOptions]="{ standalone: true }"
              [ngModel]="draft()"
              (ngModelChange)="draft.set($event ?? '')"
              [suggestions]="suggestions()"
              (completeMethod)="complete($event)"
              (onSelect)="add($any($event.value))"
              (keydown.enter)="add(draft())"
              (keydown.escape)="cancel()"
              (onBlur)="onBlur()"
              [minLength]="0"
              [delay]="0"
              [autoOptionFocus]="false"
              [completeOnFocus]="true"
              [autofocus]="true"
              placeholder="tag"
              ariaLabel="Nuevo tag"
              appendTo="body"
              data-tag-input
            />
            @if (error(); as message) {
              <small class="error" role="alert">{{ message }}</small>
            }
          </span>
        } @else {
          <button
            type="button"
            class="plus"
            [disabled]="busy()"
            [attr.aria-label]="tags().length ? 'Añadir un tag' : 'Añadir tags'"
            [title]="'Añadir un tag'"
            (click)="start()"
            data-action="add-tag"
          >
            <i class="bi bi-plus" aria-hidden="true"></i>
            @if (!tags().length && !compact()) {
              <span>Añadir tag</span>
            }
          </button>
        }
      }
    </span>
  `,
  styles: `
    .tag-editor {
      display: inline-flex;
      flex-wrap: wrap;
      gap: 0.25rem;
      align-items: center;
      max-width: 100%;
    }
    .plus {
      display: inline-flex;
      align-items: center;
      gap: 0.15rem;
      font-size: var(--tag-font-size, 0.75rem);
      line-height: 1.4;
      padding: var(--tag-padding, 0 0.4rem);
      border-radius: 999px;
      border: 1px dashed var(--p-content-border-color);
      background: none;
      color: var(--p-text-muted-color);
      cursor: pointer;
    }
    .plus:hover,
    .plus:focus-visible {
      color: var(--p-primary-color);
      border-color: var(--p-primary-color);
    }
    .add {
      display: inline-flex;
      flex-direction: column;
      gap: 0.15rem;
    }
    .error {
      color: var(--p-app-danger-color);
      font-size: 0.75rem;
    }
    :host ::ng-deep .add input {
      width: 9rem;
      padding-block: 0.15rem;
      font-size: 0.8rem;
    }
  `,
})
export class TagEditor {
  protected readonly store = inject(OrganizationStore);
  readonly tags = input<readonly string[]>([]);
  readonly editable = input(false);
  /** En el árbol: sin el texto «Añadir tag». */
  readonly compact = input(false);
  /** Mientras se guarda: sin quitar ni añadir. */
  readonly busy = input(false);
  readonly tagsChange = output<string[]>();

  /**
   * Campo de añadir abierto. Es un `model` para que lo pueda guardar quien lo usa: en el árbol,
   * el treeTable vuelve a crear las filas y el estado local se perdería.
   */
  readonly adding = model(false);
  /** Texto escrito (también `model`, por lo mismo). */
  readonly draft = model('');
  protected readonly error = signal<string | null>(null);
  protected readonly suggestions = signal<string[]>([]);
  private readonly input = viewChild('input', { read: ElementRef });
  private readonly known = computed(() =>
    this.store.tags().map((t) => t.tag),
  );

  constructor() {
    // Los colores de los tags.
    this.store.ensureTags();
  }

  start(): void {
    this.store.ensureTags();
    this.adding.set(true);
    this.draft.set('');
    this.error.set(null);
    // Tras pintar el campo (respaldo de `autofocus`).
    setTimeout(() =>
      (this.input()?.nativeElement as HTMLElement | undefined)
        ?.querySelector('input')
        ?.focus(),
    );
  }

  cancel(): void {
    this.adding.set(false);
    this.error.set(null);
  }

  /** Al salir del campo sin escribir nada, se cierra. */
  onBlur(): void {
    setTimeout(() => {
      if (!this.draft().trim() && this.adding()) this.cancel();
    }, 150);
  }

  complete(event: AutoCompleteCompleteEvent): void {
    const q = (event.query ?? '').trim().toLowerCase();
    const current = new Set(this.tags());
    this.suggestions.set(
      this.known()
        .filter((t) => !current.has(t) && t.toLowerCase().includes(q))
        .slice(0, 20),
    );
  }

  add(value: string): void {
    const tag = (value ?? '').trim();
    if (!tag) return;
    if (tag.length > TAG_MAX || !TAG_PATTERN.test(tag)) {
      this.error.set('Sin espacios; empieza por letra o número (._:/- permitidos)');
      return;
    }
    this.adding.set(false);
    this.error.set(null);
    if (this.tags().includes(tag)) return;
    this.tagsChange.emit([...this.tags(), tag]);
  }

  removeTag(tag: string): void {
    this.tagsChange.emit(this.tags().filter((t) => t !== tag));
  }
}
