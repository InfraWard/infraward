import {
  Component,
  computed,
  inject,
  input,
  model,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  ASSET_RUNTIME_STATES,
  ASSET_STATUSES,
  ASSET_TYPES,
  SEARCH_KEY_INFO,
  SEVERITIES,
  foldText,
  formatSearchTerm,
  parseSearchQuery,
  removeSearchToken,
  searchKeyInfo,
  type SearchIssue,
  type SearchIssueKind,
  type SearchKey,
  type SearchScope,
  type SearchTerm,
} from '@infraward/shared-types';
import {
  AutoComplete,
  AutoCompleteModule,
} from '@openng/optimus-ui/autocomplete';
import type { AutoCompleteCompleteEvent } from '@openng/optimus-ui/types/autocomplete';
import { OrganizationStore } from '../core/organization-store';
import {
  ASSET_STATUS_LABELS,
  ASSET_TYPE_LABELS,
  RUNTIME_LABELS,
} from './labels';

/** Un valor que se puede sugerir para una clave. */
export interface QueryValueOption {
  value: string;
  label?: string;
}

interface Suggestion {
  /** El texto completo de la consulta al elegirla. */
  value: string;
  label: string;
  description?: string;
}

export const SEARCH_ISSUE_LABELS: Record<SearchIssueKind, string> = {
  unknown_key: 'Clave desconocida: se busca como texto',
  wrong_scope: 'Esta clave no se usa aquí: se ignora',
  unsupported: 'Aún no disponible: se ignora',
  invalid_value: 'Valor no válido: se ignora',
  empty_value: 'Falta el valor: se ignora',
  unclosed_quote: 'Comillas sin cerrar: llegan hasta el final',
  too_long: 'Demasiado larga: se ignora el resto',
};

const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: 'Crítica',
  HIGH: 'Alta',
  MEDIUM: 'Media',
  LOW: 'Baja',
  UNKNOWN: 'Desconocida',
};

const MAX_SUGGESTIONS = 12;

/** Inicio del token en el que se escribe (el último fuera de comillas). */
export function currentTokenStart(text: string): number {
  let start = 0;
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"') quoted = !quoted;
    else if (!quoted && /\s/.test(c)) start = i + 1;
  }
  return start;
}

/**
 * Sugerencias para el texto escrito: claves mientras se escribe la primera parte de un término
 * y, tras `clave:`, sus valores. Cada una lleva la consulta completa resultante.
 */
export function querySuggestions(
  text: string,
  scope: SearchScope,
  values: Partial<Record<SearchKey, readonly QueryValueOption[]>>,
): Suggestion[] {
  const start = currentTokenStart(text);
  const prefix = text.slice(0, start);
  const token = text.slice(start);
  const negated = token.startsWith('-');
  const body = negated ? token.slice(1) : token;
  const colon = body.indexOf(':');
  if (colon > 0) {
    const alias = body.slice(0, colon);
    const info = searchKeyInfo(alias);
    if (!info || !info.scopes.includes(scope) || info.unsupported) return [];
    const typed = foldText(body.slice(colon + 1).replace(/^"/, ''));
    return (values[info.key] ?? [])
      .filter(
        (o) =>
          foldText(o.value).includes(typed) ||
          foldText(o.label ?? '').includes(typed),
      )
      .slice(0, MAX_SUGGESTIONS)
      .map((o) => {
        const term = formatSearchTerm(alias, o.value, negated);
        return {
          value: `${prefix}${term} `,
          label: term,
          ...(o.label && o.label !== o.value ? { description: o.label } : {}),
        };
      });
  }
  const typed = foldText(body);
  return SEARCH_KEY_INFO.filter((info) => info.scopes.includes(scope))
    .flatMap((info) => {
      const alias = info.aliases.find((a) => a.startsWith(typed));
      if (!alias) return [];
      const key = `${negated ? '-' : ''}${alias}:`;
      return [
        {
          value: `${prefix}${key}`,
          label: key,
          description: info.unsupported
            ? `${info.description} · aún no disponible`
            : info.description,
        },
      ];
    })
    .slice(0, MAX_SUGGESTIONS);
}

/**
 * Búsqueda con sintaxis de filtros (DESIGN §15): `tag:prod nombre:"web prod" -estado:retirado`.
 * Autocompleta claves y valores existentes y enseña debajo los filtros activos como chips que se
 * pueden quitar, con los que se ignoran marcados (mismo parser que la API).
 */
@Component({
  selector: 'app-query-input',
  imports: [FormsModule, AutoCompleteModule],
  template: `
    <div class="query" data-query-input>
      <p-autocomplete
        #ac
        [ngModel]="value()"
        (ngModelChange)="onModel($event)"
        [suggestions]="suggestionValues()"
        (completeMethod)="complete($event)"
        (onSelect)="selected($any($event.value))"
        [minLength]="0"
        [delay]="0"
        [autoOptionFocus]="false"
        [completeOnFocus]="true"
        [showEmptyMessage]="false"
        [placeholder]="placeholder()"
        [ariaLabel]="ariaLabel()"
        [fluid]="true"
        scrollHeight="min(22rem, 60vh)"
        appendTo="body"
        styleClass="query-ac"
        data-query-text
      >
        <ng-template #item let-value>
          @if (suggestionsByValue().get(value); as s) {
            <span class="opt" [attr.data-suggestion]="s.label">
              <code>{{ s.label }}</code>
              @if (s.description) {
                <span class="muted">{{ s.description }}</span>
              }
            </span>
          }
        </ng-template>
      </p-autocomplete>
      @if (chips().length || loose().length) {
        <ul class="chips" aria-label="Filtros activos">
          @for (chip of chips(); track chip.term.start) {
            <li
              class="chip"
              [class.negated]="chip.term.negated"
              [class.warn]="!!chip.issue"
              [class.text]="chip.term.key === null"
              [attr.title]="
                chip.issue ? issueLabels[chip.issue.kind] : chip.title
              "
              data-query-chip
            >
              @if (chip.issue) {
                <i class="bi bi-exclamation-triangle" aria-hidden="true"></i>
              } @else if (chip.term.negated) {
                <i class="bi bi-dash-circle" aria-hidden="true"></i>
              }
              <span class="raw">{{ chip.term.raw }}</span>
              @if (chip.issue) {
                <span class="sr-only"
                  >({{ issueLabels[chip.issue.kind] }})</span
                >
              }
              <button
                type="button"
                class="remove"
                [attr.aria-label]="'Quitar ' + chip.term.raw"
                (click)="remove(chip.term)"
              >
                <i class="bi bi-x" aria-hidden="true"></i>
              </button>
            </li>
          }
          @for (issue of loose(); track issue.start) {
            <li
              class="chip warn"
              [attr.title]="issueLabels[issue.kind]"
              data-query-issue
            >
              <i class="bi bi-exclamation-triangle" aria-hidden="true"></i>
              <span class="raw">{{ issue.raw }}</span>
              <span class="sr-only">({{ issueLabels[issue.kind] }})</span>
              <button
                type="button"
                class="remove"
                [attr.aria-label]="'Quitar ' + issue.raw"
                (click)="remove(issue)"
              >
                <i class="bi bi-x" aria-hidden="true"></i>
              </button>
            </li>
          }
          @if (chips().length + loose().length > 1) {
            <li>
              <button
                type="button"
                class="clear"
                (click)="value.set('')"
                data-action="clear-query"
              >
                Quitar todos
              </button>
            </li>
          }
        </ul>
      }
    </div>
  `,
  styles: `
    :host {
      display: block;
      min-width: 0;
    }
    .query {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      min-width: 0;
    }
    .opt {
      display: inline-flex;
      gap: 0.5rem;
      align-items: baseline;
      min-width: 0;
    }
    .muted {
      color: var(--p-text-muted-color);
      font-size: 0.85em;
    }
    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 0.3rem;
      list-style: none;
      margin: 0;
      padding: 0;
      min-width: 0;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
      max-width: 100%;
      padding: 0.05rem 0.15rem 0.05rem 0.55rem;
      border-radius: 999px;
      font-size: 0.8rem;
      border: 1px solid var(--p-content-border-color);
      background: var(--p-content-background);
    }
    .chip .raw {
      font-family: var(--p-font-family-mono, ui-monospace, monospace);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .chip.negated {
      border-style: dashed;
    }
    .chip.warn {
      border-color: var(--p-app-warn-color);
      color: var(--p-app-warn-color);
    }
    .remove,
    .clear {
      background: none;
      border: 0;
      color: inherit;
      cursor: pointer;
      padding: 0 0.2rem;
      border-radius: 999px;
      line-height: 1;
    }
    .remove:hover,
    .remove:focus-visible,
    .clear:hover,
    .clear:focus-visible {
      color: var(--p-primary-color);
    }
    .clear {
      font-size: 0.8rem;
      text-decoration: underline;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
      white-space: nowrap;
    }
  `,
})
export class QueryInput {
  protected readonly store = inject(OrganizationStore);
  protected readonly issueLabels = SEARCH_ISSUE_LABELS;

  readonly value = model('');
  readonly scope = input<SearchScope>('inventory');
  readonly placeholder = input(
    'Buscar por nombre o con filtros: tag:prod tipo:servidor',
  );
  readonly ariaLabel = input('Buscar con filtros');
  /** Valores extra por clave (p. ej. los roles del árbol cargado). */
  readonly extraValues = input<
    Partial<Record<SearchKey, readonly QueryValueOption[]>>
  >({});

  private readonly ac = viewChild<AutoComplete>('ac');
  private readonly suggestions = signal<Suggestion[]>([]);
  /**
   * Las sugerencias son la consulta completa en texto (así el modelo siempre es el texto del
   * campo); la etiqueta y la descripción se buscan aquí para pintarlas.
   */
  protected readonly suggestionValues = computed(() =>
    this.suggestions().map((s) => s.value),
  );
  protected readonly suggestionsByValue = computed(
    () => new Map(this.suggestions().map((s) => [s.value, s])),
  );

  protected readonly parsed = computed(() =>
    parseSearchQuery(this.value(), this.scope()),
  );
  /** Los términos, con su aviso si lo tienen (clave desconocida, comillas sin cerrar). */
  protected readonly chips = computed(() => {
    const { terms, issues } = this.parsed();
    return terms.map((term) => ({
      term,
      issue: issues.find((i) => i.start === term.start) ?? null,
      title: term.key === null ? 'Texto en el nombre' : undefined,
    }));
  });
  /** Avisos de lo que se ignora (no filtra: no tiene término). */
  protected readonly loose = computed(() => {
    const { terms, issues } = this.parsed();
    return issues.filter((i) => !terms.some((t) => t.start === i.start));
  });

  private readonly values = computed(() => {
    const own: Partial<Record<SearchKey, QueryValueOption[]>> = {
      tag: this.store.tags().map((t) => ({ value: t.tag })),
      project: this.store.projects().map((p) => ({ value: p.name })),
      type: ASSET_TYPES.map((t) => ({ value: t, label: ASSET_TYPE_LABELS[t] })),
      status: [
        ...ASSET_STATUSES.map((s) => ({
          value: s,
          label: ASSET_STATUS_LABELS[s],
        })),
        ...ASSET_RUNTIME_STATES.map((s) => ({
          value: s,
          label: RUNTIME_LABELS[s],
        })),
      ],
      severity: [...SEVERITIES].reverse().map((s) => ({
        value: s.toLowerCase(),
        label: SEVERITY_LABELS[s],
      })),
    };
    return { ...own, ...this.extraValues() };
  });

  constructor() {
    this.store.ensureTags();
    this.store.ensureProjects();
  }

  protected complete(event: AutoCompleteCompleteEvent): void {
    this.suggestions.set(
      querySuggestions(event.query ?? '', this.scope(), this.values()),
    );
  }

  protected onModel(next: unknown): void {
    // Al vaciar el campo, el autocompletado emite null.
    if (typeof next === 'string') this.value.set(next);
    else if (next === null || next === undefined) this.value.set('');
  }

  /** Tras elegir una clave, enseña sus valores sin tener que escribir más. */
  protected selected(next: unknown): void {
    if (typeof next !== 'string') return;
    this.value.set(next);
    // Se sigue escribiendo al final (el autocompletado deja el cursor donde quiere).
    setTimeout(() => {
      const input = this.ac()?.inputEL?.nativeElement as
        HTMLInputElement | undefined;
      if (!input || input.value !== next) return;
      input.focus();
      input.setSelectionRange(next.length, next.length);
    });
    if (next.endsWith(':')) {
      const options = querySuggestions(next, this.scope(), this.values());
      this.suggestions.set(options);
      if (options.length) setTimeout(() => this.ac()?.show());
    }
  }

  protected remove(token: SearchTerm | SearchIssue): void {
    this.value.set(removeSearchToken(this.value(), token));
  }
}
