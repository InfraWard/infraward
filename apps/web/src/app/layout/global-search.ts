import {
  Component,
  ElementRef,
  HostListener,
  inject,
  input,
  output,
  signal,
  viewChild,
  type AfterViewInit,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import {
  CVE_ID_PATTERN,
  formatSearchTerm,
  ipMatcher,
  type SearchSuggestions,
  type SuggestedAsset,
  type Severity,
} from '@infraward/shared-types';
import { AutoComplete, AutoCompleteModule } from '@openng/optimus-ui/autocomplete';
import type { AutoCompleteCompleteEvent } from '@openng/optimus-ui/types/autocomplete';
import { TagModule } from '@openng/optimus-ui/tag';
import { catchError, of } from 'rxjs';
import { FindingsApi } from '../core/api/findings-api';
import {
  ASSET_STATUS_LABELS,
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
  SEVERITY_TAG,
  type TagSeverity,
} from '../shared/labels';

/** Una opción de la barra: un recurso, un CVE, los CVE de un paquete o buscar el texto. */
export type SearchOption =
  | { kind: 'asset'; asset: SuggestedAsset }
  | { kind: 'cve'; id: string; severity: Severity | null; title: string | null }
  | { kind: 'package'; name: string; vulnerabilities: number; assets: number }
  | { kind: 'text'; text: string; scope: 'inventory' | 'vulnerabilities' };

export interface SearchGroup {
  label: string;
  items: SearchOption[];
}

/**
 * Grupos de sugerencias: primero la acción directa, que es la que elige Enter (abrir el CVE escrito
 * o buscar el texto en el inventario y en las vulnerabilidades), y después los recursos, CVE y
 * paquetes que coinciden.
 */
export function searchGroups(
  text: string,
  suggestions: SearchSuggestions | null,
): SearchGroup[] {
  const q = text.trim();
  if (!q) return [];
  const cve = CVE_ID_PATTERN.test(q) ? q.toUpperCase() : null;
  const direct: SearchOption | null = cve
    ? {
        kind: 'cve',
        id: cve,
        ...(suggestions?.vulnerabilities.find((v) => v.vulnerabilityId === cve) ?? {
          severity: null,
          title: null,
        }),
      }
    : null;
  const groups: SearchGroup[] = [
    {
      label: 'Ir a',
      items: direct
        ? [direct]
        : [
            { kind: 'text', text: q, scope: 'inventory' },
            { kind: 'text', text: q, scope: 'vulnerabilities' },
          ],
    },
  ];
  const assets = (suggestions?.assets ?? []).map(
    (asset): SearchOption => ({ kind: 'asset', asset }),
  );
  if (assets.length) groups.push({ label: 'Inventario', items: assets });
  const cves = (suggestions?.vulnerabilities ?? [])
    .filter((v) => v.vulnerabilityId !== cve)
    .map(
      (v): SearchOption => ({
        kind: 'cve',
        id: v.vulnerabilityId,
        severity: v.severity,
        title: v.title,
      }),
    );
  if (cves.length) groups.push({ label: 'Vulnerabilidades', items: cves });
  const packages = (suggestions?.packages ?? []).map(
    (p): SearchOption => ({ kind: 'package', ...p }),
  );
  if (packages.length) groups.push({ label: 'Paquetes', items: packages });
  return groups;
}

/**
 * El texto de la barra como búsqueda del inventario (DESIGN §15): una IP pasa a `ip:` (el texto
 * suelto solo busca en el nombre) y un texto con espacios va entre comillas, como un solo término.
 */
export function inventoryQuery(text: string): string {
  const t = text.trim();
  if (ipMatcher(t) && /^[\d.:a-f/]+$/i.test(t) && /[.:]/.test(t)) return formatSearchTerm('ip', t);
  return /\s/.test(t) ? `"${t.replaceAll('"', '')}"` : t;
}

/**
 * Ruta de una opción. Un recurso abre su ficha; un paquete (o el texto en vulnerabilidades), la
 * lista con sus CVE abiertos de cualquier severidad; el texto en el inventario, el árbol filtrado.
 */
export function searchTarget(option: SearchOption): {
  commands: string[];
  queryParams?: Record<string, string>;
} {
  switch (option.kind) {
    case 'asset':
      return { commands: ['/assets', option.asset.id] };
    case 'cve':
      return { commands: ['/vulnerabilities', option.id] };
    case 'package':
      return {
        commands: ['/vulnerabilities'],
        queryParams: { q: option.name, min: 'any', fixable: '0' },
      };
    case 'text':
      return option.scope === 'inventory'
        ? { commands: ['/inventory'], queryParams: { q: inventoryQuery(option.text) } }
        : {
            commands: ['/vulnerabilities'],
            queryParams: { q: option.text, min: 'any', fixable: '0' },
          };
  }
}

/**
 * Barra de búsqueda global de la barra superior: cualquier recurso del inventario (por nombre,
 * dirección, rol o etiqueta), un CVE (`CVE-2023-45853`, abre su ficha aunque no esté en el
 * inventario) o un paquete (por subcadena). Atajo `/` para enfocarla.
 */
@Component({
  selector: 'app-global-search',
  imports: [FormsModule, AutoCompleteModule, TagModule],
  template: `
    <p-autocomplete
      [ngModel]="value()"
      (ngModelChange)="value.set($event)"
      [suggestions]="groups()"
      (completeMethod)="complete($event)"
      (onSelect)="go($any($event.value))"
      (onHide)="onHide()"
      [group]="true"
      optionGroupLabel="label"
      optionGroupChildren="items"
      [optionLabel]="optionText"
      [delay]="200"
      [minLength]="2"
      [autoOptionFocus]="true"
      [focusOnHover]="false"
      scrollHeight="min(28rem, 70vh)"
      [showEmptyMessage]="false"
      placeholder="Buscar recursos, CVE o paquetes  ( / )"
      ariaLabel="Buscar recursos, CVE o paquetes"
      inputId="global-search"
      styleClass="global-search"
      [fluid]="true"
      appendTo="body"
      data-global-search
    >
      <ng-template #group let-group>
        <span class="group-label">{{ group.label }}</span>
      </ng-template>
      <ng-template #item let-o>
        @switch (o.kind) {
          @case ('cve') {
            <span class="opt" [attr.data-option]="o.id">
              <i class="bi bi-shield-exclamation" aria-hidden="true"></i>
              <code>{{ o.id }}</code>
              @if (o.severity) {
                <p-tag [value]="o.severity" [severity]="severityTag[o.severity]" />
              }
              @if (o.title) {
                <span class="muted ellipsis">{{ o.title }}</span>
              }
            </span>
          }
          @case ('package') {
            <span class="opt" [attr.data-option]="o.name">
              <i class="bi bi-box-seam" aria-hidden="true"></i>
              <code>{{ o.name }}</code>
              <span class="muted">
                {{ o.vulnerabilities }} CVE · {{ o.assets }} {{ o.assets === 1 ? 'asset' : 'assets' }}
              </span>
            </span>
          }
          @case ('asset') {
            <span class="opt" [attr.data-option]="'asset:' + o.asset.name">
              <i class="bi {{ typeIcons[o.asset.type] }}" aria-hidden="true"></i>
              <span>{{ o.asset.name }}</span>
              <span class="muted ellipsis">
                {{ typeLabels[o.asset.type] }}@if (o.asset.parentName) { · en {{ o.asset.parentName }}}@if (o.asset.address) { · {{ o.asset.address }}}@if (o.asset.status !== 'active') { · {{ statusLabels[o.asset.status] }}}
              </span>
            </span>
          }
          @case ('text') {
            <span class="opt" [attr.data-option]="'text:' + o.scope">
              <i class="bi {{ o.scope === 'inventory' ? 'bi-diagram-3' : 'bi-shield-exclamation' }}" aria-hidden="true"></i>
              Buscar «{{ o.text }}» en {{ o.scope === 'inventory' ? 'el inventario' : 'vulnerabilidades' }}
            </span>
          }
        }
      </ng-template>
    </p-autocomplete>
  `,
  styles: `
    :host {
      display: block;
      width: 100%;
    }
    .opt {
      display: inline-flex;
      gap: 0.5rem;
      align-items: center;
      min-width: 0;
      max-width: min(36rem, 85vw);
    }
    .muted {
      color: var(--p-text-muted-color);
      font-size: 0.85rem;
    }
    .ellipsis {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .group-label {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--p-text-muted-color);
    }
  `,
})
export class GlobalSearch implements AfterViewInit {
  private readonly api = inject(FindingsApi);
  private readonly router = inject(Router);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);

  /** Enfoca el campo al crearse (en móvil se abre con un botón). */
  readonly autofocus = input(false);
  /** Tras navegar (el shell cierra la barra en móvil). */
  readonly navigated = output<void>();

  protected readonly severityTag: Readonly<Record<string, TagSeverity>> = SEVERITY_TAG;
  protected readonly typeIcons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
  protected readonly typeLabels: Readonly<Record<string, string>> = ASSET_TYPE_LABELS;
  protected readonly statusLabels: Readonly<Record<string, string>> = ASSET_STATUS_LABELS;
  protected readonly value = signal<string | SearchOption>('');
  protected readonly groups = signal<SearchGroup[]>([]);
  private readonly autocomplete = viewChild(AutoComplete);

  /** Texto de una opción (el autocompletado recibe grupos y opciones sin tipo). */
  protected readonly optionText = (item: unknown): string => {
    const o = item as SearchOption;
    switch (o.kind) {
      case 'asset':
        return o.asset.name;
      case 'cve':
        return o.id;
      case 'package':
        return o.name;
      case 'text':
        return o.text;
    }
  };

  ngAfterViewInit(): void {
    // El campo del autocompletado aún no está pintado en este punto.
    if (this.autofocus()) setTimeout(() => this.focus());
  }

  complete(event: AutoCompleteCompleteEvent): void {
    const text = event.query;
    this.resetFocusedOption();
    // La acción directa sale ya; las sugerencias del inventario, al llegar.
    this.groups.set(searchGroups(text, null));
    this.api
      .suggest(text.trim())
      .pipe(catchError(() => of(null)))
      .subscribe((s) => {
        if (s && typeof this.value() === 'string' && this.value() === text)
          this.groups.set(searchGroups(text, s));
      });
  }

  go(option: SearchOption): void {
    const { commands, queryParams } = searchTarget(option);
    void this.router.navigate(commands, { queryParams });
    // El autocompletado escribe la opción elegida después de `onSelect`: se vacía después.
    setTimeout(() => this.value.set(''));
    this.groups.set([]);
    this.resetFocusedOption();
    this.leaving = true;
    this.navigated.emit();
  }

  /**
   * El autocompletado recuerda la posición de la última opción elegida o señalada y, en la búsqueda
   * siguiente, Enter elegiría la que cayera en ese sitio: se vuelve a la primera (la acción directa).
   */
  private resetFocusedOption(): void {
    this.autocomplete()?.focusedOptionIndex.set(-1);
  }

  /** Tras navegar, fuera el foco (al cerrarse, el autocompletado lo devuelve al campo). */
  private leaving = false;

  onHide(): void {
    if (!this.leaving) return;
    this.leaving = false;
    setTimeout(() => this.input()?.blur());
  }

  /** `/` enfoca la barra (salvo escribiendo en otro campo). */
  @HostListener('document:keydown', ['$event'])
  onKey(event: KeyboardEvent): void {
    if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
    const target = event.target;
    if (
      target instanceof Element &&
      target.closest('input, textarea, select, [contenteditable="true"]')
    )
      return;
    event.preventDefault();
    this.focus();
  }

  private focus(): void {
    this.input()?.focus();
  }

  private input(): HTMLInputElement | null {
    return this.host.nativeElement.querySelector<HTMLInputElement>('input#global-search');
  }
}
