import { Component, computed, input } from '@angular/core';
import type {
  SnapshotChange,
  SnapshotChangeSummary,
  SnapshotDiff,
} from '@infraward/shared-types';
import { TagModule } from '@openng/optimus-ui/tag';
import {
  CHANGE_KIND_LABELS,
  CHANGE_KIND_SEVERITY,
  sectionLabel,
} from '../../shared/maintenance-labels';
import type { TagSeverity } from '../../shared/labels';

/** Cambios por sección con su resumen, en el orden en que llegan. */
interface Section {
  key: string;
  label: string;
  summary: SnapshotChangeSummary | undefined;
  changes: SnapshotChange[];
}

/** Por sección, como mucho estos cambios a la vista (el resto, con «Ver los N»). */
export const MAX_SECTION_CHANGES = 25;

/** «+3 −1 ~5». */
export function summaryText(s: SnapshotChangeSummary): string {
  return [
    s.added ? `+${s.added}` : '',
    s.removed ? `−${s.removed}` : '',
    s.changed ? `~${s.changed}` : '',
  ]
    .filter(Boolean)
    .join(' ');
}

/** Valor de un cambio en una línea (objetos en JSON compacto, recortado). */
export function changeValue(value: unknown): string {
  if (value === undefined) return '';
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return text.length > 160 ? `${text.slice(0, 157)}…` : text;
}

/** Ruta del cambio dentro de su sección (`packages[openssl:amd64].version` → `openssl:amd64 · version`). */
export function changeLabel(path: string, section: string): string {
  const rest = path.slice(section.length).replace(/^\./, '');
  if (!rest) return section;
  return rest.replace(/^\[([^\]]*)\]\.?/, '$1 · ').replace(/ · $/, '');
}

/**
 * Diff de un snapshot con el anterior (DESIGN §10): una sección por bloque de los facts (paquetes,
 * puertos, Proxmox…) con lo añadido, quitado y cambiado.
 */
@Component({
  selector: 'app-snapshot-diff',
  imports: [TagModule],
  template: `
    @if (!diff()) {
      <p class="muted" data-diff="none">
        @if (first()) {
          Primer snapshot del asset: no hay nada con lo que compararlo.
        } @else {
          Snapshot anterior al cálculo de cambios: no tiene diff.
        }
      </p>
    } @else {
      @if (diff()!.truncated) {
        <p class="muted small">Lista de cambios recortada; los totales sí cuentan todos.</p>
      }
      @for (s of sections(); track s.key) {
        <section class="section" [attr.data-diff-section]="s.key">
          <h4>
            {{ s.label }}
            @if (s.summary) {
              <span class="muted small">{{ summary(s.summary) }}</span>
            }
          </h4>
          <ul>
            @for (c of s.changes.slice(0, max); track $index) {
              <li [attr.data-kind]="c.kind">
                <p-tag [value]="kindLabels[c.kind]" [severity]="kindSeverity[c.kind]" />
                <code class="path">{{ label(c.path, s.key) }}</code>
                @if (c.kind === 'changed') {
                  <span class="value before">{{ value(c.before) }}</span>
                  <i class="bi bi-arrow-right" aria-hidden="true"></i>
                  <span class="value after">{{ value(c.after) }}</span>
                } @else if (c.kind === 'added') {
                  <span class="value after">{{ value(c.after) }}</span>
                } @else {
                  <span class="value before">{{ value(c.before) }}</span>
                }
              </li>
            }
          </ul>
          @if (s.changes.length > max) {
            <p class="muted small">Y {{ s.changes.length - max }} cambios más en esta sección.</p>
          }
        </section>
      } @empty {
        <p class="muted">Sin cambios.</p>
      }
    }
  `,
  styles: `
    .section + .section {
      margin-top: 1rem;
    }
    h4 {
      margin: 0 0 0.4rem;
      display: flex;
      gap: 0.5rem;
      align-items: baseline;
    }
    ul {
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 0.3rem;
    }
    li {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.4rem;
      min-width: 0;
    }
    .path {
      font-weight: 600;
      overflow-wrap: anywhere;
    }
    .value {
      font-family: var(--p-font-family-mono, monospace);
      font-size: 0.85em;
      overflow-wrap: anywhere;
      min-width: 0;
    }
    .before {
      color: var(--p-app-danger-color);
    }
    .after {
      color: var(--p-app-success-color);
    }
  `,
})
export class SnapshotDiffView {
  readonly diff = input<SnapshotDiff | null>(null);
  /** Es el primer snapshot del asset (sin anterior). */
  readonly first = input(false);

  protected readonly max = MAX_SECTION_CHANGES;
  protected readonly kindLabels: Readonly<Record<string, string>> = CHANGE_KIND_LABELS;
  protected readonly kindSeverity: Readonly<Record<string, TagSeverity>> =
    CHANGE_KIND_SEVERITY;
  protected readonly summary = summaryText;
  protected readonly value = changeValue;
  protected readonly label = changeLabel;

  protected readonly sections = computed<Section[]>(() => {
    const diff = this.diff();
    if (!diff) return [];
    const bySection = new Map<string, SnapshotChange[]>();
    for (const c of diff.changes) {
      const key = c.path.split(/[.[]/)[0];
      bySection.set(key, [...(bySection.get(key) ?? []), c]);
    }
    return diff.summary.map((summary) => ({
      key: summary.section,
      label: sectionLabel(summary.section),
      summary,
      changes: bySection.get(summary.section) ?? [],
    }));
  });
}
