import { Component, computed, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import type { ServedDomain, ServicePathView } from '@infraward/shared-types';
import { CardModule } from '@openng/optimus-ui/card';
import { TagModule } from '@openng/optimus-ui/tag';
import { DomainsApi } from '../../core/api/domains-api';
import {
  ASSET_TYPE_ICONS,
  SERVICE_CUT_TEXT,
  SERVICE_STATUS_LABELS,
  SERVICE_STATUS_SEVERITY,
} from '../../shared/labels';

/**
 * Nombres que sirve un asset (destino final de su camino) y los que pasan por él (un proxy, un
 * host que publica un puerto), QoL-5b. No sale si no hay ninguno.
 */
@Component({
  selector: 'app-served-domains',
  imports: [RouterLink, CardModule, TagModule],
  template: `
    @if (final().length || via().length) {
      <p-card styleClass="card" data-section="served-domains">
        <ng-template #title><i class="bi bi-signpost-split" aria-hidden="true"></i> Dominios que sirve</ng-template>
        @if (final().length) {
          <ul class="list" data-served="final">
            @for (r of final(); track r.record.id) {
              <li>
                <i class="bi bi-globe2" aria-hidden="true"></i>
                <a [routerLink]="['/assets', r.record.id]">{{ r.record.name }}</a>
                @if (r.status === 'manual') {
                  <p-tag value="Fijado a mano" severity="info" />
                } @else if (r.confidence === 'deduced') {
                  <p-tag value="Deducido" severity="secondary" />
                }
              </li>
            }
          </ul>
        } @else {
          <p class="muted small">Ninguno lo tiene como destino final.</p>
        }
        @if (via().length) {
          <h4>Por aquí pasan</h4>
          <ul class="list" data-served="via">
            @for (r of via(); track r.record.id) {
              <li>
                <i class="bi bi-arrow-right-circle" aria-hidden="true"></i>
                <a [routerLink]="['/assets', r.record.id]">{{ r.record.name }}</a>
                @if (r.final; as f) {
                  <span class="muted small">→ <i class="bi {{ typeIcons[f.type] }}" aria-hidden="true"></i>
                    <a [routerLink]="['/assets', f.id]">{{ f.name }}</a></span>
                } @else {
                  <p-tag [value]="statusLabels[r.status]" [severity]="statusSeverity[r.status]" />
                }
              </li>
            }
          </ul>
        }
      </p-card>
    }
  `,
  styles: `
    .list { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.35rem; }
    li { display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; overflow-wrap: anywhere; }
    h4 { margin: 0.9rem 0 0.4rem; font-size: 0.9rem; color: var(--p-text-muted-color); font-weight: 600; }
    .muted { color: var(--p-text-muted-color); }
    .small { font-size: 0.85em; }
  `,
})
export class ServedDomainsCard {
  private readonly api = inject(DomainsApi);
  readonly assetId = input.required<string>();
  private readonly records = signal<ServedDomain[]>([]);
  protected readonly final = computed(() => this.records().filter((r) => r.role === 'final'));
  protected readonly via = computed(() => this.records().filter((r) => r.role === 'via'));
  protected readonly typeIcons = ASSET_TYPE_ICONS;
  protected readonly statusLabels = SERVICE_STATUS_LABELS;
  protected readonly statusSeverity = SERVICE_STATUS_SEVERITY;

  constructor() {
    effect((onCleanup) => {
      const sub = this.api.servedDomains(this.assetId()).subscribe({
        next: (r) => this.records.set(r.records),
        error: () => this.records.set([]),
      });
      onCleanup(() => sub.unsubscribe());
    });
  }
}

/** Qué sirve cada registro de un dominio (QoL-5b): destino final y estado de su camino. */
@Component({
  selector: 'app-domain-service-paths',
  imports: [RouterLink, CardModule, TagModule],
  template: `
    @if (paths().length) {
      <p-card styleClass="card" data-section="domain-service-paths">
        <ng-template #title><i class="bi bi-signpost-split" aria-hidden="true"></i> Qué sirve cada nombre</ng-template>
        <table class="mini">
          <thead>
            <tr>
              <th scope="col">Registro</th>
              <th scope="col">Servido por</th>
              <th scope="col">Camino</th>
            </tr>
          </thead>
          <tbody>
            @for (p of shown(); track p.recordId) {
              <tr [attr.data-path-record]="p.record">
                <td><a [routerLink]="['/assets', p.recordId]">{{ p.record }}</a></td>
                <td>
                  @if (p.final; as f) {
                    <i class="bi {{ typeIcons[f.type] }}" aria-hidden="true"></i>
                    <a [routerLink]="['/assets', f.id]">{{ f.name }}</a>
                  } @else if (p.cutReason) {
                    <span class="muted small" [title]="cutText[p.cutReason]">{{ lastHop(p) }}</span>
                  } @else {
                    <span class="muted">—</span>
                  }
                </td>
                <td>
                  <p-tag [value]="statusLabels[p.status]" [severity]="statusSeverity[p.status]" />
                  @if (p.confidence === 'deduced' && p.status === 'complete') {
                    <span class="muted small"> deducido</span>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
        @if (paths().length > shown().length) {
          <p class="muted small">Y {{ paths().length - shown().length }} más (sin destino).</p>
        }
      </p-card>
    }
  `,
  styles: `
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th { text-align: left; font-weight: 600; color: var(--p-text-muted-color); padding: 0.3rem 0.4rem; }
    td { padding: 0.3rem 0.4rem; border-top: 1px solid var(--p-content-border-color); overflow-wrap: anywhere; vertical-align: top; }
    .muted { color: var(--p-text-muted-color); }
    .small { font-size: 0.85em; }
  `,
})
export class DomainServicePathsCard {
  private readonly api = inject(DomainsApi);
  readonly assetId = input.required<string>();
  protected readonly paths = signal<ServicePathView[]>([]);
  /** Primero lo que llega a algún sitio; los registros sin destino (TXT a terceros…) al final. */
  protected readonly shown = computed(() => {
    const order = { complete: 0, manual: 0, partial: 1, none: 2 } as const;
    return [...this.paths()]
      .sort((a, b) => order[a.status] - order[b.status] || a.record.localeCompare(b.record))
      .filter((p, i) => p.status !== 'none' || i < 25)
      .slice(0, 50);
  });
  protected readonly typeIcons = ASSET_TYPE_ICONS;
  protected readonly statusLabels = SERVICE_STATUS_LABELS;
  protected readonly statusSeverity = SERVICE_STATUS_SEVERITY;
  protected readonly cutText = SERVICE_CUT_TEXT;

  constructor() {
    effect((onCleanup) => {
      const sub = this.api.servicePaths(this.assetId()).subscribe({
        next: (r) => this.paths.set(r.paths),
        error: () => this.paths.set([]),
      });
      onCleanup(() => sub.unsubscribe());
    });
  }

  /** Hasta dónde llegó un camino cortado. */
  protected lastHop(p: ServicePathView): string {
    const last = p.hops.at(-1);
    return last ? `hasta ${last.label}` : 'sin destino';
  }
}
