import { DatePipe } from '@angular/common';
import { Component, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  SERVICE_PIN_TARGET_TYPES,
  type AssetSummary,
  type ServicePathView,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { TagModule } from '@openng/optimus-ui/tag';
import type { Observable } from 'rxjs';
import { DomainsApi } from '../../core/api/domains-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { AssetPicker } from '../../shared/asset-picker';
import {
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
  SERVICE_CUT_TEXT,
  SERVICE_RESOLVER_ICONS,
  SERVICE_RESOLVER_LABELS,
  SERVICE_STATUS_LABELS,
  SERVICE_STATUS_SEVERITY,
} from '../../shared/labels';

/**
 * Qué sirve un registro DNS (QoL-5b): el camino eslabón a eslabón (registro → IP → asset →
 * proceso o proxy → destino), con el origen y la confianza de cada uno; si se corta, hasta dónde
 * llegó y por qué, y «Fijar destino» a mano.
 */
@Component({
  selector: 'app-service-path',
  imports: [DatePipe, RouterLink, ButtonModule, CardModule, TagModule, AssetPicker],
  template: `
    @if (path(); as p) {
      <p-card styleClass="card" data-section="service-path">
        <ng-template #title><i class="bi bi-signpost-split" aria-hidden="true"></i> Servido por</ng-template>
        <p class="usage-line">
          <p-tag [value]="statusLabels[p.status]" [severity]="statusSeverity[p.status]" [attr.data-path-status]="p.status" />
          @if (p.confidence && p.status !== 'manual') {
            <p-tag [value]="p.confidence === 'confirmed' ? 'Confirmado' : 'Deducido'"
              [severity]="p.confidence === 'confirmed' ? 'success' : 'secondary'"
              [icon]="p.confidence === 'confirmed' ? 'bi bi-patch-check' : 'bi bi-lightbulb'" />
          }
        </p>
        @if (p.final; as f) {
          <p class="final" data-path-final>
            <i class="bi {{ typeIcons[f.type] }}" aria-hidden="true"></i>
            <a [routerLink]="['/assets', f.id]">{{ f.name }}</a>
            <span class="muted small">· {{ typeLabels[f.type] }}</span>
          </p>
        }
        @if (p.hops.length) {
          <ol class="hops" aria-label="Camino">
            <li class="hop start"><i class="bi bi-globe2" aria-hidden="true"></i><code>{{ p.record }}</code></li>
            @for (h of p.hops; track $index) {
              <li class="hop" [attr.data-hop]="h.resolver" [class.deduced]="h.confidence === 'deduced'">
                <i class="bi {{ resolverIcons[h.resolver] }}" aria-hidden="true" [title]="resolverLabels[h.resolver]"></i>
                <div>
                  @if (h.asset; as a) {
                    <a [routerLink]="['/assets', a.id]">{{ h.label }}</a>
                  } @else {
                    <code>{{ h.label }}</code>
                  }
                  <span class="muted small"> · {{ resolverLabels[h.resolver] }}@if (h.confidence === 'deduced') { · deducido }</span>
                  <div class="source muted small">{{ h.source }}</div>
                </div>
              </li>
            }
            @if (p.cutReason) {
              <li class="hop cut" data-path-cut>
                <i class="bi bi-x-octagon" aria-hidden="true"></i>
                <div>Se corta aquí. <span class="muted">{{ cutText[p.cutReason] }}</span></div>
              </li>
            }
          </ol>
        } @else if (p.cutReason) {
          <p class="muted" data-path-cut>{{ cutText[p.cutReason] }}</p>
        }
        @if (p.pinned; as pin) {
          <p class="muted small">Fijado a mano {{ pin.at | date: 'short' }}@if (pin.by) { por {{ pin.by }} }. Gana al camino calculado, que se sigue mostrando arriba.</p>
        }
        @if (canEdit) {
          <div class="actions">
            @if (p.pinned) {
              <p-button label="Quitar el destino fijado" icon="bi bi-pin" size="small" severity="secondary"
                [text]="true" [loading]="busy()" (onClick)="unpin()" data-action="unpin-path" />
            } @else if (!picking()) {
              <p-button label="Fijar el destino" icon="bi bi-pin-angle" size="small" severity="secondary"
                [text]="p.status === 'complete'" [loading]="busy()" (onClick)="picking.set(true)" data-action="pin-path" />
            } @else {
              <label class="pick-label" for="service-path-pin">Asset que sirve este nombre</label>
              <app-asset-picker inputId="service-path-pin" [types]="pinTypes"
                placeholder="Servidor, CT, contenedor…" (picked)="pin($event)" />
              <p-button label="Cancelar" size="small" severity="secondary" [text]="true" (onClick)="picking.set(false)" />
            }
          </div>
        }
        @if (p.computedAt) {
          <p class="muted small computed">Calculado {{ p.computedAt | date: 'short' }}</p>
        }
      </p-card>
    }
  `,
  styles: `
    .usage-line { display: flex; flex-wrap: wrap; gap: 0.35rem; margin: 0 0 0.5rem; }
    .final { display: flex; gap: 0.4rem; align-items: center; font-weight: 600; margin: 0 0 0.6rem; }
    .hops { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.15rem; }
    .hop {
      display: grid;
      grid-template-columns: 1.4rem 1fr;
      gap: 0.4rem;
      padding: 0.3rem 0 0.3rem 0.1rem;
      border-left: 2px solid var(--p-primary-color);
      padding-left: 0.6rem;
      overflow-wrap: anywhere;
    }
    .hop.deduced { border-left-style: dashed; }
    .hop.start { border-left-color: var(--graph-type-dns_record, var(--p-content-border-color)); }
    .hop.cut { border-left-color: var(--p-app-danger-color, #dc2626); color: var(--p-app-danger-color, #dc2626); }
    .source { margin-top: 0.1rem; }
    .muted { color: var(--p-text-muted-color); }
    .small { font-size: 0.85em; }
    .actions { margin-top: 0.75rem; display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; }
    .pick-label { width: 100%; font-size: 0.85rem; color: var(--p-text-muted-color); }
    app-asset-picker { flex: 1 1 14rem; min-width: 0; }
    .computed { margin: 0.6rem 0 0; }
    code { overflow-wrap: anywhere; }
  `,
})
export class ServicePathCard {
  private readonly api = inject(DomainsApi);
  private readonly messages = inject(MessageService);
  protected readonly canEdit = inject(AuthService).can('assets.write');
  readonly assetId = input.required<string>();

  protected readonly path = signal<ServicePathView | null>(null);
  protected readonly busy = signal(false);
  protected readonly picking = signal(false);
  protected readonly pinTypes = SERVICE_PIN_TARGET_TYPES;
  protected readonly typeIcons = ASSET_TYPE_ICONS;
  protected readonly typeLabels = ASSET_TYPE_LABELS;
  protected readonly resolverIcons = SERVICE_RESOLVER_ICONS;
  protected readonly resolverLabels = SERVICE_RESOLVER_LABELS;
  protected readonly statusLabels = SERVICE_STATUS_LABELS;
  protected readonly statusSeverity = SERVICE_STATUS_SEVERITY;
  protected readonly cutText = SERVICE_CUT_TEXT;

  constructor() {
    effect((onCleanup) => {
      const sub = this.api.servicePath(this.assetId()).subscribe({
        next: (p) => this.path.set(p),
        error: () => this.path.set(null),
      });
      onCleanup(() => sub.unsubscribe());
    });
  }

  protected pin(asset: AssetSummary): void {
    this.run(this.api.pinServicePath(this.assetId(), asset.id), `Destino fijado: ${asset.name}`);
  }

  protected unpin(): void {
    this.run(this.api.unpinServicePath(this.assetId()), 'Destino sin fijar');
  }

  private run(request: Observable<ServicePathView>, summary: string): void {
    this.busy.set(true);
    request.subscribe({
      next: (p) => {
        this.busy.set(false);
        this.picking.set(false);
        this.path.set(p);
        this.messages.add({ severity: 'success', summary, life: 3000 });
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.messages.add({
          severity: 'error',
          summary: 'Error',
          detail: apiErrorMessage(err, 'No se pudo cambiar el destino.'),
          life: 6000,
        });
      },
    });
  }
}
