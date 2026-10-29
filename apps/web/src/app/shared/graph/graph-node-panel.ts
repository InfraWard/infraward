import { Component, computed, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';
import type { GraphNode } from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TagModule } from '@openng/optimus-ui/tag';
import {
  ASSET_STATUS_LABELS,
  ASSET_STATUS_SEVERITY,
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
  RUNTIME_LABELS,
  RUNTIME_SEVERITY,
} from '../labels';
import { hiddenSummary, hiddenTotal } from './graph-model';

/**
 * Tarjeta del nodo seleccionado en un mapa: qué es, cómo está y qué hacer con él. Flota sobre el
 * lienzo; en móvil, queda debajo como una hoja.
 */
@Component({
  selector: 'app-graph-node-panel',
  imports: [RouterLink, ButtonModule, TagModule],
  template: `
    @let n = node();
    <div class="head">
      <i class="bi {{ icons[n.type] }}" aria-hidden="true"></i>
      <div class="title">
        <strong>{{ n.name }}</strong>
        <span class="muted">{{ types[n.type] }}</span>
      </div>
      <p-button icon="bi bi-x-lg" [text]="true" [rounded]="true" severity="secondary" size="small" ariaLabel="Cerrar" (onClick)="closed.emit()" />
    </div>
    <div class="facts">
      @if (n.runtimeState) {
        <p-tag [value]="runtime[n.runtimeState]" [severity]="runtimeSeverity[n.runtimeState]" />
      }
      @if (n.status !== 'active' || !n.runtimeState) {
        <p-tag [value]="statuses[n.status]" [severity]="statusSeverity[n.status]" />
      }
      @if (n.critical) {
        <p-tag [value]="n.critical + (n.critical === 1 ? ' crítica' : ' críticas')" severity="danger" icon="bi bi-shield-exclamation" />
      }
    </div>
    @if (n.address) {
      <p class="line"><i class="bi bi-geo-alt" aria-hidden="true"></i> {{ n.address }}</p>
    }
    @if (summary()) {
      <p class="line muted" data-hidden-summary>
        <i class="bi bi-eye-slash" aria-hidden="true"></i>
        {{ expandable() ? 'Dentro, sin cargar: ' : 'Más relaciones: ' }}{{ summary() }}
      </p>
    }
    <div class="actions">
      <p-button label="Abrir ficha" icon="bi bi-box-arrow-up-right" size="small" [routerLink]="['/assets', n.id]" data-open />
      @if (canRecenter()) {
        <p-button label="Centrar aquí" icon="bi bi-bullseye" severity="secondary" size="small" (onClick)="recenter.emit(n.id)" data-recenter />
      }
      @if (expandable() && hiddenCount() > 0) {
        <p-button label="Expandir" icon="bi bi-arrows-angle-expand" severity="secondary" size="small" (onClick)="expand.emit(n.id)" data-expand />
      }
      @if (collapsible()) {
        <p-button label="Contraer" icon="bi bi-arrows-angle-contract" severity="secondary" size="small" (onClick)="collapse.emit(n.id)" data-collapse />
      }
    </div>
  `,
  styles: `
    :host {
      display: block;
      width: min(20rem, 100%);
      padding: 0.75rem;
      background: var(--p-content-background);
      border: 1px solid var(--p-content-border-color);
      border-radius: 8px;
      box-shadow: 0 4px 16px rgb(0 0 0 / 0.12);
    }
    .head {
      display: flex;
      gap: 0.5rem;
      align-items: flex-start;
      > i { font-size: 1.25rem; margin-top: 0.1rem; }
    }
    .title {
      flex: 1;
      min-width: 0;
      display: flex;
      flex-direction: column;
      strong { overflow-wrap: anywhere; }
    }
    .muted { color: var(--p-text-muted-color); }
    .facts { display: flex; flex-wrap: wrap; gap: 0.25rem; margin: 0.5rem 0; }
    .line { margin: 0.25rem 0; overflow-wrap: anywhere; }
    .actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
  `,
})
export class GraphNodePanel {
  readonly node = input.required<GraphNode>();
  /** Mapa: «Centrar aquí» (no en el propio centro). */
  readonly canRecenter = input(false);
  /** Topología: «Expandir» lo que tiene dentro. */
  readonly expandable = input(false);
  readonly collapsible = input(false);

  readonly closed = output<void>();
  readonly recenter = output<string>();
  readonly expand = output<string>();
  readonly collapse = output<string>();

  protected readonly icons = ASSET_TYPE_ICONS;
  protected readonly types = ASSET_TYPE_LABELS;
  protected readonly statuses = ASSET_STATUS_LABELS;
  protected readonly statusSeverity = ASSET_STATUS_SEVERITY;
  protected readonly runtime = RUNTIME_LABELS;
  protected readonly runtimeSeverity = RUNTIME_SEVERITY;
  protected readonly hiddenCount = computed(() => hiddenTotal(this.node()));
  protected readonly summary = computed(() => hiddenSummary(this.node()));
}
