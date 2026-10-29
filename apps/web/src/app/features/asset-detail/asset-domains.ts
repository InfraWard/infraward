import { Component, computed, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import type { AssetDomainRecord } from '@infraward/shared-types';
import { CardModule } from '@openng/optimus-ui/card';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { DomainsApi } from '../../core/api/domains-api';
import { ExpiryThresholds } from '../../core/expiry-thresholds';
import { expiryTag } from '../inventory/tree-nodes';

/** Como mucho, los que caben en el resumen (el resto, en Relaciones). */
const MAX_SHOWN = 12;

/**
 * «Dominios que le apuntan» (DESIGN §13): registros DNS que llegan al servidor, VM o CT, directos
 * (A/AAAA a una de sus IPs) o a través de CNAME, con su certificado del 443. No se pinta si no
 * hay ninguno.
 */
@Component({
  selector: 'app-asset-domains',
  imports: [RouterLink, CardModule, TagModule, TooltipModule],
  template: `
    @if (records().length) {
      <p-card styleClass="card" data-section="domains">
        <ng-template #title>
          <i class="bi bi-globe2" aria-hidden="true"></i> Dominios que le apuntan ({{ records().length }})
        </ng-template>
        <ul class="records">
          @for (r of shown(); track r.record.id) {
            <li [attr.data-record]="r.dns.name">
              <div class="line">
                <a [routerLink]="['/assets', r.record.id]" class="record-name">{{ r.dns.name }}</a>
                <span class="record-type">{{ r.dns.type }}</span>
                @if (r.dns.proxied) {
                  <i class="bi bi-cloud-fill proxied" pTooltip="Pasa por el proxy de Cloudflare"
                    aria-label="Con proxy de Cloudflare"></i>
                }
                @if (r.record.status !== 'active') {
                  <p-tag value="Desaparecido" severity="warn" />
                }
                @if (expiryOf(r); as e) {
                  <p-tag [value]="'cert. ' + e.label" [severity]="e.severity" icon="bi bi-patch-check"
                    styleClass="nowrap-tag" [pTooltip]="r.certificate!.name" data-cert-expiry />
                }
              </div>
              @if (r.via.length) {
                <span class="via">vía {{ viaText(r) }}</span>
              }
            </li>
          }
        </ul>
        @if (records().length > shown().length) {
          <p class="muted small">y {{ records().length - shown().length }} más en Relaciones.</p>
        }
      </p-card>
    }
  `,
  styles: `
    a {
      color: var(--p-primary-color);
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    .records {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 0.5rem;
    }
    .line {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      gap: 0.35rem;
    }
    .record-name {
      overflow-wrap: anywhere;
      font-weight: 500;
    }
    .record-type {
      font-family: var(--p-font-family-mono, monospace);
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
    }
    .proxied {
      color: var(--p-orange-500);
    }
    .via {
      display: block;
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
      overflow-wrap: anywhere;
    }
  `,
})
export class AssetDomainsCard {
  private readonly api = inject(DomainsApi);
  private readonly expiry = inject(ExpiryThresholds);
  readonly assetId = input.required<string>();

  protected readonly records = signal<AssetDomainRecord[]>([]);
  protected readonly shown = computed(() => this.records().slice(0, MAX_SHOWN));

  constructor() {
    this.expiry.load();
    effect((onCleanup) => {
      const sub = this.api.domainsOf(this.assetId()).subscribe({
        next: (d) => this.records.set(d.records),
        error: () => this.records.set([]),
      });
      onCleanup(() => sub.unsubscribe());
    });
  }

  protected expiryOf(r: AssetDomainRecord) {
    const at = r.certificate?.notAfter;
    return at ? expiryTag(at, this.expiry.days()) : null;
  }

  protected viaText(r: AssetDomainRecord): string {
    return r.via.map((v) => v.name.replace(/ · [A-Z]+$/, '')).join(' → ');
  }
}
