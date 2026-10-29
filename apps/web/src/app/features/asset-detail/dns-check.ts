import { DatePipe } from '@angular/common';
import { Component, effect, inject, input, signal } from '@angular/core';
import type { DnsCheckReason, DnsRecordCheck } from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { TagModule } from '@openng/optimus-ui/tag';
import { DomainsApi } from '../../core/api/domains-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';

/** Qué significa cada motivo, para la ficha. */
export const DNS_REASON_TEXT: Record<DnsCheckReason, string> = {
  linked: 'Apunta a un asset del inventario.',
  retired_target:
    'Solo apuntan a esa IP assets retirados o desaparecidos: quizá el servidor ya no existe y otro podría recibir el tráfico.',
  private_unknown:
    'Apunta a una IP privada que no tiene ningún asset del inventario: o falta en el inventario o el registro sobra.',
  public_unknown:
    'Apunta a una IP pública que no está en el inventario. Si es de un tercero (un SaaS, un CDN), márcalo como esperado.',
  cname_internal_missing:
    'Es un CNAME a un nombre de tus zonas que no tiene ningún registro: no resuelve.',
  cname_internal: 'Es un CNAME a otro registro de tus zonas.',
  cname_nxdomain:
    'Es un CNAME a un nombre externo que no existe: quien lo registre recibiría el tráfico de este nombre (subdomain takeover).',
  cname_external: 'Es un CNAME a un nombre externo que resuelve.',
  cname_takeover_service:
    'Es un CNAME a un servicio que responde a cualquier nombre (DNS comodín): que resuelva no prueba que la app siga siendo tuya. Compruébalo y márcalo como esperado si lo es.',
  cname_tunnel: 'Es un CNAME a un túnel de Cloudflare.',
  unchecked: 'No se pudo comprobar (el resolutor no respondió).',
};

/**
 * Comprobación de un registro DNS A, AAAA o CNAME (DESIGN §13): si es colgante, por qué, y
 * «Marcar como esperado» (vale mientras el registro no cambie de valor) o «Reabrir».
 */
@Component({
  selector: 'app-dns-check',
  imports: [DatePipe, ButtonModule, CardModule, TagModule],
  template: `
    @if (check(); as c) {
      <p-card styleClass="card" data-section="dns-check">
        <ng-template #title><i class="bi bi-shield-exclamation" aria-hidden="true"></i> Comprobación</ng-template>
        <p class="usage-line">
          @if (c.accepted) {
            <p-tag value="Esperado" severity="secondary" icon="bi bi-check2-circle" data-dns-level="accepted" />
          } @else if (c.level === 'high') {
            <p-tag value="Colgante" severity="danger" icon="bi bi-exclamation-octagon" data-dns-level="high" />
          } @else if (c.level === 'info') {
            <p-tag value="IP desconocida" severity="secondary" icon="bi bi-question-circle" data-dns-level="info" />
          } @else {
            <p-tag value="Correcto" severity="success" icon="bi bi-check-circle" data-dns-level="ok" />
          }
          @if (c.takeoverService) {
            <p-tag [value]="'Servicio: ' + c.takeoverService" severity="danger" />
          }
          @if (c.ambiguous) {
            <p-tag value="Varios assets con esa IP" severity="warn" />
          }
        </p>
        <p class="reason" data-dns-reason>{{ reasonText[c.reason] }}</p>
        <dl>
          <dt>Destino</dt>
          <dd><code>{{ c.target }}</code></dd>
          <dt>Comprobado</dt>
          <dd>{{ c.checkedAt | date: 'short' }}</dd>
          @if (c.accepted; as a) {
            <dt>Marcado como esperado</dt>
            <dd>{{ a.at | date: 'short' }}@if (a.by) { · {{ a.by }} }</dd>
          }
        </dl>
        @if (canEdit && c.level) {
          <div class="actions">
            @if (c.accepted) {
              <p-button label="Reabrir el aviso" icon="bi bi-arrow-counterclockwise" size="small"
                severity="secondary" [text]="true" [loading]="busy()" (onClick)="reopen()" data-action="reopen-dns" />
            } @else {
              <p-button label="Marcar como esperado" icon="bi bi-check2-circle" size="small"
                severity="secondary" [loading]="busy()" (onClick)="accept()" data-action="accept-dns" />
              @if (c.level === 'info' && c.sameTarget > 1) {
                <p-button [label]="'Marcar los ' + c.sameTarget + ' que apuntan a ' + c.target" icon="bi bi-check2-all"
                  size="small" severity="secondary" [text]="true" [loading]="busy()" (onClick)="acceptTarget(c.target)"
                  data-action="accept-dns-target" />
              }
            }
          </div>
        }
      </p-card>
    }
  `,
  styles: `
    dl {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.4rem 1rem;
      margin: 0;
    }
    dt {
      color: var(--p-text-muted-color);
    }
    dd {
      margin: 0;
      overflow-wrap: anywhere;
    }
    .reason {
      margin: 0 0 0.5rem;
      line-height: 1.45;
    }
    .usage-line {
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem;
      margin: 0 0 0.5rem;
    }
    .actions {
      margin-top: 0.75rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem 0.5rem;
    }
    code {
      overflow-wrap: anywhere;
    }
  `,
})
export class DnsCheckCard {
  private readonly api = inject(DomainsApi);
  private readonly messages = inject(MessageService);
  protected readonly canEdit = inject(AuthService).can('assets.write');
  protected readonly reasonText = DNS_REASON_TEXT;
  readonly assetId = input.required<string>();

  protected readonly check = signal<DnsRecordCheck | null>(null);
  protected readonly busy = signal(false);

  constructor() {
    effect((onCleanup) => {
      const sub = this.api.dnsCheck(this.assetId()).subscribe({
        next: (c) => this.check.set(c),
        error: () => this.check.set(null),
      });
      onCleanup(() => sub.unsubscribe());
    });
  }

  protected accept(): void {
    this.run(this.api.acceptDnsCheck(this.assetId()), 'Marcado como esperado');
  }

  /** Solo los informativos (una IP pública conocida); los de prioridad alta, uno a uno. */
  protected acceptTarget(target: string): void {
    this.busy.set(true);
    this.api.acceptDnsTarget(target).subscribe({
      next: ({ accepted }) => {
        this.messages.add({
          severity: 'success',
          summary: `${accepted} ${accepted === 1 ? 'registro marcado' : 'registros marcados'} como esperados`,
          detail: `Los que apuntan a ${target}`,
          life: 4000,
        });
        this.api.dnsCheck(this.assetId()).subscribe((c) => {
          this.busy.set(false);
          this.check.set(c);
        });
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.messages.add({
          severity: 'error',
          summary: 'Error',
          detail: apiErrorMessage(err, 'No se pudieron marcar.'),
          life: 6000,
        });
      },
    });
  }

  protected reopen(): void {
    this.run(this.api.reopenDnsCheck(this.assetId()), 'Aviso reabierto');
  }

  private run(request: ReturnType<DomainsApi['acceptDnsCheck']>, summary: string): void {
    this.busy.set(true);
    request.subscribe({
      next: (c) => {
        this.busy.set(false);
        this.check.set(c);
        this.messages.add({ severity: 'success', summary, life: 3000 });
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.messages.add({
          severity: 'error',
          summary: 'Error',
          detail: apiErrorMessage(err, 'No se pudo cambiar el aviso.'),
          life: 6000,
        });
      },
    });
  }
}
