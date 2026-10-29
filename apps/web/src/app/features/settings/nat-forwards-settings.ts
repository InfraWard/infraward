import { Component, inject, signal, viewChild, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type {
  AssetSummary,
  NatForward,
  NatForwardInput,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import type { Observable } from 'rxjs';
import { DomainsApi } from '../../core/api/domains-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { AssetPicker } from '../../shared/asset-picker';
import { ASSET_TYPE_ICONS } from '../../shared/labels';

const NAT_TARGET_TYPES = ['server', 'vm', 'lxc', 'container'] as const;

interface Draft {
  id: string | null;
  publicIp: string;
  publicPort: number | null;
  target: AssetSummary | null;
  targetPort: number | null;
  description: string;
}

const EMPTY: Draft = {
  id: null,
  publicIp: '',
  publicPort: 443,
  target: null,
  targetPort: 443,
  description: '',
};

/**
 * Ajustes > Inventario > Reenvíos NAT (QoL-5b, DESIGN §13): la IP pública de un router que no
 * está en el inventario y su puerto llegan a un asset y puerto. Con ellos, el camino de un dominio
 * que apunta a esa IP sigue hasta el servicio. Editable con `policy.write`.
 */
@Component({
  selector: 'app-nat-forwards-settings',
  imports: [
    FormsModule,
    RouterLink,
    ButtonModule,
    CardModule,
    InputNumberModule,
    InputTextModule,
    MessageModule,
    AssetPicker,
  ],
  template: `
    <p-card styleClass="block" data-block="nat-forwards">
      <ng-template #title>Reenvíos NAT</ng-template>
      <p class="text-muted intro">
        Puertos de una IP pública (la del router de casa, de un NAT) que llegan a un asset del
        inventario. Sirven para seguir el camino de los dominios que apuntan a esa IP hasta el
        servicio que los atiende.
      </p>
      @if (items().length) {
        <ul class="list" data-nat-list>
          @for (n of items(); track n.id) {
            <li [attr.data-nat]="n.publicIp + ':' + n.publicPort">
              <code>{{ n.publicIp }}:{{ n.publicPort }}</code>@if (n.proto === 'udp') { <span class="muted">/udp</span> }
              <i class="bi bi-arrow-right" aria-hidden="true"></i>
              <a [routerLink]="['/assets', n.target.id]"><i class="bi {{ typeIcons[n.target.type] }}" aria-hidden="true"></i> {{ n.target.name }}</a><code>:{{ n.targetPort }}</code>
              @if (n.description) { <span class="muted small">· {{ n.description }}</span> }
              @if (canEdit) {
                <span class="row-actions">
                  <p-button icon="bi bi-pencil" size="small" severity="secondary" [text]="true"
                    [attr.aria-label]="'Editar ' + n.publicIp + ':' + n.publicPort" (onClick)="edit(n)" />
                  <p-button icon="bi bi-trash" size="small" severity="danger" [text]="true"
                    [attr.aria-label]="'Borrar ' + n.publicIp + ':' + n.publicPort" (onClick)="remove(n)"
                    data-action="delete-nat" />
                </span>
              }
            </li>
          }
        </ul>
      } @else {
        <p class="muted small" data-nat-empty>No hay ningún reenvío declarado.</p>
      }
      @if (canEdit) {
        <form class="form" (ngSubmit)="save()" data-nat-form>
          <div class="field">
            <label for="nat-ip">IP pública</label>
            <input pInputText id="nat-ip" name="publicIp" [(ngModel)]="draft.publicIp"
              placeholder="203.0.113.7" autocomplete="off" />
          </div>
          <div class="field port">
            <label for="nat-port">Puerto</label>
            <p-inputnumber inputId="nat-port" name="publicPort" [(ngModel)]="draft.publicPort" [min]="1"
              [max]="65535" [useGrouping]="false" (onInput)="draft.publicPort = toPort($event.value)" />
          </div>
          <div class="field target">
            <label for="nat-target">Llega a</label>
            @if (draft.target; as t) {
              <span class="picked"><i class="bi {{ typeIcons[t.type] }}" aria-hidden="true"></i> {{ t.name }}
                <button type="button" class="link" (click)="draft.target = null">cambiar</button></span>
            } @else {
              <app-asset-picker inputId="nat-target" [types]="targetTypes"
                placeholder="Servidor, CT o contenedor" (picked)="draft.target = $event" />
            }
          </div>
          <div class="field port">
            <label for="nat-target-port">Puerto</label>
            <p-inputnumber inputId="nat-target-port" name="targetPort" [(ngModel)]="draft.targetPort" [min]="1"
              [max]="65535" [useGrouping]="false" (onInput)="draft.targetPort = toPort($event.value)" />
          </div>
          <div class="field grow">
            <label for="nat-desc">Nota (opcional)</label>
            <input pInputText id="nat-desc" name="description" [(ngModel)]="draft.description" maxlength="255"
              placeholder="Router de casa" />
          </div>
          <div class="buttons">
            <p-button type="submit" [label]="draft.id ? 'Guardar' : 'Añadir'" [icon]="draft.id ? 'bi bi-check-lg' : 'bi bi-plus-lg'"
              size="small" [loading]="busy()" [disabled]="!valid()" data-action="save-nat" />
            @if (draft.id) {
              <p-button label="Cancelar" size="small" severity="secondary" [text]="true" (onClick)="reset()" />
            }
          </div>
        </form>
      }
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      }
    </p-card>
  `,
  styles: `
    .intro { margin: 0 0 0.75rem; }
    .list { list-style: none; margin: 0 0 0.75rem; padding: 0; display: grid; gap: 0.35rem; }
    .list li { display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem; overflow-wrap: anywhere; }
    .row-actions { margin-left: auto; display: inline-flex; }
    .form { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: flex-end; }
    .field { display: flex; flex-direction: column; gap: 0.25rem; min-width: 0; }
    .field label { font-size: 0.85rem; color: var(--p-text-muted-color); }
    .field.port { width: 6.5rem; }
    .field.port ::ng-deep input { width: 100%; }
    .field.target { flex: 1 1 14rem; }
    .field.grow { flex: 1 1 10rem; }
    .picked { display: inline-flex; gap: 0.35rem; align-items: center; min-height: 2.25rem; }
    .link { border: 0; background: none; color: var(--p-primary-color); cursor: pointer; padding: 0; }
    .buttons { display: flex; gap: 0.4rem; }
    .muted { color: var(--p-text-muted-color); }
    .small { font-size: 0.85em; }
    @media (max-width: 640px) {
      .field, .field.port, .field.target, .field.grow { flex: 1 1 100%; width: 100%; }
    }
  `,
})
export class NatForwardsSettings implements OnInit {
  private readonly api = inject(DomainsApi);
  private readonly messages = inject(MessageService);
  protected readonly canEdit = inject(AuthService).can('policy.write');
  protected readonly typeIcons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
  protected readonly targetTypes = NAT_TARGET_TYPES;
  private readonly picker = viewChild(AssetPicker);

  protected readonly items = signal<NatForward[]>([]);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected draft: Draft = { ...EMPTY };

  ngOnInit(): void {
    this.load();
  }

  protected toPort(value: unknown): number | null {
    const n = Number(value);
    return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
  }

  protected valid(): boolean {
    const d = this.draft;
    return !!d.publicIp.trim() && !!d.publicPort && !!d.target && !!d.targetPort;
  }

  protected edit(n: NatForward): void {
    this.draft = {
      id: n.id,
      publicIp: n.publicIp,
      publicPort: n.publicPort,
      target: n.target,
      targetPort: n.targetPort,
      description: n.description ?? '',
    };
  }

  protected reset(): void {
    this.draft = { ...EMPTY };
    this.picker()?.clear();
  }

  protected save(): void {
    if (!this.valid()) return;
    const d = this.draft;
    const body: NatForwardInput = {
      publicIp: d.publicIp.trim(),
      publicPort: d.publicPort!,
      targetAssetId: d.target!.id,
      targetPort: d.targetPort!,
      description: d.description.trim() || null,
    };
    this.run(
      d.id ? this.api.updateNatForward(d.id, body) : this.api.createNatForward(body),
      d.id ? 'Reenvío guardado' : 'Reenvío añadido',
    );
  }

  protected remove(n: NatForward): void {
    this.run(this.api.deleteNatForward(n.id), `Reenvío ${n.publicIp}:${n.publicPort} borrado`);
  }

  private run(request: Observable<unknown>, summary: string): void {
    this.busy.set(true);
    this.error.set(null);
    request.subscribe({
      next: () => {
        this.busy.set(false);
        this.reset();
        this.messages.add({
          severity: 'success',
          summary,
          detail: 'Los caminos de los dominios se han recalculado.',
          life: 3000,
        });
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudo guardar el reenvío.'));
      },
    });
  }

  private load(): void {
    this.api.natForwards().subscribe({
      next: (items) => this.items.set(items),
      error: (err: unknown) =>
        this.error.set(apiErrorMessage(err, 'No se pudieron leer los reenvíos.')),
    });
  }
}
