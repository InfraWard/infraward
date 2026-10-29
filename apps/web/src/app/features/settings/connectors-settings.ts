import { DatePipe } from '@angular/common';
import { Component, inject, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  CONNECTOR_TOKEN_MAX_LENGTH,
  CONNECTOR_TOKEN_MIN_LENGTH,
  DOMAIN_PROVIDERS,
  type Connector,
  type ConnectorVerification,
  type DomainProviderInfo,
  type DomainProviderKind,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import type { Observable } from 'rxjs';
import { DomainsApi } from '../../core/api/domains-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';

/**
 * Ajustes > Conectores (`connectors.write`, DESIGN §13): proveedores de dominios, sacados del
 * catálogo `DOMAIN_PROVIDERS` (añadir uno no toca esta pantalla); varios conectores del mismo
 * proveedor = varias cuentas o tokens. El token solo
 * se escribe aquí (campo de contraseña), viaja una vez a la API, que lo guarda en el proveedor de
 * secretos, y no vuelve a salir: la web nunca lo muestra ni lo guarda.
 */
@Component({
  selector: 'app-connectors-settings',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    ButtonModule,
    CardModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    TagModule,
    TooltipModule,
  ],
  template: `
    <p-card styleClass="block" data-block="connectors">
      <ng-template #title>
        <div class="title">
          <span>Conectores de dominios</span>
          <p-button label="Nuevo conector" icon="bi bi-plus-lg" size="small"
            (onClick)="openCreate()" data-action="new-connector" />
        </div>
      </ng-template>
      <p class="text-muted intro">
        Inventaría tus dominios y registros DNS (solo lectura) y los enlaza con los servidores a los
        que apuntan. Se sincronizan con la reconciliación periódica (política de inventario).
      </p>
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      } @else if (loading()) {
        <p class="text-muted">Cargando…</p>
      } @else {
        <ul class="connectors">
          @for (c of connectors(); track c.id) {
            <li [attr.data-connector]="c.name">
              <div class="head">
                <a [routerLink]="['/assets', c.id]" class="name">
                  <i class="bi {{ info(c.kind).icon }}" aria-hidden="true"></i> {{ c.name }}
                </a>
                <p-tag [value]="info(c.kind).label" severity="secondary" data-provider-kind />
                @if (c.verify; as v) {
                  @if (v.ok) {
                    <p-tag value="Token válido" severity="success" icon="bi bi-check-circle" data-verify="ok" />
                  } @else {
                    <p-tag value="Token no válido" severity="danger" icon="bi bi-x-circle" data-verify="error" />
                  }
                } @else {
                  <p-tag value="Sin probar" severity="warn" icon="bi bi-hourglass-split" />
                }
              </div>
              <dl class="facts">
                <div><dt>Dominios</dt><dd>{{ c.domains }}</dd></div>
                <div><dt>Registros</dt><dd>{{ c.records }}</dd></div>
                <div><dt>Token</dt><dd>
                  @if (c.hasToken) {
                    guardado en <code>{{ c.secretProvider }}</code>
                  } @else {
                    —
                  }
                </dd></div>
                <div><dt>Última sincronización</dt><dd>
                  @if (c.lastSync; as s) {
                    {{ s.at | date: 'short' }}@if (!s.complete) { <span class="warn"> (parcial)</span> }
                  } @else {
                    nunca
                  }
                </dd></div>
              </dl>
              @if (c.verify; as v) {
                @if (!v.ok) {
                  <p-message severity="error" icon="bi bi-exclamation-triangle" data-verify-error>
                    {{ v.error }}
                  </p-message>
                }
                @for (w of v.warnings; track w) {
                  <p-message severity="warn" icon="bi bi-exclamation-circle">{{ w }}</p-message>
                }
              }
              <div class="actions">
                <p-button label="Probar" icon="bi bi-plug" size="small" severity="secondary"
                  [loading]="busy() === c.id + ':test'" (onClick)="test(c)" data-action="test" />
                @if (auth.can('assets.operate')) {
                  <p-button label="Sincronizar" icon="bi bi-arrow-repeat" size="small" severity="secondary"
                    [disabled]="!c.verify?.ok" [loading]="busy() === c.id + ':sync'" (onClick)="sync(c)"
                    data-action="sync" />
                }
                <p-button label="Reemplazar token" icon="bi bi-key" size="small" severity="secondary" [text]="true"
                  (onClick)="openReplace(c)" data-action="replace-token" />
                <p-button label="Dar de baja" icon="bi bi-trash" size="small" severity="danger" [text]="true"
                  (onClick)="remove(c)" data-action="delete-connector" />
              </div>
            </li>
          } @empty {
            <li class="text-muted empty">Aún no hay conectores.</li>
          }
        </ul>
      }
    </p-card>

    <p-dialog [header]="replacing() ? 'Reemplazar el token de ' + replacing()!.name : 'Nuevo conector de dominios'"
      [visible]="formOpen()" (visibleChange)="formOpen.set($event)" [modal]="true"
      [style]="{ width: 'min(34rem, 95vw)' }" data-dialog="connector">
      <form class="form" (ngSubmit)="save()">
        @if (!replacing()) {
          <span class="label" id="connector-kind">Proveedor</span>
          <div class="kinds" role="radiogroup" aria-labelledby="connector-kind">
            @for (p of providers; track p.kind) {
              <button type="button" class="kind" role="radio" [attr.aria-checked]="draft.kind === p.kind"
                [class.selected]="draft.kind === p.kind" (click)="draft.kind = p.kind" [attr.data-kind]="p.kind">
                <i class="bi {{ p.icon }}" aria-hidden="true"></i>
                <span><strong>{{ p.label }}</strong><small>{{ p.description }}</small></span>
              </button>
            }
          </div>
          <label for="connector-name">Nombre</label>
          <input pInputText id="connector-name" name="name" autocomplete="off" maxlength="100"
            [(ngModel)]="draft.name" [placeholder]="selected().label + ' · producción'" />
        }
        <label for="connector-token">{{ selected().credentialLabel }}</label>
        <input pInputText id="connector-token" name="token" type="password" autocomplete="off"
          spellcheck="false" [maxlength]="maxToken" [(ngModel)]="draft.token" data-field="token" />
        <small class="text-muted" data-token-help>
          Créalo en {{ selected().label }} ({{ selected().credentialWhere }}) de <strong>solo lectura</strong>, con
          @for (perm of selected().permissions; track perm; let last = $last) {
            <code>{{ perm }}</code>{{ last ? '' : ' y ' }}
          }
          sobre lo que quieras inventariar
          (<a [href]="selected().docsUrl" target="_blank" rel="noopener noreferrer">cómo</a>).
          Se guarda en el proveedor de secretos y no se vuelve a mostrar. Para otra cuenta, añade otro conector.
        </small>
        @if (formError(); as message) {
          <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
        }
        <button type="submit" hidden></button>
      </form>
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="formOpen.set(false)" />
        <p-button [label]="replacing() ? 'Guardar y probar' : 'Crear y probar'" icon="bi bi-check-lg"
          [loading]="busy() === 'form'" (onClick)="save()" data-action="save-connector" />
      </ng-template>
    </p-dialog>
  `,
  styles: `
    .title {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      justify-content: space-between;
    }
    .intro {
      margin: 0 0 1rem;
    }
    .connectors {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 1rem;
    }
    .connectors > li:not(.empty) {
      border: 1px solid var(--p-content-border-color);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      display: grid;
      gap: 0.6rem;
    }
    .head {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .name {
      font-weight: 600;
      margin-right: 0.25rem;
    }
    .facts {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1.5rem;
      margin: 0;
    }
    .facts dt {
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
    }
    .facts dd {
      margin: 0;
    }
    .warn {
      color: var(--p-app-warn-color);
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem 0.5rem;
    }
    .form {
      display: grid;
      gap: 0.4rem;
    }
    .form label, .form .label {
      font-weight: 600;
      margin-top: 0.5rem;
    }
    .kinds {
      display: grid;
      gap: 0.5rem;
    }
    .kind {
      display: flex;
      gap: 0.75rem;
      align-items: flex-start;
      text-align: left;
      padding: 0.6rem 0.75rem;
      border: 1px solid var(--p-content-border-color);
      border-radius: 8px;
      background: none;
      color: inherit;
      cursor: pointer;
      font: inherit;
    }
    .kind i {
      font-size: 1.25rem;
    }
    .kind small {
      display: block;
      color: var(--p-text-muted-color);
    }
    .kind.selected {
      border-color: var(--p-primary-color);
      box-shadow: inset 0 0 0 1px var(--p-primary-color);
    }
    .form small {
      display: block;
      line-height: 1.45;
    }
  `,
})
export class ConnectorsSettings implements OnInit {
  private readonly api = inject(DomainsApi);
  private readonly messages = inject(MessageService);
  private readonly confirm = inject(ConfirmationService);
  protected readonly auth = inject(AuthService);
  protected readonly maxToken = CONNECTOR_TOKEN_MAX_LENGTH;

  protected readonly connectors = signal<Connector[]>([]);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);
  /** Qué está en curso: `form`, `<id>:test` o `<id>:sync`. */
  protected readonly busy = signal<string | null>(null);
  protected readonly formOpen = signal(false);
  protected readonly replacing = signal<Connector | null>(null);
  protected readonly formError = signal<string | null>(null);
  protected readonly providers: DomainProviderInfo[] = Object.values(DOMAIN_PROVIDERS);
  protected draft: { kind: DomainProviderKind; name: string; token: string } = {
    kind: 'cloudflare',
    name: '',
    token: '',
  };

  protected info(kind: DomainProviderKind): DomainProviderInfo {
    return DOMAIN_PROVIDERS[kind] ?? DOMAIN_PROVIDERS.cloudflare;
  }

  /** Proveedor del alta (o del conector cuyo token se reemplaza). */
  protected selected(): DomainProviderInfo {
    return this.info(this.replacing()?.kind ?? this.draft.kind);
  }

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.api.connectors().subscribe({
      next: (list) => {
        this.connectors.set(list);
        this.loading.set(false);
      },
      error: (err: unknown) => {
        this.loading.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudieron cargar los conectores.'));
      },
    });
  }

  protected openCreate(): void {
    this.replacing.set(null);
    this.draft = { kind: this.providers[0].kind, name: '', token: '' };
    this.formError.set(null);
    this.formOpen.set(true);
  }

  protected openReplace(c: Connector): void {
    this.replacing.set(c);
    this.draft = { kind: c.kind, name: c.name, token: '' };
    this.formError.set(null);
    this.formOpen.set(true);
  }

  protected save(): void {
    if (this.busy() === 'form') return;
    const name = this.draft.name.trim();
    const token = this.draft.token.trim();
    const replacing = this.replacing();
    if (!replacing && !name) return this.formError.set('Escribe un nombre.');
    if (token.length < CONNECTOR_TOKEN_MIN_LENGTH)
      return this.formError.set('Pega el token completo.');
    // El token sale del formulario en cuanto se envía.
    this.draft.token = '';
    const request = replacing
      ? this.api.replaceToken(replacing.id, token)
      : this.api.createConnector({ kind: this.draft.kind, name, apiToken: token });
    this.run('form', request, (c) => {
      this.formOpen.set(false);
      this.announce(c.verify, c.name, !replacing);
    }, (m) => this.formError.set(m));
  }

  protected test(c: Connector): void {
    this.run(`${c.id}:test`, this.api.testConnector(c.id), ({ verify }) =>
      this.announce(verify, c.name, false),
    );
  }

  protected sync(c: Connector): void {
    this.run(`${c.id}:sync`, this.api.syncConnector(c.id), () =>
      this.messages.add({
        severity: 'info',
        summary: 'Sincronización en cola',
        detail: `${c.name}: sigue su progreso en la Actividad.`,
        life: 4000,
      }),
    );
  }

  protected remove(c: Connector): void {
    this.confirm.confirm({
      header: 'Dar de baja el conector',
      message: `${c.name}, sus ${c.domains} dominios y sus ${c.records} registros pasarán a retirados (se conserva el historial) y el token se borrará del proveedor de secretos. ¿Seguir?`,
      acceptLabel: 'Dar de baja',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () =>
        this.run(`${c.id}:delete`, this.api.deleteConnector(c.id), () =>
          this.messages.add({
            severity: 'success',
            summary: 'Conector dado de baja',
            detail: `${c.name}: token borrado`,
            life: 4000,
          }),
        ),
    });
  }

  private announce(
    verify: ConnectorVerification | null,
    name: string,
    created: boolean,
  ): void {
    if (!verify)
      this.messages.add({
        severity: 'warn',
        summary: 'Sin respuesta del worker',
        detail: `${name}: no se pudo probar el token ahora; vuelve a intentarlo.`,
        life: 6000,
      });
    else if (verify.ok)
      this.messages.add({
        severity: 'success',
        summary: 'Token válido',
        detail: `${name}: ${verify.zones} ${verify.zones === 1 ? 'zona' : 'zonas'}${created ? '; primera sincronización en cola' : ''}.`,
        life: 5000,
      });
    else
      this.messages.add({
        severity: 'error',
        summary: 'Token no válido',
        detail: `${name}: ${verify.error}`,
        life: 8000,
      });
  }

  private run<T>(
    key: string,
    request: Observable<T>,
    onDone: (value: T) => void,
    onError?: (message: string) => void,
  ): void {
    this.busy.set(key);
    request.subscribe({
      next: (value) => {
        this.busy.set(null);
        onDone(value);
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(null);
        const message = apiErrorMessage(err, 'No se pudo completar la acción.');
        if (onError) onError(message);
        else this.messages.add({ severity: 'error', summary: 'Error', detail: message, life: 6000 });
      },
    });
  }
}
