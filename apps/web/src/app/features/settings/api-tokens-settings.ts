import { DatePipe, NgTemplateOutlet } from '@angular/common';
import { Component, computed, inject, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  API_TOKEN_MAX_DAYS,
  API_TOKEN_NAME_MAX,
  type ApiTokenScope,
  type ApiTokenSummary,
  type CreatedApiTokenResponse,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { RadioButtonModule } from '@openng/optimus-ui/radiobutton';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from '../../core/api/api-base-url';
import { ApiTokensApi } from '../../core/api/api-tokens-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';

const DAY_MS = 24 * 60 * 60 * 1000;

export const API_TOKEN_SCOPE_INFO: Record<ApiTokenScope, { label: string; help: string }> = {
  read: {
    label: 'Solo lectura',
    help: 'Solo GET: inventario, vulnerabilidades y lo que tu rol pueda leer. Cualquier cambio, 403.',
  },
  role: {
    label: 'Lo que permita tu rol',
    help: 'Lo mismo que puedes hacer tú en la web, en cada momento (si te cambian el rol, el token cambia con él).',
  },
};

/** Fecha `aaaa-mm-dd` (para el campo de fecha) a `days` días de hoy. */
export function dateInDays(days: number, now = Date.now()): string {
  return new Date(now + days * DAY_MS).toISOString().slice(0, 10);
}

/** Caducidad elegida → ISO (al final del día elegido, hora local). */
export function expiryIso(choice: number | 'custom', customDate: string, now = Date.now()): string | null {
  if (choice !== 'custom') return new Date(now + choice * DAY_MS).toISOString();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(customDate)) return null;
  const end = new Date(`${customDate}T23:59:00`);
  if (Number.isNaN(end.getTime()) || end.getTime() <= now) return null;
  return end.getTime() > now + API_TOKEN_MAX_DAYS * DAY_MS ? null : end.toISOString();
}

/**
 * Ajustes › Tokens de API (QoL-6, DESIGN §14): los propios (crear con nombre, caducidad y alcance,
 * ver el último uso y revocar) y, con `users.manage`, los de todos. El token se enseña una sola
 * vez: la API solo guarda su hash.
 */
@Component({
  selector: 'app-api-tokens-settings',
  imports: [
    DatePipe,
    NgTemplateOutlet,
    FormsModule,
    ButtonModule,
    CardModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    RadioButtonModule,
    SelectModule,
    TableModule,
    TagModule,
    TooltipModule,
  ],
  template: `
    <p-card styleClass="block" data-block="api-tokens">
      <ng-template #title>
        <div class="title">
          <span>Tus tokens de API</span>
          <p-button label="Nuevo token" icon="bi bi-key" size="small" (onClick)="openCreate()" data-action="new-token" />
        </div>
      </ng-template>
      <p class="text-muted hint">
        Para scripts y herramientas: <code>Authorization: Bearer iwt_…</code>. Caducan siempre (como mucho
        en un año) y valen como tú: nunca más que tu rol.
      </p>
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      } @else {
        <ng-container *ngTemplateOutlet="tokensTable; context: { $implicit: mine(), owner: false }" />
      }
    </p-card>

    @if (auth.can('users.manage')) {
      <p-card styleClass="block" data-block="all-api-tokens">
        <ng-template #title>
          <div class="title">
            <span>Tokens de todos los usuarios</span>
            <p-select
              [options]="ownerOptions()"
              optionLabel="label"
              optionValue="value"
              [ngModel]="ownerFilter()"
              (ngModelChange)="ownerFilter.set($event)"
              placeholder="Todos los usuarios"
              [showClear]="true"
              ariaLabel="Filtrar por usuario"
              data-filter="owner"
            />
          </div>
        </ng-template>
        @if (allError(); as message) {
          <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
        } @else {
          <ng-container *ngTemplateOutlet="tokensTable; context: { $implicit: allShown(), owner: true }" />
        }
      </p-card>
    }

    <ng-template #tokensTable let-tokens let-owner="owner">
      <div class="table-scroll">
        <p-table [value]="tokens" size="small" dataKey="id" [loading]="loading()">
          <ng-template #header>
            <tr>
              @if (owner) {
                <th>Usuario</th>
              }
              <th>Nombre</th>
              <th style="width: 9rem">Token</th>
              <th style="width: 10rem">Alcance</th>
              <th style="width: 8rem">Caduca</th>
              <th style="width: 11rem">Último uso</th>
              <th style="width: 7rem">Estado</th>
              <th style="width: 6rem"></th>
            </tr>
          </ng-template>
          <ng-template #body let-t>
            <tr [attr.data-token]="t.name" [class.inactive]="!t.active">
              @if (owner) {
                <td class="email">{{ t.user?.email }}</td>
              }
              <td>{{ t.name }}</td>
              <td><code>{{ t.prefix }}…</code></td>
              <td>
                <p-tag
                  [value]="scopeLabel(t.scope)"
                  [severity]="t.scope === 'read' ? 'secondary' : 'info'"
                  [icon]="t.scope === 'read' ? 'bi bi-eye' : 'bi bi-person-badge'"
                />
              </td>
              <td class="nowrap" [pTooltip]="(t.expiresAt | date: 'medium') ?? undefined">{{ t.expiresAt | date: 'd MMM y' }}</td>
              <td class="nowrap">
                @if (t.lastUsedAt) {
                  <span [pTooltip]="t.lastUsedIp ? 'Desde ' + t.lastUsedIp : undefined">{{ t.lastUsedAt | date: 'short' }}</span>
                } @else {
                  <span class="text-muted">Nunca</span>
                }
              </td>
              <td>
                @if (t.revokedAt) {
                  <p-tag value="Revocado" severity="danger" [pTooltip]="(t.revokedAt | date: 'medium') ?? undefined" />
                } @else if (!t.active) {
                  <p-tag value="Caducado" severity="warn" />
                } @else {
                  <p-tag value="Vigente" severity="success" />
                }
              </td>
              <td class="row-actions">
                @if (t.active) {
                  <p-button
                    label="Revocar"
                    severity="danger"
                    [text]="true"
                    size="small"
                    (onClick)="confirmRevoke(t, owner)"
                    data-action="revoke-token"
                  />
                }
              </td>
            </tr>
          </ng-template>
          <ng-template #emptymessage>
            <tr>
              <td [attr.colspan]="owner ? 8 : 7" class="text-muted">
                {{ owner ? 'Nadie tiene tokens.' : 'Aún no tienes tokens.' }}
              </td>
            </tr>
          </ng-template>
        </p-table>
      </div>
    </ng-template>

    <p-dialog header="Nuevo token de API" [visible]="formOpen()" (visibleChange)="formOpen.set($event)"
      [modal]="true" [style]="{ width: 'min(32rem, 95vw)' }" data-dialog="new-token">
      <div class="form">
        <label for="token-name">Nombre</label>
        <input pInputText id="token-name" [(ngModel)]="name" [maxlength]="nameMax"
          placeholder="Para qué es (script de copias, CI…)" autocomplete="off" data-field="name" />
        <label for="token-expiry">Caduca</label>
        <p-select inputId="token-expiry" [options]="expiryOptions" optionLabel="label" optionValue="value"
          [(ngModel)]="expiry" appendTo="body" data-field="expiry" />
        @if (expiry === 'custom') {
          <input pInputText type="date" aria-label="Fecha de caducidad" [(ngModel)]="customDate"
            [min]="minDate" [max]="maxDate" data-field="date" />
        }
        <span class="label">Alcance</span>
        @for (scope of scopes; track scope) {
          <div class="radio">
            <p-radiobutton [inputId]="'scope-' + scope" name="scope" [value]="scope" [(ngModel)]="scope_" />
            <label [for]="'scope-' + scope">
              <strong>{{ scopeInfo[scope].label }}</strong>
              <small class="text-muted">{{ scopeInfo[scope].help }}</small>
            </label>
          </div>
        }
      </div>
      @if (formError(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mt">{{ message }}</p-message>
      }
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="formOpen.set(false)" />
        <p-button label="Crear" icon="bi bi-check-lg" [loading]="busy()" (onClick)="create()" data-action="create-token" />
      </ng-template>
    </p-dialog>

    <p-dialog header="Token creado" [visible]="!!issued()" (visibleChange)="!$event && issued.set(null)"
      [modal]="true" [style]="{ width: 'min(36rem, 95vw)' }" data-dialog="issued-token">
      @if (issued(); as t) {
        <p>Token <strong>{{ t.token.name }}</strong> ({{ scopeInfo[t.token.scope].label.toLowerCase() }}, caduca el
          {{ t.token.expiresAt | date: 'd MMM y' }}):</p>
        <div class="secret">
          <code data-issued-token>{{ t.secret }}</code>
          <p-button icon="bi bi-clipboard" size="small" severity="secondary" [text]="true"
            [ariaLabel]="copied() ? 'Copiado' : 'Copiar'" [pTooltip]="copied() ? 'Copiado' : 'Copiar'"
            (onClick)="copy(t.secret)" data-action="copy" />
        </div>
        <p-message severity="warn" icon="bi bi-eye-slash">
          Solo se muestra ahora: InfraWard guarda únicamente su huella. Guárdalo en un gestor de secretos;
          si lo pierdes, revócalo y crea otro.
        </p-message>
        <p class="label">Pruébalo:</p>
        <pre class="example"><code>curl -H "Authorization: Bearer $INFRAWARD_TOKEN" {{ apiUrl }}/assets/tree</code></pre>
      }
      <ng-template #footer>
        <p-button label="Hecho" (onClick)="issued.set(null)" data-action="close-issued" />
      </ng-template>
    </p-dialog>
  `,
  styles: `
    :host {
      display: grid;
      /* Sin minmax(0, …) la columna crece con la tabla y la página se desborda en el móvil. */
      grid-template-columns: minmax(0, 1fr);
      gap: 1rem;
    }
    .title {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      justify-content: space-between;
    }
    .hint {
      margin: 0 0 0.75rem;
      overflow-wrap: anywhere;
    }
    .email {
      overflow-wrap: break-word;
      min-width: 10rem;
    }
    .nowrap {
      white-space: nowrap;
    }
    tr.inactive td:not(.row-actions) {
      opacity: 0.6;
    }
    .row-actions {
      white-space: nowrap;
      text-align: right;
    }
    .form {
      display: grid;
      gap: 0.4rem;
    }
    .form label,
    .label {
      font-weight: 600;
      margin-top: 0.5rem;
    }
    .radio {
      display: flex;
      gap: 0.5rem;
      align-items: flex-start;
    }
    .radio label {
      display: grid;
      gap: 0.1rem;
      margin-top: 0;
      font-weight: normal;
    }
    :host ::ng-deep .form .p-select {
      width: 100%;
    }
    :host ::ng-deep .mt {
      margin-top: 0.75rem;
    }
    .secret {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }
    .secret code {
      font-size: 0.95rem;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      background: var(--p-content-hover-background);
      overflow-wrap: anywhere;
      user-select: all;
    }
    .example {
      margin: 0.25rem 0 0;
      padding: 0.5rem 0.75rem;
      overflow-x: auto;
      border-radius: 6px;
      background: var(--p-app-code-background);
      font-size: 0.8rem;
    }
  `,
})
export class ApiTokensSettings implements OnInit {
  private readonly api = inject(ApiTokensApi);
  private readonly messages = inject(MessageService);
  private readonly confirm = inject(ConfirmationService);
  protected readonly auth = inject(AuthService);
  protected readonly apiUrl = `${globalThis.location?.origin ?? ''}${inject(API_BASE_URL)}`;

  protected readonly scopeInfo = API_TOKEN_SCOPE_INFO;
  protected readonly scopes: ApiTokenScope[] = ['read', 'role'];
  protected readonly nameMax = API_TOKEN_NAME_MAX;
  protected readonly expiryOptions = [
    { label: '7 días', value: 7 },
    { label: '30 días', value: 30 },
    { label: '90 días', value: 90 },
    { label: '1 año', value: API_TOKEN_MAX_DAYS },
    { label: 'Otra fecha…', value: 'custom' },
  ];
  protected readonly minDate = dateInDays(1);
  protected readonly maxDate = dateInDays(API_TOKEN_MAX_DAYS - 1);

  protected readonly mine = signal<ApiTokenSummary[]>([]);
  protected readonly all = signal<ApiTokenSummary[]>([]);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly allError = signal<string | null>(null);
  protected readonly ownerFilter = signal<string | null>(null);
  protected readonly ownerOptions = computed(() => {
    const seen = new Map<string, string>();
    for (const t of this.all()) if (t.user) seen.set(t.user.id, t.user.email);
    return [...seen].map(([value, label]) => ({ value, label }));
  });
  protected readonly allShown = computed(() => {
    const owner = this.ownerFilter();
    return owner ? this.all().filter((t) => t.user?.id === owner) : this.all();
  });

  protected readonly formOpen = signal(false);
  protected readonly formError = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected name = '';
  protected expiry: number | 'custom' = 30;
  protected customDate = dateInDays(30);
  protected scope_: ApiTokenScope = 'read';
  protected readonly issued = signal<CreatedApiTokenResponse | null>(null);
  protected readonly copied = signal(false);

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.api.mine().subscribe({
      next: (tokens) => {
        this.mine.set(tokens);
        this.loading.set(false);
        this.error.set(null);
      },
      error: (err: unknown) => {
        this.loading.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudieron cargar tus tokens.'));
      },
    });
    if (this.auth.can('users.manage'))
      this.api.all().subscribe({
        next: (tokens) => {
          this.all.set(tokens);
          this.allError.set(null);
        },
        error: (err: unknown) =>
          this.allError.set(apiErrorMessage(err, 'No se pudieron cargar los tokens de todos.')),
      });
  }

  protected scopeLabel(scope: ApiTokenScope): string {
    return API_TOKEN_SCOPE_INFO[scope].label;
  }

  protected openCreate(): void {
    this.name = '';
    this.expiry = 30;
    this.customDate = dateInDays(30);
    this.scope_ = 'read';
    this.formError.set(null);
    this.formOpen.set(true);
  }

  protected create(): void {
    const name = this.name.trim();
    if (!name) {
      this.formError.set('Ponle un nombre para reconocerlo.');
      return;
    }
    const expiresAt = expiryIso(this.expiry, this.customDate);
    if (!expiresAt) {
      this.formError.set(`Elige una fecha entre mañana y dentro de ${API_TOKEN_MAX_DAYS} días.`);
      return;
    }
    this.busy.set(true);
    this.api.create({ name, scope: this.scope_, expiresAt }).subscribe({
      next: (res) => {
        this.busy.set(false);
        this.formOpen.set(false);
        this.copied.set(false);
        this.issued.set(res);
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.formError.set(apiErrorMessage(err, 'No se pudo crear el token.'));
      },
    });
  }

  protected confirmRevoke(token: ApiTokenSummary, asAdmin: boolean): void {
    const whose = asAdmin && token.user ? ` de ${token.user.email}` : '';
    this.confirm.confirm({
      header: `¿Revocar «${token.name}»${whose}?`,
      message: 'Deja de valer al momento: los scripts que lo usen recibirán 401. No se puede deshacer.',
      icon: 'bi bi-key',
      acceptLabel: 'Revocar',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () => {
        const own = !asAdmin || token.user?.id === this.auth.user()?.id;
        this.run(own ? this.api.revokeMine(token.id) : this.api.revoke(token.id), 'Token revocado');
      },
    });
  }

  private run(request: Observable<unknown>, summary: string): void {
    request.subscribe({
      next: () => {
        this.messages.add({ severity: 'success', summary, life: 4000 });
        this.load();
      },
      error: (err: unknown) =>
        this.messages.add({
          severity: 'error',
          summary: apiErrorMessage(err, 'No se pudo revocar el token.'),
          life: 6000,
        }),
    });
  }

  protected async copy(value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      this.copied.set(true);
    } catch {
      // Sin permiso de portapapeles: se puede seleccionar a mano (user-select: all).
    }
  }
}
