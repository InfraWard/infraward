import { DatePipe } from '@angular/common';
import { Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  VAULT_ENTRY_KIND_LABELS,
  VAULT_ENTRY_KINDS,
  VAULT_NAME_MAX,
  VAULT_NOTES_MAX,
  VAULT_ROTATION_DAYS_MAX,
  VAULT_ROTATION_DAYS_MIN,
  VAULT_URL_MAX,
  VAULT_USERNAME_MAX,
  type AssetSummary,
  type VaultEntry,
  type VaultEntryKind,
  type VaultVersion,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService, type MenuItem } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MenuModule } from '@openng/optimus-ui/menu';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import type { Observable } from 'rxjs';
import { VaultApi } from '../../core/api/vault-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { AssetPicker } from '../../shared/asset-picker';
import { VaultRevealDialog } from './vault-reveal-dialog';
import { VaultSecretField } from './vault-secret-field';

export const VAULT_KIND_ICONS: Record<VaultEntryKind, string> = {
  console: 'bi-terminal',
  web: 'bi-globe2',
  ipmi: 'bi-cpu',
  other: 'bi-key',
};

const ORIGIN_LABELS: Record<VaultVersion['origin'], string> = {
  created: 'Creada',
  replaced: 'Sustituida',
  restored: 'Restaurada',
};

/** Tipos de asset a los que se puede asociar una credencial. */
const ASSET_TYPES = ['server', 'vm', 'lxc', 'container', 'database', 'domain'] as const;

interface EntryForm {
  kind: VaultEntryKind;
  name: string;
  username: string;
  url: string;
  notes: string;
  rotationDays: number | null;
  asset: { id: string; name: string; roles: string[] } | null;
  secret: string;
  /** Al crear: la contraseña es nueva (cuenta como rotada hoy). */
  freshSecret: boolean;
}

function emptyForm(asset: EntryForm['asset']): EntryForm {
  return {
    kind: 'console',
    name: '',
    username: '',
    url: '',
    notes: '',
    rotationDays: null,
    asset,
    secret: '',
    freshSecret: true,
  };
}

/** Días hasta (o desde) una fecha, para el estado de la rotación. */
function daysFrom(iso: string | null, now = Date.now()): number {
  return iso ? Math.round((new Date(iso).getTime() - now) / 86_400_000) : 0;
}

/**
 * Credenciales de la caja fuerte (QoL-7): de un asset (pestaña de su ficha) o de todo el
 * inventario (página `/vault`). Gestionar (`vault.manage`) nunca enseña valores; «Revelar» y
 * restaurar versiones, solo los admins (`vault.admin`) y con reautenticación reciente.
 */
@Component({
  selector: 'app-vault-entries',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    AssetPicker,
    ButtonModule,
    CheckboxModule,
    DialogModule,
    InputNumberModule,
    InputTextModule,
    MenuModule,
    MessageModule,
    SelectModule,
    TableModule,
    TagModule,
    TextareaModule,
    TooltipModule,
    VaultRevealDialog,
    VaultSecretField,
  ],
  template: `
    <div class="toolbar">
      @if (!assetId()) {
        <span class="search">
          <i class="bi bi-search" aria-hidden="true"></i>
          <input
            pInputText
            type="search"
            placeholder="Buscar por nombre, usuario, URL o asset"
            aria-label="Buscar credenciales"
            [ngModel]="query()"
            (ngModelChange)="query.set($event)"
            data-field="search"
          />
        </span>
      }
      <p-button
        [label]="trash() ? 'Volver a las vigentes' : 'Papelera'"
        [icon]="trash() ? 'bi bi-arrow-left' : 'bi bi-trash3'"
        severity="secondary"
        [text]="true"
        size="small"
        (onClick)="trash.set(!trash())"
        data-action="toggle-trash"
      />
      <span class="grow"></span>
      @if (!trash()) {
        <p-button
          label="Nueva credencial"
          icon="bi bi-plus-lg"
          size="small"
          (onClick)="openCreate()"
          data-action="new-entry"
        />
      }
    </div>

    @if (error(); as message) {
      <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
    } @else {
      @if (overdue() > 0 && !trash() && !assetId()) {
        <p-message severity="warn" icon="bi bi-clock-history" styleClass="mb" data-block="overdue">
          {{ overdue() }} {{ overdue() === 1 ? 'credencial ha superado' : 'credenciales han superado' }}
          su plazo de rotación.
        </p-message>
      }
      <div class="table-scroll">
        <p-table [value]="entries()" size="small" dataKey="id" [loading]="loading()">
          <ng-template #header>
            <tr>
              <th>Credencial</th>
              @if (!assetId()) {
                <th>Asset</th>
              }
              <th>Usuario</th>
              <th class="hide-sm">URL</th>
              <th>{{ trash() ? 'Se destruye' : 'Rotación' }}</th>
              <th></th>
            </tr>
          </ng-template>
          <ng-template #body let-e>
            <tr [attr.data-entry]="e.name">
              <td>
                <div class="name">
                  <i class="bi {{ kindIcons[e.kind] }}" aria-hidden="true"></i>
                  <span>{{ e.name }}</span>
                </div>
                <small class="text-muted">
                  {{ kindLabels[e.kind] }}
                  @if (!e.hasSecret) {
                    · sin secreto
                  } @else {
                    · v{{ e.currentVersion }}
                  }
                </small>
              </td>
              @if (!assetId()) {
                <td>
                  @if (e.asset) {
                    <a [routerLink]="['/assets', e.asset.id]" [queryParams]="{ tab: 'credentials' }">{{ e.asset.name }}</a>
                  } @else {
                    <span class="text-muted">Suelta</span>
                  }
                </td>
              }
              <td class="user">
                @if (e.username) {
                  <code>{{ e.username }}</code>
                } @else {
                  <span class="text-muted">—</span>
                }
              </td>
              <td class="hide-sm url">
                @if (e.url) {
                  <a [href]="safeUrl(e.url)" target="_blank" rel="noopener noreferrer">{{ e.url }}</a>
                }
              </td>
              <td class="nowrap">
                @if (trash()) {
                  <span [pTooltip]="'Borrada por ' + (e.deletedBy ?? '—')">{{ e.purgeAt | date: 'd MMM y' }}</span>
                } @else {
                  @switch (e.rotationState) {
                    @case ('overdue') {
                      <p-tag severity="danger" icon="bi bi-exclamation-circle" value="Vencida"
                        [pTooltip]="'Venció el ' + (e.rotationDueAt | date: 'd MMM y') + ' (plazo de ' + e.effectiveRotationDays + ' días)'" />
                    }
                    @case ('ok') {
                      <p-tag severity="success" value="Al día"
                        [pTooltip]="'Rotada el ' + (e.lastRotatedAt | date: 'd MMM y') + '; vence en ' + days(e.rotationDueAt) + ' días'" />
                    }
                    @default {
                      <p-tag severity="secondary" value="Sin fecha" pTooltip="No consta cuándo se cambió por última vez" />
                    }
                  }
                }
              </td>
              <td class="row-actions">
                @if (trash()) {
                  <p-button label="Recuperar" icon="bi bi-arrow-counterclockwise" size="small" [text]="true"
                    (onClick)="run(api.restore(e.id), 'Credencial recuperada')" data-action="restore-entry" />
                } @else {
                  @if (canReveal && e.hasSecret) {
                    <p-button label="Revelar" icon="bi bi-eye" size="small" severity="warn" [outlined]="true"
                      (onClick)="revealing.set(e)" data-action="reveal" />
                  }
                  <p-button icon="bi bi-three-dots-vertical" size="small" severity="secondary" [text]="true"
                    ariaLabel="Más acciones" (onClick)="openMenu(menu, $event, e)" data-action="entry-menu" />
                }
              </td>
            </tr>
          </ng-template>
          <ng-template #emptymessage>
            <tr>
              <td [attr.colspan]="assetId() ? 5 : 6" class="text-muted">
                {{ trash() ? 'La papelera está vacía.' : 'Aún no hay credenciales guardadas.' }}
              </td>
            </tr>
          </ng-template>
        </p-table>
      </div>
    }
    <p-menu #menu [model]="menuItems()" [popup]="true" appendTo="body" />

    <!-- Alta y edición -->
    <p-dialog
      [header]="editing() ? 'Editar credencial' : 'Nueva credencial'"
      [visible]="formOpen()"
      (visibleChange)="formOpen.set($event)"
      [modal]="true"
      [style]="{ width: 'min(36rem, 95vw)' }"
      data-dialog="entry"
    >
      <div class="form">
        <label for="vault-kind">Tipo</label>
        <p-select inputId="vault-kind" [options]="kindOptions" optionLabel="label" optionValue="value"
          [(ngModel)]="form.kind" appendTo="body" data-field="kind" />
        <label for="vault-name">Nombre</label>
        <input pInputText id="vault-name" [(ngModel)]="form.name" [maxlength]="limits.name"
          placeholder="root (consola), Proxmox (web), iDRAC…" autocomplete="off" data-field="name" />
        @if (!assetId()) {
          <span class="label">Asset</span>
          @if (form.asset; as a) {
            <div class="asset">
              <span>{{ a.name }}</span>
              <p-button icon="bi bi-x-lg" size="small" severity="secondary" [text]="true"
                ariaLabel="Quitar el asset (credencial suelta)" (onClick)="form.asset = null" />
            </div>
          } @else {
            <app-asset-picker inputId="vault-asset" [types]="assetTypes"
              placeholder="Opcional: busca el servidor, CT…" (picked)="pickAsset($event)" />
          }
        }
        <label for="vault-user">Usuario</label>
        <input pInputText id="vault-user" [(ngModel)]="form.username" [maxlength]="limits.username"
          placeholder="root, root@pam, ADMIN…" autocomplete="off" data-field="username" />
        <label for="vault-url">URL</label>
        <input pInputText id="vault-url" [(ngModel)]="form.url" [maxlength]="limits.url"
          placeholder="https://pve1:8006" autocomplete="off" data-field="url" />
        <label for="vault-notes">Notas</label>
        <textarea pTextarea id="vault-notes" [(ngModel)]="form.notes" [maxlength]="limits.notes" rows="3"
          placeholder="Cómo se llega a la consola, quién la tiene…" data-field="notes"></textarea>
        <label for="vault-rotation">Plazo de rotación (días)</label>
        <p-inputnumber inputId="vault-rotation" [(ngModel)]="form.rotationDays" [min]="limits.rotationMin"
          [max]="limits.rotationMax" [placeholder]="'Por defecto (ajustes)'" data-field="rotation" />
        @if (!editing()) {
          <app-vault-secret-field inputId="vault-secret" [(value)]="form.secret" [kind]="form.kind"
            [username]="form.username" [roles]="form.asset?.roles ?? assetRoles()" />
          @if (form.secret) {
            <span class="check">
              <p-checkbox inputId="vault-fresh" [(ngModel)]="form.freshSecret" [binary]="true" />
              <label for="vault-fresh">Es nueva: ya la he aplicado (cuenta como rotada hoy)</label>
            </span>
          }
        }
      </div>
      @if (formError(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mt">{{ message }}</p-message>
      }
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="formOpen.set(false)" />
        <p-button label="Guardar" icon="bi bi-check-lg" [loading]="busy()" (onClick)="save()" data-action="save-entry" />
      </ng-template>
    </p-dialog>

    <!-- Sustituir el secreto -->
    <p-dialog header="Sustituir el secreto" [visible]="!!replacing()" (visibleChange)="!$event && replacing.set(null)"
      [modal]="true" [style]="{ width: 'min(34rem, 95vw)' }" data-dialog="replace-secret">
      @if (replacing(); as e) {
        <p class="text-muted">
          <strong>{{ e.name }}</strong>: se guarda como versión nueva; la anterior se conserva (un admin
          puede restaurarla).
        </p>
        <app-vault-secret-field inputId="vault-new-secret" label="Contraseña nueva" [(value)]="newSecret"
          [kind]="e.kind" [username]="e.username" [roles]="e.asset?.roles ?? assetRoles()" />
        <span class="check">
          <p-checkbox inputId="vault-rotated" [(ngModel)]="rotated" [binary]="true" />
          <label for="vault-rotated">Ya la he aplicado en el servidor (marcar como rotada)</label>
        </span>
      }
      @if (formError(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mt">{{ message }}</p-message>
      }
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="replacing.set(null)" />
        <p-button label="Guardar versión" icon="bi bi-check-lg" [loading]="busy()" (onClick)="replace()"
          data-action="save-secret" />
      </ng-template>
    </p-dialog>

    <!-- Historial de versiones -->
    <p-dialog header="Historial de versiones" [visible]="!!history()" (visibleChange)="!$event && history.set(null)"
      [modal]="true" [style]="{ width: 'min(40rem, 95vw)' }" data-dialog="versions">
      @if (history(); as h) {
        <p class="text-muted"><strong>{{ h.entry.name }}</strong>: quién y cuándo, nunca los valores.</p>
        <div class="table-scroll">
          <p-table [value]="h.versions" size="small">
            <ng-template #header>
              <tr><th>Versión</th><th>Origen</th><th>Fecha</th><th>Por</th><th></th></tr>
            </ng-template>
            <ng-template #body let-v>
              <tr [attr.data-version]="v.version">
                <td>v{{ v.version }} @if (v.current) { <p-tag value="Actual" severity="success" /> }</td>
                <td>{{ originLabel(v) }}</td>
                <td class="nowrap">{{ v.createdAt | date: 'short' }}</td>
                <td class="user">{{ v.createdBy ?? '—' }}</td>
                <td class="row-actions">
                  @if (!v.current && canReveal) {
                    <p-button label="Restaurar" size="small" [text]="true" [disabled]="!v.available"
                      [pTooltip]="v.available ? 'Copia esta versión como la actual' : 'El almacén ya no la conserva'"
                      (onClick)="restoreVersion(h.entry, v.version)" data-action="restore-version" />
                  }
                </td>
              </tr>
            </ng-template>
          </p-table>
        </div>
      }
    </p-dialog>

    <app-vault-reveal-dialog [entry]="revealing()" (closed)="revealing.set(null)" />
  `,
  styles: `
    :host {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 0.75rem;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
    }
    .grow {
      flex: 1;
    }
    .search {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      flex: 1 1 16rem;
      max-width: 28rem;
    }
    .search input {
      flex: 1;
      min-width: 0;
    }
    .name {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      font-weight: 600;
      min-width: 8rem;
      overflow-wrap: break-word;
    }
    .user,
    .url {
      overflow-wrap: break-word;
    }
    .user code {
      white-space: nowrap;
    }
    .url {
      max-width: 16rem;
    }
    .nowrap {
      white-space: nowrap;
    }
    .row-actions {
      white-space: nowrap;
      text-align: right;
    }
    .form {
      display: grid;
      gap: 0.4rem;
    }
    .form > label,
    .label {
      font-weight: 600;
      margin-top: 0.4rem;
    }
    .asset {
      display: flex;
      align-items: center;
      gap: 0.25rem;
    }
    .check {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.5rem;
    }
    :host ::ng-deep .form .p-select,
    :host ::ng-deep .form .p-inputnumber {
      width: 100%;
    }
    :host ::ng-deep .mt {
      margin-top: 0.75rem;
    }
    :host ::ng-deep .mb {
      margin-bottom: 0.25rem;
    }
    @media (max-width: 640px) {
      .hide-sm {
        display: none;
      }
    }
  `,
})
export class VaultEntries {
  protected readonly api = inject(VaultApi);
  private readonly messages = inject(MessageService);
  private readonly confirm = inject(ConfirmationService);
  private readonly auth = inject(AuthService);

  /** Solo las de este asset (pestaña de la ficha). */
  readonly assetId = input<string | null>(null);
  readonly assetName = input<string | null>(null);
  /** Roles del asset (para el comando de rotación). */
  readonly assetRoles = input<readonly string[]>([]);

  protected readonly kindLabels: Readonly<Record<string, string>> = VAULT_ENTRY_KIND_LABELS;
  protected readonly kindIcons: Readonly<Record<string, string>> = VAULT_KIND_ICONS;
  protected readonly kindOptions = VAULT_ENTRY_KINDS.map((value) => ({
    value,
    label: VAULT_ENTRY_KIND_LABELS[value],
  }));
  protected readonly assetTypes = ASSET_TYPES;
  protected readonly limits = {
    name: VAULT_NAME_MAX,
    username: VAULT_USERNAME_MAX,
    url: VAULT_URL_MAX,
    notes: VAULT_NOTES_MAX,
    rotationMin: VAULT_ROTATION_DAYS_MIN,
    rotationMax: VAULT_ROTATION_DAYS_MAX,
  };
  protected readonly canReveal = this.auth.can('vault.admin');

  protected readonly query = signal('');
  protected readonly trash = signal(false);
  protected readonly entries = signal<VaultEntry[]>([]);
  protected readonly overdue = signal(0);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly formOpen = signal(false);
  protected readonly editing = signal<VaultEntry | null>(null);
  protected readonly formError = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected form: EntryForm = emptyForm(null);

  protected readonly replacing = signal<VaultEntry | null>(null);
  protected newSecret = '';
  protected rotated = true;

  protected readonly history = signal<{ entry: VaultEntry; versions: VaultVersion[] } | null>(null);
  protected readonly revealing = signal<VaultEntry | null>(null);

  private readonly menuEntry = signal<VaultEntry | null>(null);
  protected readonly menuItems = computed<MenuItem[]>(() => {
    const e = this.menuEntry();
    if (!e) return [];
    return [
      { label: 'Editar', icon: 'bi bi-pencil', command: () => this.openEdit(e) },
      {
        label: e.hasSecret ? 'Sustituir el secreto' : 'Guardar el secreto',
        icon: 'bi bi-arrow-repeat',
        command: () => this.openReplace(e),
      },
      {
        label: 'Marcar como rotada hoy',
        icon: 'bi bi-check2-circle',
        command: () => this.run(this.api.markRotated(e.id), 'Marcada como rotada'),
      },
      { label: 'Historial de versiones', icon: 'bi bi-clock-history', command: () => this.openHistory(e) },
      { separator: true },
      { label: 'Borrar', icon: 'bi bi-trash3', command: () => this.confirmDelete(e) },
    ];
  });

  constructor() {
    let timer: ReturnType<typeof setTimeout> | undefined;
    // Recarga al cambiar el asset, la papelera o la búsqueda (con un respiro al teclear).
    effect(() => {
      this.assetId();
      this.trash();
      this.query();
      clearTimeout(timer);
      timer = setTimeout(() => untracked(() => this.load()), 200);
    });
  }

  load(): void {
    this.loading.set(true);
    this.api
      .list({ assetId: this.assetId() ?? undefined, deleted: this.trash(), q: this.query() })
      .subscribe({
        next: (list) => {
          this.entries.set(list.items);
          this.overdue.set(list.overdue);
          this.loading.set(false);
          this.error.set(null);
        },
        error: (err: unknown) => {
          this.loading.set(false);
          this.error.set(apiErrorMessage(err, 'No se pudo cargar la caja fuerte.'));
        },
      });
  }

  protected days(iso: string | null): number {
    return Math.max(0, daysFrom(iso));
  }

  /** Solo http(s): una URL guardada con otro esquema (javascript:…) no se enlaza. */
  protected safeUrl(url: string): string | null {
    return /^https?:\/\//i.test(url) ? url : null;
  }

  protected originLabel(v: VaultVersion): string {
    return v.origin === 'restored' && v.restoredFrom
      ? `${ORIGIN_LABELS.restored} (de la v${v.restoredFrom})`
      : ORIGIN_LABELS[v.origin];
  }

  protected openMenu(menu: { toggle: (e: Event) => void }, event: Event, entry: VaultEntry): void {
    this.menuEntry.set(entry);
    menu.toggle(event);
  }

  protected pickAsset(asset: AssetSummary): void {
    this.form.asset = { id: asset.id, name: asset.name, roles: [] };
  }

  protected openCreate(): void {
    const id = this.assetId();
    this.form = emptyForm(id ? { id, name: this.assetName() ?? '', roles: [...this.assetRoles()] } : null);
    this.editing.set(null);
    this.formError.set(null);
    this.formOpen.set(true);
  }

  private openEdit(e: VaultEntry): void {
    this.form = {
      kind: e.kind,
      name: e.name,
      username: e.username ?? '',
      url: e.url ?? '',
      notes: e.notes ?? '',
      rotationDays: e.rotationDays,
      asset: e.asset ? { id: e.asset.id, name: e.asset.name, roles: e.asset.roles } : null,
      secret: '',
      freshSecret: true,
    };
    this.editing.set(e);
    this.formError.set(null);
    this.formOpen.set(true);
  }

  protected save(): void {
    const f = this.form;
    if (!f.name.trim()) {
      this.formError.set('Ponle un nombre para reconocerla.');
      return;
    }
    const fields = {
      kind: f.kind,
      name: f.name.trim(),
      username: f.username.trim() || null,
      url: f.url.trim() || null,
      notes: f.notes.trim() || null,
      rotationDays: f.rotationDays || null,
      assetId: f.asset?.id ?? null,
    };
    const editing = this.editing();
    const request = editing
      ? this.api.update(editing.id, fields)
      : this.api.create({
          ...fields,
          ...(f.secret ? { secret: f.secret, ...(f.freshSecret ? {} : { lastRotatedAt: null }) } : {}),
        });
    this.busy.set(true);
    request.subscribe({
      next: () => {
        this.busy.set(false);
        this.formOpen.set(false);
        // El secreto escrito no se queda en el formulario.
        this.form = emptyForm(null);
        this.messages.add({ severity: 'success', summary: editing ? 'Credencial guardada' : 'Credencial creada', life: 4000 });
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.formError.set(apiErrorMessage(err, 'No se pudo guardar la credencial.'));
      },
    });
  }

  private openReplace(e: VaultEntry): void {
    this.newSecret = '';
    this.rotated = true;
    this.formError.set(null);
    this.replacing.set(e);
  }

  protected replace(): void {
    const e = this.replacing();
    if (!e) return;
    if (!this.newSecret) {
      this.formError.set('Escribe o genera la contraseña nueva.');
      return;
    }
    this.busy.set(true);
    this.api.replaceSecret(e.id, { secret: this.newSecret, rotated: this.rotated }).subscribe({
      next: (updated) => {
        this.busy.set(false);
        this.newSecret = '';
        this.replacing.set(null);
        this.messages.add({ severity: 'success', summary: `Guardada como v${updated.currentVersion}`, life: 4000 });
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.formError.set(apiErrorMessage(err, 'No se pudo guardar el secreto.'));
      },
    });
  }

  private openHistory(e: VaultEntry): void {
    this.api.versions(e.id).subscribe({
      next: (versions) => this.history.set({ entry: e, versions }),
      error: (err: unknown) =>
        this.messages.add({ severity: 'error', summary: apiErrorMessage(err, 'No se pudo cargar el historial.'), life: 6000 }),
    });
  }

  protected restoreVersion(e: VaultEntry, version: number): void {
    this.confirm.confirm({
      header: `¿Restaurar la v${version} de «${e.name}»?`,
      message: 'Se guarda como una versión nueva (la actual se conserva). Pide confirmar tu identidad.',
      icon: 'bi bi-clock-history',
      acceptLabel: 'Restaurar',
      rejectLabel: 'Cancelar',
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () =>
        this.api.restoreVersion(e.id, version).subscribe({
          next: (updated) => {
            this.messages.add({ severity: 'success', summary: `Restaurada como v${updated.currentVersion}`, life: 4000 });
            this.history.set(null);
            this.load();
          },
          error: (err: unknown) =>
            this.messages.add({ severity: 'error', summary: apiErrorMessage(err, 'No se pudo restaurar.'), life: 6000 }),
        }),
    });
  }

  private confirmDelete(e: VaultEntry): void {
    this.confirm.confirm({
      header: `¿Borrar «${e.name}»?`,
      message: 'Va a la papelera: se puede recuperar hasta que pase el plazo de los ajustes; después se destruye.',
      icon: 'bi bi-trash3',
      acceptLabel: 'Borrar',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () => this.run(this.api.remove(e.id), 'Credencial en la papelera'),
    });
  }

  protected run(request: Observable<unknown>, summary: string): void {
    request.subscribe({
      next: () => {
        this.messages.add({ severity: 'success', summary, life: 4000 });
        this.load();
      },
      error: (err: unknown) =>
        this.messages.add({ severity: 'error', summary: apiErrorMessage(err, 'No se pudo completar.'), life: 6000 }),
    });
  }
}
