import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import {
  USER_ROLES,
  type AuthProviders,
  type TemporaryPasswordResponse,
  type UserRole,
  type UserSummary,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import type { Observable } from 'rxjs';
import { MfaApi } from '../../core/api/mfa-api';
import { UsersApi } from '../../core/api/users-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { ROLE_INFO, roleLabel, roleSeverity } from '../../shared/role-labels';

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Ajustes > Usuarios (solo admin, DESIGN §14): alta con contraseña temporal, nombre y rol,
 * desactivar/reactivar y restablecer la contraseña. La temporal se ve una sola vez. Cada usuario
 * muestra cómo entra (local u OIDC); el rol de los enlazados al proveedor lo decide el proveedor y
 * con el login local desactivado no hay altas ni contraseñas (salvo el admin de emergencia).
 */
@Component({
  selector: 'app-users-settings',
  imports: [
    DatePipe,
    FormsModule,
    RouterLink,
    ButtonModule,
    CardModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    SelectModule,
    TableModule,
    TagModule,
    TooltipModule,
  ],
  template: `
    <p-card styleClass="block" data-block="users">
      <ng-template #title>
        <div class="title">
          <span>Usuarios</span>
          @if (localLogin()) {
            <p-button label="Nuevo usuario" icon="bi bi-person-plus" size="small"
              (onClick)="openCreate()" data-action="new-user" />
          }
        </div>
      </ng-template>
      @if (!localLogin() && providers(); as p) {
        <p class="text-muted hint" data-oidc-only>
          <i class="bi bi-info-circle" aria-hidden="true"></i>
          El acceso con contraseña está desactivado: los usuarios se crean solos al entrar con
          {{ p.oidc?.name }} y su rol sale de sus grupos.
        </p>
      }
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      } @else {
        <div class="table-scroll">
          <p-table [value]="users()" size="small" dataKey="id" [loading]="loading()">
            <ng-template #header>
              <tr>
                <th>Nombre</th>
                <th>Email</th>
                <th style="width: 6rem">Rol</th>
                <th style="width: 8rem">Acceso</th>
                <th style="width: 9rem">Estado</th>
                <th style="width: 10rem">Último acceso</th>
                <th style="width: 14rem"></th>
              </tr>
            </ng-template>
            <ng-template #body let-user>
              <tr [attr.data-user]="user.email" [class.inactive]="!user.active">
                <td>{{ user.name }} @if (user.id === auth.user()?.id) { <span class="text-muted">(tú)</span> }</td>
                <td class="email">{{ user.email }}</td>
                <td><p-tag [value]="roleLabel(user.role)" [severity]="roleSeverity(user.role)" /></td>
                <td><div class="access" data-access>
                  @if (user.origin === 'oidc') {
                    <p-tag value="OIDC" severity="info" icon="bi bi-box-arrow-in-right"
                      [pTooltip]="'Entra con ' + providerName() + '; el rol sale de sus grupos'" />
                  } @else if (user.oidcLinked) {
                    <p-tag value="Local + OIDC" severity="info" icon="bi bi-link-45deg"
                      [pTooltip]="'Cuenta local enlazada a ' + providerName() + ' (email verificado); el rol sale de sus grupos'" />
                  } @else {
                    <p-tag value="Local" severity="secondary" icon="bi bi-key" pTooltip="Entra con email y contraseña" />
                  }
                  @if (user.emergency) {
                    <p-tag value="Emergencia" severity="warn" icon="bi bi-life-preserver"
                      pTooltip="Admin local de emergencia: entra con contraseña aunque el login local esté desactivado" />
                  }
                  @if (user.mfaEnabled) {
                    <p-tag value="2FA" severity="success" icon="bi bi-shield-check"
                      pTooltip="Verificación en dos pasos activada" data-mfa />
                  }
                </div></td>
                <td>
                  @if (!user.active) {
                    <p-tag value="Desactivado" severity="danger" icon="bi bi-slash-circle" />
                  } @else if (user.mustChangePassword) {
                    <p-tag value="Temporal pendiente" severity="warn" icon="bi bi-hourglass-split" />
                  } @else {
                    <p-tag value="Activo" severity="success" />
                  }
                </td>
                <td class="nowrap">{{ user.lastLoginAt ? (user.lastLoginAt | date: 'short') : '—' }}</td>
                <td class="row-actions">
                  <p-button icon="bi bi-pencil" size="small" severity="secondary" [text]="true"
                    pTooltip="Editar" ariaLabel="Editar" (onClick)="openEdit(user)" data-action="edit-user" />
                  @if (canResetPassword(user)) {
                    <p-button icon="bi bi-key" size="small" severity="secondary" [text]="true"
                      pTooltip="Restablecer contraseña" ariaLabel="Restablecer contraseña"
                      (onClick)="resetPassword(user)" data-action="reset-password" />
                  }
                  @if (user.mfaEnabled && user.id !== auth.user()?.id) {
                    <p-button icon="bi bi-shield-x" size="small" severity="secondary" [text]="true"
                      pTooltip="Restablecer la verificación en dos pasos" ariaLabel="Restablecer la verificación en dos pasos"
                      (onClick)="resetMfa(user)" data-action="reset-mfa" />
                  }
                  @if (user.active) {
                    <p-button icon="bi bi-person-slash" size="small" severity="danger" [text]="true"
                      pTooltip="Desactivar" ariaLabel="Desactivar" [disabled]="user.id === auth.user()?.id"
                      (onClick)="deactivate(user)" data-action="deactivate" />
                  } @else {
                    <p-button icon="bi bi-person-check" size="small" severity="success" [text]="true"
                      pTooltip="Reactivar" ariaLabel="Reactivar" (onClick)="reactivate(user)" data-action="reactivate" />
                  }
                  <a class="p-button p-button-text p-button-secondary p-button-sm p-button-icon-only"
                    [routerLink]="[]" [queryParams]="{ tab: 'audit', actor: user.id }"
                    pTooltip="Ver su actividad" aria-label="Ver su actividad" data-action="user-audit">
                    <i class="bi bi-journal-text" aria-hidden="true"></i>
                  </a>
                </td>
              </tr>
            </ng-template>
          </p-table>
        </div>
      }
    </p-card>

    <p-dialog [header]="editing() ? 'Editar ' + editing()!.email : 'Nuevo usuario'" [visible]="formOpen()"
      (visibleChange)="formOpen.set($event)" [modal]="true" [style]="{ width: 'min(30rem, 95vw)' }" data-dialog="user">
      <div class="form">
        <label for="user-email">Email</label>
        <input pInputText id="user-email" type="email" autocomplete="off" maxlength="320"
          [(ngModel)]="draft.email" [disabled]="emailLocked()" />
        @if (emailLocked()) {
          <small class="text-muted" data-email-managed>
            {{ editing()!.emergency ? 'Es el admin de emergencia: su email va en LOCAL_LOGIN_EMERGENCY_EMAIL.'
              : 'El email lo gestiona el proveedor de identidad.' }}
          </small>
        }
        <label for="user-name">Nombre</label>
        <input pInputText id="user-name" autocomplete="off" maxlength="120" [(ngModel)]="draft.name" />
        <span class="label" id="user-role">Rol</span>
        <p-select [options]="roleOptions" optionLabel="label" optionValue="value" appendTo="body"
          [(ngModel)]="draft.role" ariaLabelledBy="user-role" data-field="role"
          [disabled]="roleManagedByProvider()" fluid />
        <small class="text-muted" data-role-help>{{ roleInfo[draft.role].description }}</small>
        @if (roleManagedByProvider()) {
          <small class="text-muted" data-role-managed>
            <i class="bi bi-link-45deg" aria-hidden="true"></i>
            El rol lo decide {{ providerName() }} en cada inicio de sesión, según sus grupos.
          </small>
        }
        @if (!editing()) {
          <small class="text-muted">Se generará una contraseña temporal de un solo uso que deberá cambiar al entrar.</small>
        }
        @if (formError(); as message) {
          <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
        }
      </div>
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="formOpen.set(false)" />
        <p-button [label]="editing() ? 'Guardar' : 'Crear'" icon="bi bi-check-lg" [loading]="busy()"
          (onClick)="save()" data-action="save-user" />
      </ng-template>
    </p-dialog>

    <p-dialog header="Contraseña temporal" [visible]="!!issued()" (visibleChange)="!$event && issued.set(null)"
      [modal]="true" [closable]="true" [style]="{ width: 'min(32rem, 95vw)' }" data-dialog="temporary-password">
      @if (issued(); as t) {
        <p>Contraseña temporal de <strong>{{ t.user.email }}</strong>:</p>
        <div class="secret">
          <code data-temporary-password>{{ t.temporaryPassword }}</code>
          <p-button icon="bi bi-clipboard" size="small" severity="secondary" [text]="true"
            [ariaLabel]="copied() ? 'Copiada' : 'Copiar'" [pTooltip]="copied() ? 'Copiada' : 'Copiar'"
            (onClick)="copy(t.temporaryPassword)" data-action="copy" />
        </div>
        <p-message severity="warn" icon="bi bi-eye-slash">
          Solo se muestra ahora: InfraWard no la guarda. Vale para un único inicio de sesión hasta el
          {{ t.expiresAt | date: 'short' }} y obliga a elegir una nueva.
        </p-message>
      }
      <ng-template #footer>
        <p-button label="Hecho" (onClick)="issued.set(null)" data-action="close-temporary" />
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
    /* El email no se parte letra a letra: la tabla se desplaza dentro de su caja. */
    .email {
      overflow-wrap: break-word;
      min-width: 10rem;
    }
    tr.inactive td:not(.row-actions) {
      opacity: 0.6;
    }
    .row-actions {
      white-space: nowrap;
      text-align: right;
    }
    .access {
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem;
    }
    .hint {
      margin: 0 0 0.75rem;
    }
    .form {
      display: grid;
      gap: 0.4rem;
    }
    .form label, .form .label {
      font-weight: 600;
      margin-top: 0.5rem;
    }
    .form small {
      display: block;
    }
    .secret {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }
    .secret code {
      font-size: 1.15rem;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      background: var(--p-content-hover-background);
      overflow-wrap: anywhere;
      user-select: all;
    }
  `,
})
export class UsersSettings implements OnInit {
  private readonly api = inject(UsersApi);
  private readonly mfa = inject(MfaApi);
  private readonly messages = inject(MessageService);
  private readonly confirm = inject(ConfirmationService);
  protected readonly auth = inject(AuthService);

  protected readonly roleInfo = ROLE_INFO;
  protected readonly roleSeverity = roleSeverity;
  protected readonly roleLabel = roleLabel;
  /** De menos a más permisos. */
  protected readonly roleOptions: { label: string; value: UserRole }[] = [...USER_ROLES]
    .reverse()
    .map((value) => ({ value, label: ROLE_INFO[value].label }));

  protected readonly users = signal<UserSummary[]>([]);
  protected readonly providers = signal<AuthProviders | null>(null);
  /** Hasta saberlo, como siempre: con login local. */
  protected readonly localLogin = computed(() => this.providers()?.local ?? true);
  protected readonly providerName = computed(() => this.providers()?.oidc?.name ?? 'el proveedor');
  /** Editando un usuario enlazado al proveedor OIDC (su rol no se cambia a mano). */
  protected readonly roleManagedByProvider = computed(
    () => !!this.editing()?.oidcLinked && !!this.providers()?.oidc,
  );
  /** Editando una cuenta cuyo email no se cambia aquí (OIDC, enlazada o de emergencia). */
  protected readonly emailLocked = computed(() => {
    const user = this.editing();
    return !!user && (user.origin === 'oidc' || user.oidcLinked || user.emergency);
  });
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly formOpen = signal(false);
  protected readonly editing = signal<UserSummary | null>(null);
  protected readonly formError = signal<string | null>(null);
  protected readonly issued = signal<TemporaryPasswordResponse | null>(null);
  protected readonly copied = signal(false);
  protected draft: { email: string; name: string; role: UserRole } = {
    email: '',
    name: '',
    role: 'viewer',
  };

  ngOnInit(): void {
    this.load();
    void this.auth.providers().then((p) => this.providers.set(p));
  }

  /** Las cuentas OIDC no tienen contraseña; sin login local, solo la de emergencia la usa. */
  protected canResetPassword(user: UserSummary): boolean {
    return user.origin === 'local' && (this.localLogin() || user.emergency);
  }

  private load(): void {
    this.api.list().subscribe({
      next: (users) => {
        this.users.set(users);
        this.loading.set(false);
      },
      error: (err: unknown) => {
        this.loading.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudieron cargar los usuarios.'));
      },
    });
  }

  protected openCreate(): void {
    this.editing.set(null);
    this.draft = { email: '', name: '', role: 'viewer' };
    this.formError.set(null);
    this.formOpen.set(true);
  }

  protected openEdit(user: UserSummary): void {
    this.editing.set(user);
    this.draft = { email: user.email, name: user.name, role: user.role };
    this.formError.set(null);
    this.formOpen.set(true);
  }

  protected save(): void {
    const user = this.editing();
    const name = this.draft.name.trim();
    const email = this.draft.email.trim();
    if (!name) return this.formError.set('Escribe un nombre.');
    const emailChanged = !!user && !this.emailLocked() && email.toLowerCase() !== user.email;
    if ((!user || emailChanged) && !EMAIL.test(email))
      return this.formError.set('Ese email no es válido.');
    this.busy.set(true);
    if (user) {
      const changes = {
        ...(name !== user.name ? { name } : {}),
        ...(emailChanged ? { email } : {}),
        ...(this.draft.role !== user.role && !this.roleManagedByProvider()
          ? { role: this.draft.role }
          : {}),
      };
      this.run(this.api.update(user.id, changes), () => {
        this.formOpen.set(false);
        this.messages.add({ severity: 'success', summary: 'Usuario guardado', life: 3000 });
      }, (m) => this.formError.set(m));
      return;
    }
    this.run(this.api.create({ email, name, role: this.draft.role }), (res) => {
      this.formOpen.set(false);
      this.showTemporary(res as TemporaryPasswordResponse);
    }, (m) => this.formError.set(m));
  }

  protected deactivate(user: UserSummary): void {
    this.confirm.confirm({
      header: 'Desactivar usuario',
      message: `${user.name} (${user.email}) no podrá entrar y sus sesiones abiertas se cerrarán al momento. ¿Seguir?`,
      acceptLabel: 'Desactivar',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () =>
        this.run(this.api.deactivate(user.id), () =>
          this.messages.add({ severity: 'success', summary: 'Usuario desactivado', detail: user.email, life: 4000 }),
        ),
    });
  }

  protected reactivate(user: UserSummary): void {
    this.run(this.api.reactivate(user.id), () =>
      this.messages.add({ severity: 'success', summary: 'Usuario reactivado', detail: user.email, life: 4000 }),
    );
  }

  protected resetPassword(user: UserSummary): void {
    this.confirm.confirm({
      header: 'Restablecer contraseña',
      message: `Se generará una contraseña temporal para ${user.email}; la actual dejará de valer y sus sesiones se cerrarán. ¿Seguir?`,
      acceptLabel: 'Restablecer',
      rejectLabel: 'Cancelar',
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () =>
        this.run(this.api.resetPassword(user.id), (res) =>
          this.showTemporary(res as TemporaryPasswordResponse),
        ),
    });
  }

  /** Perdió el dispositivo: se le quita el TOTP y se le cierran las sesiones (auditado). */
  protected resetMfa(user: UserSummary): void {
    this.confirm.confirm({
      header: 'Restablecer la verificación en dos pasos',
      message: `${user.email} perderá su app de autenticación y sus códigos de recuperación, y sus sesiones se cerrarán. ${
        user.role === 'admin' ? 'Al volver a entrar tendrá que configurarla de nuevo.' : 'Podrá volver a activarla en su perfil.'
      } ¿Seguir?`,
      acceptLabel: 'Restablecer',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () =>
        this.run(this.mfa.reset(user.id), () =>
          this.messages.add({
            severity: 'success',
            summary: 'Verificación en dos pasos restablecida',
            detail: user.email,
            life: 4000,
          }),
        ),
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

  private showTemporary(res: TemporaryPasswordResponse): void {
    this.copied.set(false);
    this.issued.set(res);
  }

  private run(
    request: Observable<unknown>,
    onDone: (value: unknown) => void,
    onError?: (message: string) => void,
  ): void {
    this.busy.set(true);
    request.subscribe({
      next: (value) => {
        this.busy.set(false);
        onDone(value);
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        const message = apiErrorMessage(err, 'No se pudo completar la acción.');
        if (onError) onError(message);
        else this.messages.add({ severity: 'error', summary: 'Error', detail: message, life: 6000 });
      },
    });
  }
}
