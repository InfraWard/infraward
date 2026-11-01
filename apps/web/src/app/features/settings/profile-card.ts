import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import {
  FormBuilder,
  ReactiveFormsModule,
  Validators,
  type AbstractControl,
  type ValidationErrors,
} from '@angular/forms';
import { PASSWORD_MIN_LENGTH, type UserProfile } from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { PasswordModule } from '@openng/optimus-ui/password';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { ROLE_INFO, roleSeverity } from '../../shared/role-labels';
import { MfaCard } from './mfa-card';

/** La nueva y su repetición coinciden. */
export function samePasswords(group: AbstractControl): ValidationErrors | null {
  const value = group.value as { newPassword?: string; repeat?: string };
  return value.newPassword === value.repeat ? null : { mismatch: true };
}

/**
 * Perfil propio en Ajustes: cabecera con avatar, nombre (editable en el sitio), email, rol y cómo
 * entra; debajo, «Cuenta» y «Seguridad» como filas de ajustes. Cambiar el email o la contraseña
 * (pidiendo la actual) va en un diálogo; la verificación en dos pasos es una fila de Seguridad.
 */
@Component({
  selector: 'app-profile-card',
  imports: [
    DatePipe,
    ReactiveFormsModule,
    ButtonModule,
    CardModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    PasswordModule,
    TagModule,
    TooltipModule,
    MfaCard,
  ],
  template: `
    @if (auth.user(); as me) {
      <section class="profile" data-block="profile">
        <header class="hero">
          <div class="avatar" aria-hidden="true">{{ initials(me.name) }}</div>
          <div class="who">
            @if (editingName()) {
              <form class="name-form" [formGroup]="nameForm" (ngSubmit)="saveName()" novalidate>
                <label class="sr-only" for="profile-name">Nombre</label>
                <input pInputText id="profile-name" formControlName="name" autocomplete="name" maxlength="120" />
                <p-button type="submit" label="Guardar" icon="bi bi-check-lg" size="small"
                  [loading]="savingName()" [disabled]="nameForm.invalid || nameForm.value.name?.trim() === me.name"
                  data-action="save-name" />
                <p-button label="Cancelar" severity="secondary" [text]="true" size="small" (onClick)="cancelName()" />
              </form>
            } @else {
              <h2>
                <span data-profile-name>{{ me.name }}</span>
                <p-button icon="bi bi-pencil" [text]="true" [rounded]="true" severity="secondary" size="small"
                  ariaLabel="Cambiar el nombre" pTooltip="Cambiar el nombre" (onClick)="editName(me.name)"
                  data-action="edit-name" />
              </h2>
            }
            <p class="email">{{ me.email }}</p>
            <div class="chips">
              <p-tag [value]="roleInfo[me.role].label" [severity]="roleSeverity(me.role)" />
              <span class="chip"><i class="bi {{ accessIcon(me) }}" aria-hidden="true"></i> {{ accessShort(me) }}</span>
              <span class="chip muted-chip"><i class="bi bi-calendar3" aria-hidden="true"></i> Desde {{ me.createdAt | date: 'longDate' }}</span>
            </div>
          </div>
        </header>

        <div class="cols">
          <p-card styleClass="block">
            <ng-template #title><i class="bi bi-person" aria-hidden="true"></i> Cuenta</ng-template>
            <div class="rows">
              <div class="row">
                <i class="bi bi-envelope icon" aria-hidden="true"></i>
                <div class="text">
                  <span class="label">Email</span>
                  <span class="value">{{ me.email }}</span>
                  @if (!auth.canChangeEmail()) {
                    <small class="text-muted" data-email-managed>
                      {{ me.origin === 'oidc' || me.oidcLinked ? 'Lo gestiona el proveedor de identidad.'
                        : 'Lo cambia un administrador.' }}
                    </small>
                  }
                </div>
                @if (auth.canChangeEmail()) {
                  <p-button label="Cambiar" severity="secondary" [outlined]="true" size="small"
                    (onClick)="openEmail()" data-action="change-email" />
                }
              </div>
              <div class="row">
                <i class="bi bi-person-badge icon" aria-hidden="true"></i>
                <div class="text">
                  <span class="label">Rol</span>
                  <span class="value">{{ roleInfo[me.role].label }}</span>
                  <small class="text-muted">{{ roleInfo[me.role].description }}</small>
                  @if (me.oidcLinked) {
                    <small class="text-muted" data-role-from-provider>
                      Lo deciden tus grupos del proveedor de identidad en cada inicio de sesión.
                    </small>
                  }
                </div>
              </div>
              <div class="row">
                <i class="bi bi-box-arrow-in-right icon" aria-hidden="true"></i>
                <div class="text">
                  <span class="label">Cómo entras</span>
                  <span class="value" data-access>{{ me.origin === 'oidc' ? 'Proveedor de identidad (OIDC)' : me.oidcLinked
                    ? 'Email y contraseña, o proveedor de identidad (OIDC)' : 'Email y contraseña' }}</span>
                </div>
              </div>
            </div>
          </p-card>

          <p-card styleClass="block">
            <ng-template #title><i class="bi bi-shield-lock" aria-hidden="true"></i> Seguridad</ng-template>
            <div class="rows">
              <div class="row">
                <i class="bi bi-key icon" aria-hidden="true"></i>
                <div class="text">
                  <span class="label">Contraseña</span>
                  @if (me.origin === 'oidc') {
                    <small class="text-muted" data-no-password>
                      Entras con el proveedor de identidad: InfraWard no guarda ninguna contraseña tuya.
                    </small>
                  } @else {
                    <small class="text-muted">Al menos {{ minLength }} caracteres. Cambiarla cierra tus otras sesiones.</small>
                  }
                </div>
                @if (me.origin !== 'oidc') {
                  <p-button label="Cambiar" severity="secondary" [outlined]="true" size="small"
                    (onClick)="openPassword()" data-action="change-password" />
                }
              </div>
              <app-mfa-card />
            </div>
          </p-card>
        </div>

        <p-dialog header="Cambiar el email" [visible]="emailOpen()" (visibleChange)="!$event && emailOpen.set(false)"
          [modal]="true" [style]="{ width: 'min(28rem, 95vw)' }" data-dialog="change-email">
          <form class="dialog-form" [formGroup]="emailForm" (ngSubmit)="changeEmail()" novalidate>
            <div class="field">
              <label for="new-email">Nuevo email</label>
              <input pInputText id="new-email" type="email" formControlName="email" autocomplete="email" maxlength="320" />
            </div>
            <div class="field">
              <label for="email-current-password">Contraseña actual</label>
              <p-password inputId="email-current-password" formControlName="currentPassword"
                autocomplete="current-password" [feedback]="false" [toggleMask]="true" fluid />
            </div>
            @if (emailError(); as message) {
              <p-message severity="error" icon="bi bi-exclamation-triangle" data-email-error>{{ message }}</p-message>
            }
            <div class="dialog-actions">
              <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="emailOpen.set(false)" />
              <p-button type="submit" label="Cambiar email" icon="bi bi-envelope" [loading]="savingEmail()"
                data-action="submit-email" />
            </div>
          </form>
        </p-dialog>

        <p-dialog header="Cambiar la contraseña" [visible]="passwordOpen()" (visibleChange)="!$event && passwordOpen.set(false)"
          [modal]="true" [style]="{ width: 'min(28rem, 95vw)' }" data-dialog="change-password">
          <form class="dialog-form" [formGroup]="passwordForm" (ngSubmit)="changePassword()" novalidate>
            <div class="field">
              <label for="current-password">Contraseña actual</label>
              <p-password inputId="current-password" formControlName="currentPassword"
                autocomplete="current-password" [feedback]="false" [toggleMask]="true" fluid />
            </div>
            <div class="field">
              <label for="new-password">Nueva contraseña</label>
              <p-password inputId="new-password" formControlName="newPassword"
                autocomplete="new-password" [feedback]="false" [toggleMask]="true" fluid />
              <small class="text-muted">Al menos {{ minLength }} caracteres. Se cerrarán tus otras sesiones.</small>
            </div>
            <div class="field">
              <label for="repeat-password">Repite la nueva</label>
              <p-password inputId="repeat-password" formControlName="repeat"
                autocomplete="new-password" [feedback]="false" [toggleMask]="true" fluid />
            </div>
            @if (passwordForm.touched && passwordForm.hasError('mismatch')) {
              <p-message severity="error" variant="simple" size="small">Las contraseñas nuevas no coinciden.</p-message>
            }
            @if (passwordError(); as message) {
              <p-message severity="error" icon="bi bi-exclamation-triangle" data-password-error>{{ message }}</p-message>
            }
            <div class="dialog-actions">
              <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="passwordOpen.set(false)" />
              <p-button type="submit" label="Cambiar contraseña" icon="bi bi-key" [loading]="savingPassword()"
                data-action="submit-password" />
            </div>
          </form>
        </p-dialog>
      </section>
    }
  `,
  styles: `
    .profile {
      display: grid;
      gap: 1rem;
    }
    .hero {
      display: flex;
      align-items: center;
      gap: 1.25rem;
      padding: 1.25rem 1.5rem;
      border: 1px solid var(--p-content-border-color);
      border-radius: 12px;
      background:
        linear-gradient(120deg, color-mix(in srgb, var(--p-primary-color) 12%, transparent), transparent 60%),
        var(--p-content-background);
    }
    .avatar {
      flex: none;
      width: 4.5rem;
      height: 4.5rem;
      border-radius: 50%;
      display: grid;
      place-items: center;
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: 0.02em;
      color: var(--p-primary-contrast-color);
      background: var(--p-primary-color);
      box-shadow: 0 0 0 4px color-mix(in srgb, var(--p-primary-color) 25%, transparent);
    }
    .who {
      min-width: 0;
      display: grid;
      gap: 0.35rem;
    }
    h2 {
      margin: 0;
      font-size: 1.4rem;
      display: flex;
      align-items: center;
      gap: 0.25rem;
      overflow-wrap: anywhere;
    }
    .email {
      margin: 0;
      color: var(--p-text-muted-color);
      overflow-wrap: anywhere;
    }
    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      align-items: center;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.8rem;
      border: 1px solid var(--p-content-border-color);
      background: var(--p-content-background);
    }
    .muted-chip {
      color: var(--p-text-muted-color);
    }
    .name-form {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .name-form input {
      flex: 1 1 14rem;
      min-width: 0;
    }
    .cols {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 1rem;
      align-items: start;
    }
    @media (max-width: 1000px) {
      .cols {
        grid-template-columns: 1fr;
      }
    }
    .rows {
      display: grid;
    }
    .row,
    :host ::ng-deep app-mfa-card .row {
      display: flex;
      align-items: center;
      gap: 0.9rem;
      padding: 0.85rem 0;
      border-top: 1px solid var(--p-content-border-color);
    }
    .rows > .row:first-child {
      border-top: 0;
      padding-top: 0.25rem;
    }
    .icon,
    :host ::ng-deep app-mfa-card .icon {
      flex: none;
      width: 2.25rem;
      height: 2.25rem;
      border-radius: 8px;
      display: grid;
      place-items: center;
      font-size: 1.05rem;
      color: var(--p-primary-color);
      background: color-mix(in srgb, var(--p-primary-color) 12%, transparent);
    }
    .text,
    :host ::ng-deep app-mfa-card .text {
      flex: 1;
      min-width: 0;
      display: grid;
      gap: 0.15rem;
    }
    .label,
    :host ::ng-deep app-mfa-card .label {
      font-weight: 600;
    }
    .value {
      overflow-wrap: anywhere;
    }
    .dialog-form {
      display: grid;
      gap: 0.9rem;
    }
    .field label {
      display: block;
      margin-bottom: 0.3rem;
      color: var(--p-text-muted-color);
    }
    .field input {
      width: 100%;
    }
    .field small {
      display: block;
      margin-top: 0.3rem;
    }
    .dialog-actions {
      display: flex;
      justify-content: flex-end;
      gap: 0.5rem;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
    }
    @media (max-width: 600px) {
      .hero {
        flex-direction: column;
        align-items: flex-start;
        padding: 1rem;
      }
      .row,
      :host ::ng-deep app-mfa-card .row {
        flex-wrap: wrap;
      }
    }
  `,
})
export class ProfileCard {
  protected readonly auth = inject(AuthService);
  private readonly messages = inject(MessageService);
  private readonly fb = inject(FormBuilder).nonNullable;
  protected readonly minLength = PASSWORD_MIN_LENGTH;
  protected readonly roleInfo = ROLE_INFO;
  protected readonly roleSeverity = roleSeverity;

  protected readonly editingName = signal(false);
  protected readonly emailOpen = signal(false);
  protected readonly passwordOpen = signal(false);
  protected readonly savingName = signal(false);
  protected readonly savingPassword = signal(false);
  protected readonly passwordError = signal<string | null>(null);
  protected readonly savingEmail = signal(false);
  protected readonly emailError = signal<string | null>(null);

  protected readonly emailForm = this.fb.group({
    email: ['', [Validators.required, Validators.email, Validators.maxLength(320)]],
    currentPassword: ['', Validators.required],
  });

  protected readonly nameForm = this.fb.group({
    name: [
      this.auth.user()?.name ?? '',
      [Validators.required, Validators.maxLength(120), Validators.pattern(/\S/)],
    ],
  });

  protected readonly passwordForm = this.fb.group(
    {
      currentPassword: ['', Validators.required],
      newPassword: ['', [Validators.required, Validators.minLength(PASSWORD_MIN_LENGTH)]],
      repeat: ['', Validators.required],
    },
    { validators: samePasswords },
  );

  /** «Ana García» → «AG»; «admin» → «A». */
  protected initials(name: string): string {
    const words = name.trim().split(/\s+/).filter(Boolean);
    const letters = (words.length > 1 ? [words[0]!, words.at(-1)!] : words).map((w) =>
      [...w][0]!.toUpperCase(),
    );
    return letters.join('') || '?';
  }

  protected accessShort(me: UserProfile): string {
    return me.origin === 'oidc' ? 'OIDC' : me.oidcLinked ? 'Contraseña u OIDC' : 'Contraseña';
  }

  protected accessIcon(me: UserProfile): string {
    return me.origin === 'oidc' || me.oidcLinked ? 'bi-person-check' : 'bi-key';
  }

  protected editName(current: string): void {
    this.nameForm.setValue({ name: current });
    this.editingName.set(true);
  }

  protected cancelName(): void {
    this.editingName.set(false);
  }

  protected openEmail(): void {
    this.emailForm.reset();
    this.emailError.set(null);
    this.emailOpen.set(true);
  }

  protected openPassword(): void {
    this.passwordForm.reset();
    this.passwordError.set(null);
    this.passwordOpen.set(true);
  }

  protected async saveName(): Promise<void> {
    if (this.nameForm.invalid) return;
    this.savingName.set(true);
    try {
      const user = await this.auth.updateName(this.nameForm.getRawValue().name.trim());
      this.nameForm.setValue({ name: user.name });
      this.editingName.set(false);
      this.messages.add({ severity: 'success', summary: 'Nombre guardado', life: 3000 });
    } catch (err) {
      this.messages.add({
        severity: 'error',
        summary: 'No se pudo guardar',
        detail: apiErrorMessage(err, 'Error al guardar el nombre.'),
        life: 6000,
      });
    } finally {
      this.savingName.set(false);
    }
  }

  protected async changeEmail(): Promise<void> {
    this.emailForm.markAllAsTouched();
    this.emailError.set(null);
    const { email, currentPassword } = this.emailForm.getRawValue();
    if (this.emailForm.controls.email.invalid) return this.emailError.set('Ese email no es válido.');
    if (this.emailForm.invalid) return this.emailError.set('Escribe tu contraseña actual.');
    if (email.trim().toLowerCase() === this.auth.user()?.email)
      return this.emailError.set('Ese ya es tu email.');
    this.savingEmail.set(true);
    try {
      const user = await this.auth.changeEmail({ email: email.trim(), currentPassword });
      this.emailForm.reset();
      this.emailOpen.set(false);
      this.messages.add({
        severity: 'success',
        summary: 'Email cambiado',
        detail: `Ahora entras con ${user.email}.`,
        life: 5000,
      });
    } catch (err) {
      this.emailError.set(apiErrorMessage(err, 'No se pudo cambiar el email.'));
      this.emailForm.controls.currentPassword.reset();
    } finally {
      this.savingEmail.set(false);
    }
  }

  protected async changePassword(): Promise<void> {
    this.passwordForm.markAllAsTouched();
    this.passwordError.set(null);
    if (this.passwordForm.invalid) {
      if (this.passwordForm.controls.newPassword.hasError('minlength'))
        this.passwordError.set(`La nueva contraseña debe tener al menos ${PASSWORD_MIN_LENGTH} caracteres.`);
      return;
    }
    const { currentPassword, newPassword } = this.passwordForm.getRawValue();
    this.savingPassword.set(true);
    try {
      await this.auth.changePassword({ currentPassword, newPassword });
      this.passwordForm.reset();
      this.passwordOpen.set(false);
      this.messages.add({
        severity: 'success',
        summary: 'Contraseña cambiada',
        detail: 'Tus otras sesiones se han cerrado.',
        life: 5000,
      });
    } catch (err) {
      this.passwordError.set(apiErrorMessage(err, 'No se pudo cambiar la contraseña.'));
      this.passwordForm.controls.currentPassword.reset();
    } finally {
      this.savingPassword.set(false);
    }
  }
}
