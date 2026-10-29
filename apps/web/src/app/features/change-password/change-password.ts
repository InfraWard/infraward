import { Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { PASSWORD_MIN_LENGTH } from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { PasswordModule } from '@openng/optimus-ui/password';
import { HOME_URL } from '../../core/auth/auth.guards';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { BrandMark } from '../../shared/brand-mark';
import { samePasswords } from '../settings/profile-card';

/**
 * Cambio obligado tras entrar con una contraseña temporal (alta o restablecimiento): la sesión
 * solo sirve para esto (15 min). La temporal ya se gastó al entrar: no se vuelve a pedir.
 */
@Component({
  selector: 'app-change-password',
  imports: [ReactiveFormsModule, ButtonModule, MessageModule, PasswordModule, BrandMark],
  template: `
    <main class="page">
      <section class="card">
        <header>
          <app-brand-mark [size]="36" />
          <h1>Elige tu contraseña</h1>
          <p>
            Has entrado con una contraseña temporal, {{ auth.user()?.name }}. Para seguir, elige una
            nueva (al menos {{ minLength }} caracteres).
          </p>
        </header>
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <input type="email" name="username" autocomplete="username" [value]="auth.user()?.email ?? ''" hidden />
          <div class="field">
            <label for="new-password">Nueva contraseña</label>
            <p-password inputId="new-password" formControlName="newPassword" autocomplete="new-password"
              [feedback]="false" [toggleMask]="true" fluid />
          </div>
          <div class="field">
            <label for="repeat-password">Repítela</label>
            <p-password inputId="repeat-password" formControlName="repeat" autocomplete="new-password"
              [feedback]="false" [toggleMask]="true" fluid />
          </div>
          @if (error(); as message) {
            <p-message severity="error" icon="bi bi-exclamation-triangle" role="alert">{{ message }}</p-message>
          }
          <p-button type="submit" label="Guardar y entrar" icon="bi bi-check-lg" [loading]="saving()" fluid
            data-action="save-password" />
          <p-button label="Salir" severity="secondary" [text]="true" fluid (onClick)="logout()" />
        </form>
      </section>
    </main>
  `,
  styles: `
    .page {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 1rem;
      background: var(--p-app-background);
    }
    .card {
      width: min(26rem, 100%);
      padding: 2rem;
      border-radius: 12px;
      background: var(--p-content-background);
      border: 1px solid var(--p-content-border-color);
    }
    header h1 {
      font-size: 1.4rem;
      margin: 0.75rem 0 0.4rem;
    }
    header p {
      margin: 0 0 1.25rem;
      color: var(--p-text-muted-color);
    }
    form {
      display: grid;
      gap: 0.9rem;
    }
    label {
      display: block;
      margin-bottom: 0.3rem;
      font-weight: 600;
    }
  `,
})
export class ChangePassword {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly minLength = PASSWORD_MIN_LENGTH;
  protected readonly saving = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly form = inject(FormBuilder).nonNullable.group(
    {
      newPassword: ['', [Validators.required, Validators.minLength(PASSWORD_MIN_LENGTH)]],
      repeat: ['', Validators.required],
    },
    { validators: samePasswords },
  );

  async submit(): Promise<void> {
    this.error.set(null);
    if (this.form.controls.newPassword.invalid)
      return this.error.set(`Al menos ${PASSWORD_MIN_LENGTH} caracteres.`);
    if (this.form.hasError('mismatch')) return this.error.set('Las contraseñas no coinciden.');
    this.saving.set(true);
    try {
      await this.auth.changePassword({
        currentPassword: '',
        newPassword: this.form.getRawValue().newPassword,
      });
      await this.router.navigateByUrl(HOME_URL);
    } catch (err) {
      this.error.set(apiErrorMessage(err, 'No se pudo cambiar la contraseña.'));
    } finally {
      this.saving.set(false);
    }
  }

  async logout(): Promise<void> {
    // Con sesión del proveedor OIDC, el navegador sale a cerrarla y vuelve a /login.
    if (!(await this.auth.logout())) await this.router.navigate(['/login']);
  }
}
