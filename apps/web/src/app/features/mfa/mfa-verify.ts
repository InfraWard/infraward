import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { safeReturnUrl } from '../../core/auth/auth.guards';
import { AuthService } from '../../core/auth/auth.service';
import { BrandMark } from '../../shared/brand-mark';

/**
 * Segundo paso del login: código de la app de autenticación o uno de recuperación. La sesión
 * intermedia dura 5 minutos y admite 5 códigos incorrectos.
 */
@Component({
  selector: 'app-mfa-verify',
  imports: [FormsModule, ButtonModule, InputTextModule, MessageModule, BrandMark],
  template: `
    <main class="page">
      <section class="card">
        <header>
          <app-brand-mark [size]="36" />
          <h1>Verificación en dos pasos</h1>
          <p>
            @if (recovery()) {
              Escribe uno de tus códigos de recuperación. Cada uno sirve una sola vez.
            } @else {
              Escribe el código de 6 cifras de tu app de autenticación.
            }
          </p>
        </header>
        <form (ngSubmit)="submit()" novalidate>
          <label for="mfa-code" class="sr-only">{{ recovery() ? 'Código de recuperación' : 'Código' }}</label>
          <input pInputText id="mfa-code" name="code" [(ngModel)]="code" autocomplete="one-time-code"
            [attr.inputmode]="recovery() ? 'text' : 'numeric'" [maxlength]="recovery() ? 19 : 6"
            [placeholder]="recovery() ? 'xxxx-xxxx-xxxx-xxxx' : '123456'" class="code" fluid />
          @if (error(); as message) {
            <p-message severity="error" icon="bi bi-exclamation-triangle" role="alert" data-mfa-error>
              {{ message }}</p-message>
          }
          <p-button type="submit" label="Entrar" icon="bi bi-box-arrow-in-right" [loading]="busy()" fluid
            data-action="mfa-verify" />
          <p-button type="button" [text]="true" size="small" fluid (onClick)="toggleRecovery()"
            [label]="recovery() ? 'Usar la app de autenticación' : 'He perdido el móvil: usar un código de recuperación'"
            data-action="toggle-recovery" />
          <p-button type="button" label="Volver" severity="secondary" [text]="true" size="small" fluid
            (onClick)="back()" />
        </form>
      </section>
    </main>
  `,
  styleUrl: './mfa-page.scss',
  styles: `
    form {
      display: grid;
      gap: 0.75rem;
    }
    .code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      letter-spacing: 0.2em;
      font-size: 1.3rem;
      text-align: center;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
    }
  `,
})
export class MfaVerify {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  /** Ruta a la que volver tras entrar. */
  readonly returnUrl = input<string>();

  protected code = '';
  protected readonly recovery = signal(false);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected toggleRecovery(): void {
    this.recovery.update((v) => !v);
    this.code = '';
    this.error.set(null);
  }

  async submit(): Promise<void> {
    const code = this.code.trim();
    if (!code || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      const session = await this.auth.verifyMfa(code);
      await this.router.navigateByUrl(
        session.mustChangePassword ? '/change-password' : safeReturnUrl(this.returnUrl()),
      );
    } catch (err) {
      this.code = '';
      if (err instanceof HttpErrorResponse && err.status === 401) {
        // Demasiados códigos incorrectos (o caducó): hay que empezar de nuevo.
        this.auth.clear();
        await this.router.navigate(['/login'], { queryParams: { mfaFailed: 1 } });
        return;
      }
      this.error.set(verifyError(err));
    } finally {
      this.busy.set(false);
    }
  }

  protected async back(): Promise<void> {
    await this.auth.logout();
    await this.router.navigate(['/login']);
  }
}

function verifyError(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 400) return 'El código no es correcto.';
    if (err.status === 429) return 'Demasiados intentos. Espera un minuto y vuelve a probar.';
    if (err.status === 0) return 'No se puede conectar con la API.';
  }
  return 'No se pudo comprobar el código.';
}
