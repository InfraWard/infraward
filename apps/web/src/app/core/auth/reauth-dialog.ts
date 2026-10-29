import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { SENSITIVE_ACTIONS } from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { AuthService } from './auth.service';
import { ReauthService } from './reauth.service';

/**
 * Diálogo único de reautenticación (step-up): código TOTP o de recuperación para las sesiones
 * locales, nuevo login en el proveedor para las OIDC, o el aviso de activar la verificación en
 * dos pasos si aún no la tiene. Vive en el shell.
 */
@Component({
  selector: 'app-reauth-dialog',
  imports: [FormsModule, ButtonModule, DialogModule, InputTextModule, MessageModule],
  template: `
    <p-dialog header="Confirma que eres tú" [visible]="!!reauth.prompt()" (visibleChange)="!$event && cancel()"
      [modal]="true" [closable]="true" [draggable]="false" [style]="{ width: 'min(26rem, 95vw)' }"
      data-dialog="reauth">
      @if (reauth.prompt(); as p) {
        <p class="action"><i class="bi bi-shield-lock" aria-hidden="true"></i> {{ actionLabel() }}</p>
        @switch (p.kind) {
          @case ('totp') {
            <form (ngSubmit)="submit()" novalidate>
              <label for="reauth-code">
                {{ recovery() ? 'Código de recuperación' : 'Código de tu app de autenticación' }}
              </label>
              <input pInputText id="reauth-code" name="code" [(ngModel)]="code" autocomplete="one-time-code"
                [attr.inputmode]="recovery() ? 'text' : 'numeric'" [maxlength]="recovery() ? 19 : 6"
                [placeholder]="recovery() ? 'xxxx-xxxx-xxxx-xxxx' : '123456'" class="code" fluid />
              <small class="text-muted">Durante unos minutos no te lo volveremos a pedir.</small>
              @if (error(); as message) {
                <p-message severity="error" icon="bi bi-exclamation-triangle" role="alert" data-reauth-error>
                  {{ message }}</p-message>
              }
              <div class="actions">
                <p-button type="button" [text]="true" size="small" (onClick)="toggleRecovery()"
                  [label]="recovery() ? 'Usar la app' : 'Usar un código de recuperación'" />
                <p-button type="submit" label="Confirmar" icon="bi bi-check-lg" [loading]="busy()"
                  data-action="reauth-submit" />
              </div>
            </form>
          }
          @case ('oidc') {
            <p>Para continuar, vuelve a entrar en {{ providerName() }}. Después vuelves aquí y repites la acción.</p>
            <div class="actions">
              <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="cancel()" />
              <p-button [label]="'Continuar con ' + providerName()" icon="bi bi-box-arrow-up-right"
                [loading]="busy()" (onClick)="goToProvider()" data-action="reauth-oidc" />
            </div>
          }
          @case ('setup') {
            <p>Para hacer esto necesitas activar la verificación en dos pasos en tu perfil.</p>
            <div class="actions">
              <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="cancel()" />
              <p-button label="Ir a tu perfil" icon="bi bi-person" (onClick)="goToProfile()"
                data-action="reauth-setup" />
            </div>
          }
        }
      }
    </p-dialog>
  `,
  styles: `
    .action {
      margin: 0 0 1rem;
      font-weight: 600;
    }
    form {
      display: grid;
      gap: 0.5rem;
    }
    label {
      color: var(--p-text-muted-color);
    }
    .code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      letter-spacing: 0.15em;
      font-size: 1.15rem;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 0.5rem;
      margin-top: 0.75rem;
    }
  `,
})
export class ReauthDialog {
  protected readonly reauth = inject(ReauthService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  protected code = '';
  protected readonly recovery = signal(false);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly providerName = signal('el proveedor');
  protected readonly actionLabel = computed(() => {
    const p = this.reauth.prompt();
    return p ? SENSITIVE_ACTIONS[p.action] : '';
  });

  constructor() {
    // Cada vez que se abre, desde cero (y el nombre del proveedor si hace falta).
    effect(() => {
      const p = this.reauth.prompt();
      if (!p) return;
      this.code = '';
      this.recovery.set(false);
      this.error.set(null);
      this.busy.set(false);
      if (p.kind === 'oidc')
        void this.auth.providers().then((v) => v.oidc && this.providerName.set(v.oidc.name));
    });
  }

  protected toggleRecovery(): void {
    this.recovery.update((v) => !v);
    this.code = '';
    this.error.set(null);
  }

  protected async submit(): Promise<void> {
    const code = this.code.trim();
    if (!code || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      await this.auth.reauthenticate(code, this.reauth.prompt()?.action);
      this.reauth.complete(true);
    } catch (err) {
      this.error.set(reauthError(err));
      this.code = '';
    } finally {
      this.busy.set(false);
    }
  }

  protected goToProvider(): void {
    this.busy.set(true);
    // Vuelve a la misma página con `?reauth=ok` (el shell avisa de que puede repetir la acción).
    this.auth.startOidcReauth(this.router.url);
  }

  protected goToProfile(): void {
    this.reauth.complete(false);
    void this.router.navigate(['/settings']);
  }

  protected cancel(): void {
    if (this.reauth.prompt()) this.reauth.complete(false);
  }
}

function reauthError(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 400) return 'El código no es correcto.';
    if (err.status === 429) return 'Demasiados intentos. Espera un minuto y vuelve a probar.';
    if (err.status === 0) return 'No se puede conectar con la API.';
    const message = (err.error as { message?: unknown } | null)?.message;
    if (typeof message === 'string') return message;
  }
  return 'No se pudo confirmar tu identidad.';
}
