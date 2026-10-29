import { Component, inject, input, output, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type { MfaSetupResponse } from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { firstValueFrom } from 'rxjs';
import { MfaApi } from '../../core/api/mfa-api';
import { apiErrorMessage } from '../../shared/api-errors';
import { RecoveryCodes } from './recovery-codes';

/**
 * Alta de la verificación en dos pasos (o cambio de dispositivo): QR y secreto (una vez),
 * confirmación con un código de la app y los códigos de recuperación. Lo usan la página de alta
 * obligada y el perfil.
 */
@Component({
  selector: 'app-mfa-setup-flow',
  imports: [FormsModule, ButtonModule, InputTextModule, MessageModule, RecoveryCodes],
  template: `
    @if (recoveryCodes(); as codes) {
      <h3>Verificación en dos pasos activada</h3>
      <app-recovery-codes [codes]="codes" [account]="account()" />
      <div class="done">
        <p-button label="Ya los he guardado" icon="bi bi-check-lg" (onClick)="done.emit()"
          data-action="mfa-done" />
      </div>
    } @else if (setup(); as s) {
      <ol class="steps">
        <li>
          <p>Escanea este código con tu app de autenticación (Google Authenticator, Aegis, 1Password…).</p>
          <img [src]="s.qrDataUrl" alt="Código QR para la app de autenticación" class="qr" width="200" height="200"
            data-qr />
          <details>
            <summary>¿No puedes escanearlo? Escribe la clave</summary>
            <code class="secret" data-secret>{{ grouped(s.secret) }}</code>
          </details>
        </li>
        <li>
          <form (ngSubmit)="enable()" novalidate>
            <label for="mfa-setup-code">Escribe el código de 6 cifras que muestra la app</label>
            <div class="row">
              <input pInputText id="mfa-setup-code" name="code" [(ngModel)]="code" inputmode="numeric"
                autocomplete="one-time-code" maxlength="6" placeholder="123456" class="code" />
              <p-button type="submit" label="Activar" icon="bi bi-shield-check" [loading]="busy()"
                data-action="mfa-enable" />
            </div>
          </form>
        </li>
      </ol>
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" role="alert" data-mfa-error>{{ message }}</p-message>
      }
    } @else if (error(); as message) {
      <p-message severity="error" icon="bi bi-exclamation-triangle" role="alert">{{ message }}</p-message>
      <p-button label="Reintentar" icon="bi bi-arrow-clockwise" severity="secondary" size="small"
        (onClick)="start()" />
    } @else {
      <p class="text-muted"><i class="bi bi-hourglass-split" aria-hidden="true"></i> Preparando…</p>
    }
  `,
  styles: `
    .steps {
      display: grid;
      gap: 1.25rem;
      margin: 0 0 1rem;
      padding-left: 1.25rem;
    }
    .steps p {
      margin: 0 0 0.75rem;
    }
    .qr {
      display: block;
      width: 200px;
      height: 200px;
      padding: 8px;
      border-radius: 8px;
      /* El QR necesita fondo claro también en modo oscuro. */
      background: #fff;
    }
    details {
      margin-top: 0.6rem;
    }
    summary {
      cursor: pointer;
      color: var(--p-text-muted-color);
    }
    .secret {
      display: block;
      margin-top: 0.4rem;
      overflow-wrap: anywhere;
      letter-spacing: 0.05em;
    }
    label {
      display: block;
      margin-bottom: 0.4rem;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .code {
      width: 9rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      letter-spacing: 0.15em;
      font-size: 1.1rem;
    }
    h3 {
      font-size: 1.05rem;
      margin: 0 0 0.75rem;
    }
    .done {
      margin-top: 1rem;
    }
  `,
})
export class MfaSetupFlow implements OnInit {
  private readonly api = inject(MfaApi);
  readonly account = input<string>('');
  /** El usuario terminó (ya vio los códigos de recuperación). */
  readonly done = output();
  /** Se activó (antes de enseñar los códigos): para refrescar el estado. */
  readonly enabled = output();

  protected readonly setup = signal<MfaSetupResponse | null>(null);
  protected readonly recoveryCodes = signal<string[] | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected code = '';

  ngOnInit(): void {
    void this.start();
  }

  protected async start(): Promise<void> {
    this.error.set(null);
    try {
      this.setup.set(await firstValueFrom(this.api.setup()));
    } catch (err) {
      this.error.set(apiErrorMessage(err, 'No se pudo empezar la configuración.'));
    }
  }

  protected async enable(): Promise<void> {
    const code = this.code.trim();
    if (!/^\d{6}$/.test(code)) return this.error.set('Escribe las 6 cifras del código.');
    this.busy.set(true);
    this.error.set(null);
    try {
      const res = await firstValueFrom(this.api.enable(code));
      // El secreto ya no hace falta en pantalla.
      this.setup.set(null);
      this.recoveryCodes.set(res.recoveryCodes);
      this.enabled.emit();
    } catch (err) {
      this.code = '';
      this.error.set(apiErrorMessage(err, 'El código no es correcto.'));
    } finally {
      this.busy.set(false);
    }
  }

  protected grouped(secret: string): string {
    return secret.match(/.{1,4}/g)?.join(' ') ?? secret;
  }
}
