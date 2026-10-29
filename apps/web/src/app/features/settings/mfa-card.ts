import { Component, inject, signal, type OnInit } from '@angular/core';
import type { MfaStatus } from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { TagModule } from '@openng/optimus-ui/tag';
import { firstValueFrom } from 'rxjs';
import { MfaApi } from '../../core/api/mfa-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import { MfaSetupFlow } from '../mfa/mfa-setup-flow';
import { RecoveryCodes } from '../mfa/recovery-codes';

/**
 * Verificación en dos pasos propia (fila de «Seguridad» en Ajustes › Perfil): activarla, cambiar de dispositivo,
 * generar códigos de recuperación nuevos y, si no es obligatoria, desactivarla. Las tres últimas
 * piden reautenticación (el interceptor abre el diálogo y repite la petición).
 */
@Component({
  selector: 'app-mfa-card',
  imports: [ButtonModule, DialogModule, TagModule, MfaSetupFlow, RecoveryCodes],
  template: `
    @if (auth.user(); as me) {
      <!-- Fila de «Seguridad» del perfil (los estilos de fila los pone el perfil). -->
      <div class="row mfa" data-block="mfa">
        <i class="bi bi-phone icon" aria-hidden="true"></i>
        <div class="text">
          <span class="label">Verificación en dos pasos</span>
          @if (me.origin === 'oidc') {
            <small class="text-muted" data-mfa-provider>La aplica tu proveedor de identidad.</small>
          } @else if (status(); as s) {
            <span class="state">
              @if (s.enabled) {
                <p-tag value="Activada" severity="success" icon="bi bi-shield-check" data-mfa-state="on" />
                <small [class.low]="s.recoveryCodesLeft <= 3" class="text-muted" data-recovery-left>
                  Te quedan {{ s.recoveryCodesLeft }} códigos de recuperación.
                </small>
              } @else {
                <p-tag value="Desactivada" severity="secondary" icon="bi bi-shield" data-mfa-state="off" />
                <small class="text-muted">Además de la contraseña, un código de una app de autenticación.</small>
              }
            </span>
            @if (s.required) {
              <small class="text-muted" data-mfa-required>Obligatoria para los administradores.</small>
            }
            @if (me.oidcLinked) {
              <small class="text-muted">Se pide al entrar con contraseña; con el proveedor, la aplica él.</small>
            }
          }
        </div>
        @if (me.origin !== 'oidc' && status(); as s) {
          <div class="actions">
            @if (s.enabled) {
              <p-button label="Cambiar de dispositivo" icon="bi bi-phone" severity="secondary" [outlined]="true" size="small"
                (onClick)="setupOpen.set(true)" data-action="mfa-replace" />
              <p-button label="Códigos nuevos" icon="bi bi-arrow-repeat" severity="secondary" [text]="true" size="small"
                [loading]="busy()" (onClick)="regenerate()" data-action="mfa-regenerate" />
              @if (!s.required) {
                <p-button label="Desactivar" icon="bi bi-shield-x" severity="danger" [text]="true" size="small"
                  (onClick)="disable()" data-action="mfa-disable" />
              }
            } @else {
              <p-button label="Activar" icon="bi bi-shield-plus" size="small" (onClick)="setupOpen.set(true)"
                data-action="mfa-setup" />
            }
          </div>
        }
      </div>

      <p-dialog [header]="status()?.enabled ? 'Cambiar de dispositivo' : 'Activar la verificación en dos pasos'"
        [visible]="setupOpen()" (visibleChange)="!$event && closeSetup()" [modal]="true"
        [style]="{ width: 'min(34rem, 95vw)' }" data-dialog="mfa-setup">
        @if (setupOpen()) {
          <app-mfa-setup-flow [account]="me.email" (enabled)="refresh()" (done)="closeSetup()" />
        }
      </p-dialog>

      <p-dialog header="Códigos de recuperación nuevos" [visible]="!!newCodes()"
        (visibleChange)="!$event && newCodes.set(null)" [modal]="true" [style]="{ width: 'min(34rem, 95vw)' }"
        data-dialog="recovery-codes">
        @if (newCodes(); as codes) {
          <p>Los anteriores ya no valen.</p>
          <app-recovery-codes [codes]="codes" [account]="me.email" />
        }
      </p-dialog>
    }
  `,
  styles: `
    :host {
      display: block;
    }
    .state {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
    }
    .low {
      color: var(--p-app-warn-color);
      font-weight: 600;
    }
    /* Las acciones, debajo y alineadas con el texto (hay varias y el texto necesita sitio). */
    .row.mfa {
      flex-wrap: wrap;
    }
    .actions {
      flex-basis: 100%;
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem;
      padding-left: 3.15rem;
    }
  `,
})
export class MfaCard implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly api = inject(MfaApi);
  private readonly messages = inject(MessageService);
  private readonly confirm = inject(ConfirmationService);

  protected readonly status = signal<MfaStatus | null>(null);
  protected readonly setupOpen = signal(false);
  protected readonly newCodes = signal<string[] | null>(null);
  protected readonly busy = signal(false);

  ngOnInit(): void {
    if (this.auth.user()?.origin !== 'oidc') void this.refresh();
  }

  protected async refresh(): Promise<void> {
    try {
      this.status.set(await firstValueFrom(this.api.status()));
    } catch {
      // Sin estado no se enseñan acciones.
    }
  }

  protected closeSetup(): void {
    this.setupOpen.set(false);
    void this.refresh();
    void this.auth.verify();
  }

  protected regenerate(): void {
    this.confirm.confirm({
      header: 'Generar códigos nuevos',
      message: 'Los códigos de recuperación que tienes ahora dejarán de valer.',
      icon: 'bi bi-arrow-repeat',
      acceptLabel: 'Generar',
      rejectLabel: 'Cancelar',
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: async () => {
        this.busy.set(true);
        try {
          const res = await firstValueFrom(this.api.regenerateRecoveryCodes());
          this.newCodes.set(res.recoveryCodes);
          await this.refresh();
        } catch (err) {
          this.error('No se generaron los códigos', err);
        } finally {
          this.busy.set(false);
        }
      },
    });
  }

  protected disable(): void {
    this.confirm.confirm({
      header: 'Desactivar la verificación en dos pasos',
      message: 'Volverás a entrar solo con la contraseña y se borrarán tus códigos de recuperación.',
      icon: 'bi bi-shield-x',
      acceptLabel: 'Desactivar',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: async () => {
        try {
          await firstValueFrom(this.api.disable());
          await this.refresh();
          await this.auth.verify();
          this.messages.add({ severity: 'success', summary: 'Verificación en dos pasos desactivada', life: 4000 });
        } catch (err) {
          this.error('No se desactivó', err);
        }
      },
    });
  }

  private error(summary: string, err: unknown): void {
    this.messages.add({
      severity: 'error',
      summary,
      detail: apiErrorMessage(err, 'Inténtalo de nuevo.'),
      life: 6000,
    });
  }
}
