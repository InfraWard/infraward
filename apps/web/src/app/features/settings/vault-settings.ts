import { Component, inject, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  DEFAULT_VAULT_SETTINGS,
  VAULT_RETENTION_DAYS_MAX,
  VAULT_RETENTION_DAYS_MIN,
  VAULT_ROTATION_DAYS_MAX,
  VAULT_ROTATION_DAYS_MIN,
  type VaultSettings,
  type VaultStatus,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { VaultApi } from '../../core/api/vault-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';

/**
 * Ajustes › Caja fuerte (QoL-7): estado del almacén y, para los admins, el plazo de rotación, el
 * aviso de revelados y los días de la papelera. Cambiarlos pide confirmar la identidad (el
 * interceptor abre el diálogo) y queda en la auditoría.
 */
@Component({
  selector: 'app-vault-settings',
  imports: [FormsModule, ButtonModule, CardModule, InputNumberModule, MessageModule, TagModule, ToggleSwitchModule],
  template: `
    <p-card styleClass="block" data-block="vault-status">
      <ng-template #title>Almacén de la caja fuerte</ng-template>
      @if (status(); as s) {
        @if (s.provider === 'none') {
          <p-message severity="warn" icon="bi bi-exclamation-triangle">
            Sin configurar. En la API (nunca en el worker): <code>VAULT_PROVIDER=local</code> con
            <code>VAULT_LOCAL_MASTER_KEY_FILE</code> (una clave distinta de la de los secretos) u
            <code>openbao</code> con la AppRole <code>infraward-vault</code> que crea
            <code>pnpm openbao:bootstrap</code>.
          </p-message>
        } @else {
          <p class="status">
            <strong>{{ s.provider === 'openbao' ? 'OpenBao' : 'Local (cifrado en la BD con su propia clave)' }}</strong>
            @if (s.healthy) {
              <p-tag value="Operativo" severity="success" icon="bi bi-check-circle" />
            } @else {
              <p-tag value="Con problemas" severity="danger" icon="bi bi-x-circle" />
            }
            <span class="text-muted">· conserva {{ s.maxVersions }} versiones por credencial</span>
          </p>
          <p class="text-muted small">
            Separado de los secretos de la app: el worker no tiene ni su clave ni su AppRole, así que no
            puede leerlo.
          </p>
        }
      }
    </p-card>

    <p-card styleClass="block" data-block="vault-settings">
      <ng-template #title>Rotación, avisos y papelera</ng-template>
      <div class="form">
        <label for="vault-rotation-days">Plazo de rotación por defecto (días)</label>
        <p-inputnumber inputId="vault-rotation-days" [(ngModel)]="form.rotationWarnDays" [min]="rotationMin"
          [max]="rotationMax" [disabled]="!canEdit" data-field="rotation-days" />
        <small class="text-muted">Pasado el plazo desde la última rotación, la credencial sale como vencida. Cada una puede tener el suyo.</small>

        <label for="vault-notify">Avisar a los demás admins de cada revelado</label>
        <p-toggleswitch inputId="vault-notify" [(ngModel)]="form.notifyOnReveal" [disabled]="!canEdit" data-field="notify" />

        <label for="vault-retention">Días en la papelera antes de destruirla</label>
        <p-inputnumber inputId="vault-retention" [(ngModel)]="form.deleteRetentionDays" [min]="retentionMin"
          [max]="retentionMax" [disabled]="!canEdit" data-field="retention" />
      </div>
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mt">{{ message }}</p-message>
      }
      @if (canEdit) {
        <div class="actions">
          <p-button label="Guardar" icon="bi bi-check-lg" [loading]="busy()" (onClick)="save()" data-action="save-vault-settings" />
        </div>
      } @else {
        <p class="text-muted small">Solo un admin los cambia.</p>
      }
    </p-card>
  `,
  styles: `
    :host {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 1rem;
    }
    .status {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
      margin: 0;
    }
    .small {
      font-size: 0.85rem;
    }
    .form {
      display: grid;
      gap: 0.4rem;
      max-width: 28rem;
    }
    .form label {
      font-weight: 600;
      margin-top: 0.5rem;
    }
    .actions {
      margin-top: 1rem;
    }
    :host ::ng-deep .mt {
      margin-top: 0.75rem;
    }
  `,
})
export class VaultSettingsCard implements OnInit {
  private readonly api = inject(VaultApi);
  private readonly messages = inject(MessageService);
  protected readonly canEdit = inject(AuthService).can('vault.admin');

  protected readonly rotationMin = VAULT_ROTATION_DAYS_MIN;
  protected readonly rotationMax = VAULT_ROTATION_DAYS_MAX;
  protected readonly retentionMin = VAULT_RETENTION_DAYS_MIN;
  protected readonly retentionMax = VAULT_RETENTION_DAYS_MAX;
  protected readonly status = signal<VaultStatus | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected form: VaultSettings = { ...DEFAULT_VAULT_SETTINGS };

  ngOnInit(): void {
    this.api.status().subscribe({ next: (s) => this.status.set(s), error: () => undefined });
    this.api.settings().subscribe({
      next: (s) => (this.form = { ...s }),
      error: (err: unknown) => this.error.set(apiErrorMessage(err, 'No se pudieron leer los ajustes.')),
    });
  }

  protected save(): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.updateSettings(this.form).subscribe({
      next: (s) => {
        this.busy.set(false);
        this.form = { ...s };
        this.messages.add({ severity: 'success', summary: 'Ajustes de la caja fuerte guardados', life: 4000 });
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudieron guardar los ajustes.'));
      },
    });
  }
}
