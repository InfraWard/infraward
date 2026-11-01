import { DatePipe } from '@angular/common';
import { Component, inject, signal, type OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  ALERT_CHANNEL_NAME_MAX,
  ALERT_EMAIL_RECIPIENTS_MAX,
  ALERT_WEBHOOK_SECRET_MAX,
  ALERT_WEBHOOK_SECRET_MIN,
  ALERT_WEBHOOK_URL_MAX,
  NOTIFICATION_KINDS,
  type AlertChannel,
  type AlertChannelType,
  type AlertsStatus,
  type NotificationKind,
} from '@infraward/shared-types';
import { ConfirmationService, MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { TagModule } from '@openng/optimus-ui/tag';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import type { Observable } from 'rxjs';
import { AlertsApi } from '../../core/api/alerts-api';
import { apiErrorMessage } from '../../shared/api-errors';
import { NOTIFICATION_KIND_LABELS } from '../../shared/maintenance-labels';

interface Draft {
  type: AlertChannelType;
  name: string;
  url: string;
  recipients: string;
  secret: string;
  /** Al editar: quitar el secreto de firma. */
  clearSecret: boolean;
  kinds: NotificationKind[];
  includeAdminOnly: boolean;
  enabled: boolean;
}

const EMPTY: Draft = {
  type: 'webhook',
  name: '',
  url: '',
  recipients: '',
  secret: '',
  clearSecret: false,
  kinds: [],
  includeAdminOnly: false,
  enabled: true,
};

/** Destinatarios escritos separados por comas, espacios o líneas. */
export function parseRecipients(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).map((r) => r.trim()).filter(Boolean))];
}

/**
 * Ajustes › Alertas (`alerts.manage`, DESIGN §10): canales que reciben lo mismo que la campana,
 * por webhook (POST JSON firmado con HMAC-SHA256) o por correo (el SMTP del worker). La URL del
 * webhook y su secreto de firma solo se escriben: van al gestor de secretos y no vuelven.
 */
@Component({
  selector: 'app-alerts-settings',
  imports: [
    DatePipe,
    FormsModule,
    ButtonModule,
    CardModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    MultiSelectModule,
    TagModule,
    ToggleSwitchModule,
  ],
  template: `
    <p-card styleClass="block" data-block="alerts">
      <ng-template #title>
        <div class="title">
          <span>Canales de alertas</span>
          <p-button label="Nuevo canal" icon="bi bi-plus-lg" size="small" (onClick)="openCreate()"
            data-action="new-channel" />
        </div>
      </ng-template>
      <p class="text-muted intro">
        Envían fuera de InfraWard las notificaciones de la campana (nunca facts, conexiones ni
        credenciales): por webhook, firmado con <code>X-InfraWard-Signature</code>
        (HMAC-SHA256 de <code>&lt;X-InfraWard-Timestamp&gt;.&lt;cuerpo&gt;</code>), o por correo.
      </p>
      @if (status(); as s) {
        @if (s.smtpConfigured === false) {
          <p-message severity="info" icon="bi bi-envelope-slash" data-smtp-missing>
            El worker no tiene SMTP configurado (<code>SMTP_HOST</code>): los canales de correo no enviarán.
          </p-message>
        } @else if (s.smtpConfigured === null) {
          <p-message severity="warn" icon="bi bi-question-circle" data-worker-unknown>
            El worker aún no ha dicho cómo envía (¿está arrancado?).
          </p-message>
        }
      }
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
      } @else if (loading()) {
        <p class="text-muted">Cargando…</p>
      } @else {
        <ul class="channels">
          @for (c of channels(); track c.id) {
            <li [attr.data-channel]="c.name">
              <div class="head">
                <span class="name">
                  <i class="bi {{ c.type === 'webhook' ? 'bi-broadcast' : 'bi-envelope' }}" aria-hidden="true"></i>
                  {{ c.name }}
                </span>
                <p-tag [value]="c.type === 'webhook' ? 'Webhook' : 'Correo'" severity="secondary" />
                @if (!c.enabled) {
                  <p-tag value="Desactivado" severity="secondary" icon="bi bi-pause-circle" data-disabled />
                } @else if (c.lastErrorAt && (!c.lastSuccessAt || c.lastErrorAt > c.lastSuccessAt)) {
                  <p-tag value="Falla" severity="danger" icon="bi bi-x-circle" data-state="error" />
                } @else if (c.lastSuccessAt) {
                  <p-tag value="Envía" severity="success" icon="bi bi-check-circle" data-state="ok" />
                } @else {
                  <p-tag value="Sin envíos" severity="warn" icon="bi bi-hourglass-split" />
                }
              </div>
              <dl class="facts">
                <div><dt>Destino</dt><dd>
                  @if (c.type === 'webhook') {
                    <code>{{ c.host }}</code>{{ c.hasSecret ? ' · firmado' : ' · sin firma' }}
                  } @else {
                    {{ c.recipients?.join(', ') }}
                  }
                </dd></div>
                <div><dt>Recibe</dt><dd>{{ kindsText(c) }}</dd></div>
                <div><dt>Último envío</dt><dd>{{ c.lastSuccessAt ? (c.lastSuccessAt | date: 'short') : 'nunca' }}</dd></div>
              </dl>
              @if (c.lastError && c.lastErrorAt && (!c.lastSuccessAt || c.lastErrorAt > c.lastSuccessAt)) {
                <p-message severity="error" icon="bi bi-exclamation-triangle" data-last-error>
                  {{ c.lastErrorAt | date: 'short' }}: {{ c.lastError }}
                </p-message>
              }
              <div class="actions">
                <p-button label="Enviar prueba" icon="bi bi-send" size="small" severity="secondary"
                  [loading]="busy() === c.id + ':test'" (onClick)="test(c)" data-action="test-channel" />
                <p-button label="Editar" icon="bi bi-pencil" size="small" severity="secondary" [text]="true"
                  (onClick)="openEdit(c)" data-action="edit-channel" />
                <p-button label="Borrar" icon="bi bi-trash" size="small" severity="danger" [text]="true"
                  (onClick)="remove(c)" data-action="delete-channel" />
              </div>
            </li>
          } @empty {
            <li class="text-muted empty">Aún no hay canales: las notificaciones solo están en la campana.</li>
          }
        </ul>
      }
    </p-card>

    <p-dialog [header]="editing() ? 'Editar ' + editing()!.name : 'Nuevo canal de alertas'"
      [visible]="formOpen()" (visibleChange)="formOpen.set($event)" [modal]="true"
      [style]="{ width: 'min(36rem, 95vw)' }" data-dialog="alert-channel">
      <form class="form" (ngSubmit)="save()">
        @if (!editing()) {
          <span class="label" id="channel-type">Tipo</span>
          <div class="types" role="radiogroup" aria-labelledby="channel-type">
            @for (t of types; track t.value) {
              <button type="button" class="type" role="radio" [attr.aria-checked]="draft.type === t.value"
                [class.selected]="draft.type === t.value" (click)="draft.type = t.value" [attr.data-type]="t.value">
                <i class="bi {{ t.icon }}" aria-hidden="true"></i>
                <span><strong>{{ t.label }}</strong><small>{{ t.help }}</small></span>
              </button>
            }
          </div>
        }
        <label for="channel-name">Nombre</label>
        <input pInputText id="channel-name" name="name" autocomplete="off" [maxlength]="nameMax"
          [(ngModel)]="draft.name" placeholder="n8n de casa, guardia…" data-field="name" />
        @if (draft.type === 'webhook') {
          <label for="channel-url">URL{{ editing() ? ' (déjala vacía para no cambiarla)' : '' }}</label>
          <input pInputText id="channel-url" name="url" type="password" autocomplete="off" spellcheck="false"
            [maxlength]="urlMax" [(ngModel)]="draft.url" placeholder="https://…" data-field="url" />
          <small class="text-muted">
            Suele llevar un token (Slack, Discord, ntfy…): se guarda en el gestor de secretos y aquí solo
            se ve el host. Solo https, salvo que el worker permita http; IPs privadas, solo con
            <code>ALERTS_WEBHOOK_ALLOW_PRIVATE</code>{{ status()?.allowPrivate ? ' (activado)' : '' }}.
          </small>
          <label for="channel-secret">Secreto de firma (opcional)</label>
          <input pInputText id="channel-secret" name="secret" type="password" autocomplete="new-password"
            spellcheck="false" [maxlength]="secretMax" [(ngModel)]="draft.secret" [disabled]="draft.clearSecret"
            [placeholder]="editing()?.hasSecret ? 'Guardado: escribe otro para cambiarlo' : 'Al menos ' + secretMin + ' caracteres'"
            data-field="secret" />
          @if (editing()?.hasSecret) {
            <span class="inline">
              <p-toggleswitch inputId="channel-clear-secret" name="clearSecret" [(ngModel)]="draft.clearSecret"
                data-field="clear-secret" />
              <label for="channel-clear-secret" class="plain">Quitar la firma</label>
            </span>
          }
        } @else {
          <label for="channel-recipients">Destinatarios</label>
          <input pInputText id="channel-recipients" name="recipients" autocomplete="off"
            [(ngModel)]="draft.recipients" placeholder="guardia@example.com, ops@example.com" data-field="recipients" />
        }
        <label for="channel-kinds">Qué recibe</label>
        <p-multiselect inputId="channel-kinds" name="kinds" [options]="kindOptions" optionLabel="label"
          optionValue="value" [(ngModel)]="draft.kinds" placeholder="Todas" display="chip" appendTo="body"
          [showToggleAll]="false" data-field="kinds" />
        <span class="inline">
          <p-toggleswitch inputId="channel-admin-only" name="includeAdminOnly" [(ngModel)]="draft.includeAdminOnly"
            data-field="admin-only" />
          <label for="channel-admin-only" class="plain">También las que solo ven los admins (credencial revelada)</label>
        </span>
        <span class="inline">
          <p-toggleswitch inputId="channel-enabled" name="enabled" [(ngModel)]="draft.enabled" data-field="enabled" />
          <label for="channel-enabled" class="plain">Activo</label>
        </span>
        @if (formError(); as message) {
          <p-message severity="error" icon="bi bi-exclamation-triangle">{{ message }}</p-message>
        }
        <button type="submit" hidden></button>
      </form>
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="formOpen.set(false)" />
        <p-button [label]="editing() ? 'Guardar' : 'Crear'" icon="bi bi-check-lg" [loading]="busy() === 'form'"
          (onClick)="save()" data-action="save-channel" />
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
    .intro {
      margin: 0 0 1rem;
    }
    .channels {
      list-style: none;
      margin: 1rem 0 0;
      padding: 0;
      display: grid;
      gap: 1rem;
    }
    .channels > li:not(.empty) {
      border: 1px solid var(--p-content-border-color);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      display: grid;
      gap: 0.6rem;
    }
    .head {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .name {
      font-weight: 600;
      margin-right: 0.25rem;
    }
    .facts {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1.5rem;
      margin: 0;
    }
    .facts dt {
      font-size: 0.8rem;
      color: var(--p-text-muted-color);
    }
    .facts dd {
      margin: 0;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem 0.5rem;
    }
    .form {
      display: grid;
      gap: 0.4rem;
    }
    .form label:not(.plain), .form .label {
      font-weight: 600;
      margin-top: 0.5rem;
    }
    .form small {
      display: block;
      line-height: 1.45;
    }
    .inline {
      display: flex;
      gap: 0.5rem;
      align-items: center;
      margin-top: 0.5rem;
    }
    .types {
      display: grid;
      gap: 0.5rem;
    }
    .type {
      display: flex;
      gap: 0.75rem;
      align-items: flex-start;
      text-align: left;
      padding: 0.6rem 0.75rem;
      border: 1px solid var(--p-content-border-color);
      border-radius: 8px;
      background: none;
      color: inherit;
      cursor: pointer;
      font: inherit;
    }
    .type i {
      font-size: 1.25rem;
    }
    .type small {
      display: block;
      color: var(--p-text-muted-color);
    }
    .type.selected {
      border-color: var(--p-primary-color);
      box-shadow: inset 0 0 0 1px var(--p-primary-color);
    }
  `,
})
export class AlertsSettings implements OnInit {
  private readonly api = inject(AlertsApi);
  private readonly messages = inject(MessageService);
  private readonly confirm = inject(ConfirmationService);

  protected readonly nameMax = ALERT_CHANNEL_NAME_MAX;
  protected readonly urlMax = ALERT_WEBHOOK_URL_MAX;
  protected readonly secretMin = ALERT_WEBHOOK_SECRET_MIN;
  protected readonly secretMax = ALERT_WEBHOOK_SECRET_MAX;
  protected readonly types: { value: AlertChannelType; label: string; icon: string; help: string }[] = [
    {
      value: 'webhook',
      label: 'Webhook',
      icon: 'bi-broadcast',
      help: 'POST JSON a una URL (n8n, ntfy, Slack o Discord con un puente…).',
    },
    {
      value: 'email',
      label: 'Correo',
      icon: 'bi-envelope',
      help: 'Con el servidor SMTP del worker.',
    },
  ];
  protected readonly kindOptions = NOTIFICATION_KINDS.map((value) => ({
    value,
    label: NOTIFICATION_KIND_LABELS[value],
  }));

  protected readonly channels = signal<AlertChannel[]>([]);
  protected readonly status = signal<AlertsStatus | null>(null);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal<string | null>(null);
  protected readonly formOpen = signal(false);
  protected readonly editing = signal<AlertChannel | null>(null);
  protected readonly formError = signal<string | null>(null);
  protected draft: Draft = { ...EMPTY };

  ngOnInit(): void {
    this.load();
    this.api.status().subscribe({ next: (s) => this.status.set(s), error: () => undefined });
  }

  protected kindsText(c: AlertChannel): string {
    const kinds = c.kinds?.map((k) => NOTIFICATION_KIND_LABELS[k]).join(', ') ?? 'Todas';
    return c.includeAdminOnly ? `${kinds} (también las de solo admins)` : kinds;
  }

  private load(): void {
    this.api.channels().subscribe({
      next: (list) => {
        this.channels.set(list);
        this.loading.set(false);
      },
      error: (err: unknown) => {
        this.loading.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudieron cargar los canales.'));
      },
    });
  }

  protected openCreate(): void {
    this.editing.set(null);
    this.draft = { ...EMPTY, kinds: [] };
    this.formError.set(null);
    this.formOpen.set(true);
  }

  protected openEdit(c: AlertChannel): void {
    this.editing.set(c);
    this.draft = {
      ...EMPTY,
      type: c.type,
      name: c.name,
      recipients: c.recipients?.join(', ') ?? '',
      kinds: c.kinds ?? [],
      includeAdminOnly: c.includeAdminOnly,
      enabled: c.enabled,
    };
    this.formError.set(null);
    this.formOpen.set(true);
  }

  protected save(): void {
    if (this.busy() === 'form') return;
    const d = this.draft;
    const name = d.name.trim();
    const url = d.url.trim();
    const secret = d.secret.trim();
    const recipients = parseRecipients(d.recipients);
    const editing = this.editing();
    if (!name) return this.formError.set('Escribe un nombre.');
    if (d.type === 'webhook' && !editing && !url) return this.formError.set('Pega la URL del webhook.');
    if (d.type === 'email' && !recipients.length) return this.formError.set('Escribe al menos un destinatario.');
    if (recipients.length > ALERT_EMAIL_RECIPIENTS_MAX)
      return this.formError.set(`Como mucho ${ALERT_EMAIL_RECIPIENTS_MAX} destinatarios.`);
    if (secret && secret.length < ALERT_WEBHOOK_SECRET_MIN)
      return this.formError.set(`El secreto de firma, al menos ${ALERT_WEBHOOK_SECRET_MIN} caracteres.`);
    const common = {
      name,
      kinds: d.kinds.length ? d.kinds : null,
      includeAdminOnly: d.includeAdminOnly,
      enabled: d.enabled,
      ...(d.type === 'email' ? { recipients } : {}),
      ...(d.type === 'webhook' && url ? { url } : {}),
    };
    // La URL y el secreto salen del formulario en cuanto se envían.
    this.draft.url = '';
    this.draft.secret = '';
    const request = editing
      ? this.api.update(editing.id, {
          ...common,
          ...(d.clearSecret ? { secret: null } : secret ? { secret } : {}),
        })
      : this.api.create({ ...common, type: d.type, ...(secret ? { secret } : {}) });
    this.run(
      'form',
      request,
      (c) => {
        this.formOpen.set(false);
        this.messages.add({
          severity: 'success',
          summary: editing ? 'Canal guardado' : 'Canal creado',
          detail: `${c.name}: prueba que llega con «Enviar prueba».`,
          life: 5000,
        });
      },
      (m) => this.formError.set(m),
    );
  }

  protected test(c: AlertChannel): void {
    this.run(`${c.id}:test`, this.api.test(c.id), (r) =>
      this.messages.add(
        r.ok
          ? { severity: 'success', summary: 'Prueba enviada', detail: `${c.name}: entregada.`, life: 5000 }
          : { severity: 'error', summary: 'La prueba falló', detail: `${c.name}: ${r.error}`, life: 8000 },
      ),
    );
  }

  protected remove(c: AlertChannel): void {
    this.confirm.confirm({
      header: 'Borrar el canal',
      message: `${c.name} dejará de recibir alertas${c.type === 'webhook' ? ' y su URL y secreto se borrarán del gestor de secretos' : ''}. ¿Seguir?`,
      acceptLabel: 'Borrar',
      rejectLabel: 'Cancelar',
      acceptButtonProps: { severity: 'danger' },
      rejectButtonProps: { severity: 'secondary', text: true },
      accept: () =>
        this.run(`${c.id}:delete`, this.api.remove(c.id), () =>
          this.messages.add({ severity: 'success', summary: 'Canal borrado', detail: c.name, life: 4000 }),
        ),
    });
  }

  private run<T>(
    key: string,
    request: Observable<T>,
    onDone: (value: T) => void,
    onError?: (message: string) => void,
  ): void {
    this.busy.set(key);
    request.subscribe({
      next: (value) => {
        this.busy.set(null);
        onDone(value);
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(null);
        const message = apiErrorMessage(err, 'No se pudo completar la acción.');
        if (onError) onError(message);
        else this.messages.add({ severity: 'error', summary: 'Error', detail: message, life: 6000 });
      },
    });
  }
}
