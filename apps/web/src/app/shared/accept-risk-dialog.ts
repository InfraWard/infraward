import { DatePipe } from '@angular/common';
import { Component, inject, input, model, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  FINDING_ACCEPT_MAX_DAYS,
  FINDING_ACCEPT_REASON_MAX,
  FINDING_ACCEPT_REASON_MIN,
  type FindingAcceptance,
  type FindingAcceptanceResult,
  type ReopenFindingsRequest,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { FindingsApi } from '../core/api/findings-api';
import { apiErrorMessage } from './api-errors';

const DAY_MS = 24 * 60 * 60 * 1000;

/** Fecha `aaaa-mm-dd` (para el campo de fecha) a `days` días de hoy. */
function dateInDays(days: number, now = Date.now()): string {
  return new Date(now + days * DAY_MS).toISOString().slice(0, 10);
}

/** Caducidad elegida → ISO (al final del día, hora local); null = sin caducidad; undefined = inválida. */
export function acceptExpiryIso(
  choice: number | 'never' | 'custom',
  customDate: string,
  now = Date.now(),
): string | null | undefined {
  if (choice === 'never') return null;
  if (choice !== 'custom') return new Date(now + choice * DAY_MS).toISOString();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(customDate)) return undefined;
  const end = new Date(`${customDate}T23:59:00`);
  if (Number.isNaN(end.getTime()) || end.getTime() <= now) return undefined;
  return end.getTime() > now + FINDING_ACCEPT_MAX_DAYS * DAY_MS ? undefined : end.toISOString();
}

/** «Aceptado por x el d · motivo · hasta d» (para la etiqueta de un finding aceptado). */
export function acceptanceText(a: FindingAcceptance, date: DatePipe): string {
  return [
    `Aceptado${a.by ? ` por ${a.by}` : ''} el ${date.transform(a.at, 'd MMM y')}`,
    `«${a.reason}»`,
    a.expiresAt ? `hasta el ${date.transform(a.expiresAt, 'd MMM y')}` : 'sin caducidad',
  ].join(' · ');
}

/**
 * Diálogo «Aceptar el riesgo» (DESIGN §9): motivo obligatorio y caducidad (por defecto 90 días).
 * El destino son findings concretos o todos los abiertos de unos CVE (`target`).
 */
@Component({
  selector: 'app-accept-risk-dialog',
  imports: [
    FormsModule,
    ButtonModule,
    DialogModule,
    InputTextModule,
    MessageModule,
    SelectModule,
    TextareaModule,
  ],
  template: `
    <p-dialog header="Aceptar el riesgo" [visible]="visible()" (visibleChange)="close($event)"
      [modal]="true" [style]="{ width: 'min(32rem, 95vw)' }" data-dialog="accept-risk">
      <p class="text-muted small" data-accept-scope>{{ scope() }}</p>
      <div class="form">
        <label for="accept-reason">Motivo</label>
        <textarea pTextarea id="accept-reason" rows="3" [(ngModel)]="reason" [maxlength]="reasonMax"
          placeholder="Por qué no se corrige ahora (no es explotable aquí, mitigado por…, sin parche…)"
          data-field="reason"></textarea>
        <label for="accept-expiry">Caduca</label>
        <p-select inputId="accept-expiry" [options]="expiryOptions" optionLabel="label" optionValue="value"
          [(ngModel)]="expiry" appendTo="body" data-field="expiry" />
        @if (expiry === 'custom') {
          <input pInputText type="date" aria-label="Fecha de caducidad" [(ngModel)]="customDate"
            [min]="minDate" [max]="maxDate" data-field="date" />
        }
        <small class="text-muted">
          Sale de los recuentos de abiertos; al caducar vuelve a abrirse. Queda en la auditoría.
        </small>
      </div>
      @if (error(); as message) {
        <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mt">{{ message }}</p-message>
      }
      <ng-template #footer>
        <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="close(false)" />
        <p-button label="Aceptar el riesgo" icon="bi bi-shield-check" [loading]="busy()"
          (onClick)="submit()" data-action="accept-risk" />
      </ng-template>
    </p-dialog>
  `,
  styles: `
    .form {
      display: grid;
      gap: 0.5rem;
    }
    .mt {
      margin-top: 0.75rem;
    }
  `,
})
export class AcceptRiskDialog {
  private readonly api = inject(FindingsApi);

  readonly visible = model(false);
  readonly target = input.required<ReopenFindingsRequest>();
  /** Qué se acepta, en una frase («2 CVE seleccionados», «openssl en web1»…). */
  readonly scope = input('');
  readonly done = output<FindingAcceptanceResult>();

  protected readonly reasonMax = FINDING_ACCEPT_REASON_MAX;
  protected readonly expiryOptions = [
    { label: '30 días', value: 30 },
    { label: '90 días', value: 90 },
    { label: '180 días', value: 180 },
    { label: '1 año', value: FINDING_ACCEPT_MAX_DAYS },
    { label: 'Otra fecha…', value: 'custom' },
    { label: 'Sin caducidad', value: 'never' },
  ];
  protected readonly minDate = dateInDays(1);
  protected readonly maxDate = dateInDays(FINDING_ACCEPT_MAX_DAYS - 1);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected reason = '';
  protected expiry: number | 'never' | 'custom' = 90;
  protected customDate = dateInDays(90);

  protected close(open: boolean): void {
    if (open) return;
    this.visible.set(false);
    this.error.set(null);
  }

  protected submit(): void {
    const reason = this.reason.trim();
    if (reason.length < FINDING_ACCEPT_REASON_MIN) {
      this.error.set(`Explica el motivo (al menos ${FINDING_ACCEPT_REASON_MIN} caracteres).`);
      return;
    }
    const expiresAt = acceptExpiryIso(this.expiry, this.customDate);
    if (expiresAt === undefined) {
      this.error.set(`Elige una fecha futura, como mucho a ${FINDING_ACCEPT_MAX_DAYS} días.`);
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.api.accept({ ...this.target(), reason, expiresAt }).subscribe({
      next: (result) => {
        this.busy.set(false);
        this.reason = '';
        this.visible.set(false);
        this.done.emit(result);
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.error.set(apiErrorMessage(err, 'No se pudo aceptar el riesgo'));
      },
    });
  }
}
