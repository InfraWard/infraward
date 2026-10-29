import {
  Component,
  DestroyRef,
  effect,
  inject,
  input,
  output,
  signal,
  type WritableSignal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  VAULT_ENTRY_KIND_LABELS,
  VAULT_REASON_MAX,
  VAULT_REVEAL_SECONDS,
  type VaultEntry,
  type VaultRevealPurpose,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressBarModule } from '@openng/optimus-ui/progressbar';
import { VaultApi } from '../../core/api/vault-api';
import { apiErrorMessage } from '../../shared/api-errors';
import { copyEphemeral } from './clipboard';

/**
 * «Revelar» (solo admins): motivo opcional y dos salidas, verlo unos segundos o copiarlo al
 * portapapeles (que se vacía después). Si hace falta reautenticarse, el interceptor abre el
 * diálogo de identidad y repite la petición. El valor vive solo en una señal que se borra al
 * caducar, al cerrar o al destruir el componente; nunca va a la URL, al estado ni a los logs.
 */
@Component({
  selector: 'app-vault-reveal-dialog',
  imports: [FormsModule, ButtonModule, DialogModule, InputTextModule, MessageModule, ProgressBarModule],
  template: `
    <p-dialog
      header="Revelar credencial"
      [visible]="!!entry()"
      (visibleChange)="!$event && close()"
      [modal]="true"
      [style]="{ width: 'min(34rem, 95vw)' }"
      data-dialog="reveal"
    >
      @if (entry(); as e) {
        <p class="what">
          <strong>{{ e.name }}</strong> · {{ kindLabels[e.kind] }}
          @if (e.asset) {
            · {{ e.asset.name }}
          }
          @if (e.username) {
            <br /><span class="text-muted">Usuario:</span>&nbsp;<code>{{ e.username }}</code>
          }
        </p>
        @if (value(); as v) {
          <div class="value" data-block="revealed">
            <code data-revealed-value>{{ v }}</code>
          </div>
          <p-progressbar [value]="(remaining() / seconds) * 100" [showValue]="false" styleClass="bar" />
          <small class="text-muted">Se oculta en {{ remaining() }} s.</small>
        } @else if (copiedFor() > 0) {
          <p-message severity="success" icon="bi bi-clipboard-check" data-block="copied">
            Copiada al portapapeles: se borra de él en {{ copiedFor() }} s.
          </p-message>
        } @else {
          <label for="reveal-reason">Motivo (opcional, queda en la auditoría)</label>
          <input
            pInputText
            id="reveal-reason"
            [(ngModel)]="reason"
            [maxlength]="reasonMax"
            placeholder="Consola de emergencia, incidencia #123…"
            autocomplete="off"
            data-field="reason"
          />
          <p-message severity="secondary" icon="bi bi-eye" styleClass="mt">
            Se registra quién la revela y cuándo, y se avisa a los demás admins si está
            activado en los ajustes.
          </p-message>
        }
        @if (error(); as message) {
          <p-message severity="error" icon="bi bi-exclamation-triangle" styleClass="mt">{{ message }}</p-message>
        }
      }
      <ng-template #footer>
        @if (value() || copiedFor() > 0) {
          <p-button label="Ocultar y cerrar" icon="bi bi-eye-slash" (onClick)="close()" data-action="hide" />
        } @else {
          <p-button label="Cancelar" severity="secondary" [text]="true" (onClick)="close()" />
          <p-button
            label="Copiar"
            icon="bi bi-clipboard"
            severity="secondary"
            [loading]="busy() === 'copy'"
            [disabled]="!!busy()"
            (onClick)="reveal('copy')"
            data-action="reveal-copy"
          />
          <p-button
            [label]="'Mostrar ' + seconds + ' s'"
            icon="bi bi-eye"
            [loading]="busy() === 'show'"
            [disabled]="!!busy()"
            (onClick)="reveal('show')"
            data-action="reveal-show"
          />
        }
      </ng-template>
    </p-dialog>
  `,
  styles: `
    .what {
      margin: 0 0 0.75rem;
      overflow-wrap: anywhere;
    }
    label {
      display: block;
      font-weight: 600;
      margin-bottom: 0.35rem;
    }
    input {
      width: 100%;
    }
    .value {
      padding: 0.6rem 0.75rem;
      border-radius: 6px;
      background: var(--p-content-hover-background);
      margin-bottom: 0.5rem;
    }
    .value code {
      font-size: 1.05rem;
      overflow-wrap: anywhere;
      user-select: all;
    }
    :host ::ng-deep .bar {
      height: 0.35rem;
      margin-bottom: 0.25rem;
    }
    :host ::ng-deep .mt {
      margin-top: 0.75rem;
    }
  `,
})
export class VaultRevealDialog {
  private readonly api = inject(VaultApi);

  /** Entrada a revelar (null = cerrado). */
  readonly entry = input<VaultEntry | null>(null);
  readonly closed = output<void>();

  protected readonly kindLabels = VAULT_ENTRY_KIND_LABELS;
  protected readonly reasonMax = VAULT_REASON_MAX;
  protected readonly seconds = VAULT_REVEAL_SECONDS;
  protected reason = '';
  protected readonly busy = signal<VaultRevealPurpose | null>(null);
  protected readonly error = signal<string | null>(null);
  /** El valor mostrado: solo mientras dura la cuenta atrás. */
  protected readonly value = signal<string | null>(null);
  protected readonly remaining = signal(0);
  protected readonly copiedFor = signal(0);

  private ticker: ReturnType<typeof setInterval> | undefined;

  constructor() {
    // Al cambiar de entrada (o cerrar desde fuera), nada del anterior queda a la vista.
    effect(() => {
      this.entry();
      this.reset();
    });
    inject(DestroyRef).onDestroy(() => this.reset());
  }

  protected reveal(purpose: VaultRevealPurpose): void {
    const entry = this.entry();
    if (!entry) return;
    this.busy.set(purpose);
    this.error.set(null);
    const reason = this.reason.trim() || undefined;
    this.api.reveal(entry.id, { purpose, reason }).subscribe({
      next: async (res) => {
        this.busy.set(null);
        if (purpose === 'show') {
          this.value.set(res.value);
          // Al acabar, fuera de la vista y el diálogo se cierra.
          this.countdown(res.expiresInSeconds, this.remaining, () => this.close());
          return;
        }
        try {
          await copyEphemeral(res.value, res.expiresInSeconds);
          this.countdown(res.expiresInSeconds, this.copiedFor, () => this.close());
        } catch {
          this.error.set('El navegador no deja usar el portapapeles: usa «Mostrar».');
        }
      },
      error: (err: unknown) => {
        this.busy.set(null);
        this.error.set(apiErrorMessage(err, 'No se pudo revelar la credencial.'));
      },
    });
  }

  protected close(): void {
    this.reset();
    this.closed.emit();
  }

  private countdown(
    seconds: number,
    target: WritableSignal<number>,
    done: () => void,
  ): void {
    clearInterval(this.ticker);
    target.set(seconds);
    this.ticker = setInterval(() => {
      const left = target() - 1;
      target.set(Math.max(0, left));
      if (left <= 0) {
        clearInterval(this.ticker);
        done();
      }
    }, 1000);
  }

  /** Borra el valor de la vista; el portapapeles se vacía a su hora (aunque se cierre antes). */
  private reset(): void {
    clearInterval(this.ticker);
    this.value.set(null);
    this.remaining.set(0);
    this.copiedFor.set(0);
    this.busy.set(null);
    this.error.set(null);
    this.reason = '';
  }
}
