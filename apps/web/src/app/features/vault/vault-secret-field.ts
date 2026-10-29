import { Component, computed, input, model, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  GENERATED_PASSWORD_DEFAULT,
  GENERATED_PASSWORD_MAX,
  GENERATED_PASSWORD_MIN,
  generatePassword,
  rotationCommand,
  VAULT_REVEAL_SECONDS,
  VAULT_SECRET_MAX,
  type VaultEntryKind,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { PasswordModule } from '@openng/optimus-ui/password';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { copyEphemeral } from './clipboard';

/** Bytes aleatorios del navegador (Web Crypto): la contraseña generada no sale de aquí hasta guardarla. */
function browserRandom(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Campo de secreto de la caja fuerte: solo de escritura (nunca se rellena con el valor guardado),
 * con «Generar» (en el navegador, con Web Crypto) y el comando para aplicarla en el servidor.
 * InfraWard no la aplica: el comando la pide de forma interactiva y nunca la lleva en la línea.
 */
@Component({
  selector: 'app-vault-secret-field',
  imports: [FormsModule, ButtonModule, CheckboxModule, InputNumberModule, PasswordModule, TooltipModule],
  template: `
    <div class="secret-field">
      <label [for]="inputId()">{{ label() }}</label>
      <div class="row">
        <p-password
          [inputId]="inputId()"
          [ngModel]="value()"
          (ngModelChange)="value.set($event ?? '')"
          [feedback]="false"
          [toggleMask]="true"
          [maxlength]="max"
          autocomplete="new-password"
          placeholder="Escríbela o genera una"
          fluid
          data-field="secret"
        />
        <p-button
          icon="bi bi-clipboard"
          severity="secondary"
          [text]="true"
          [disabled]="!value()"
          ariaLabel="Copiar la contraseña"
          [pTooltip]="copied() ? 'Copiada: se borra del portapapeles en ' + clearSeconds + ' s' : 'Copiar la contraseña'"
          (onClick)="copySecret()"
          data-action="copy-secret"
        />
      </div>
      <div class="generator">
        <p-button
          label="Generar"
          icon="bi bi-magic"
          size="small"
          severity="secondary"
          (onClick)="generate()"
          data-action="generate"
        />
        <label class="inline" for="{{ inputId() }}-length">Longitud</label>
        <p-inputnumber
          [inputId]="inputId() + '-length'"
          [(ngModel)]="length"
          [min]="minLength"
          [max]="maxLength"
          size="small"
          [inputStyle]="{ width: '4rem' }"
        />
        <span class="inline">
          <p-checkbox [inputId]="inputId() + '-symbols'" [(ngModel)]="symbols" [binary]="true" />
          <label [for]="inputId() + '-symbols'">Símbolos</label>
        </span>
      </div>
      @if (generated()) {
        <div class="command" data-block="rotation-command">
          <p class="title">
            <i class="bi bi-terminal" aria-hidden="true"></i> {{ command().title }}
          </p>
          @for (line of command().commands; track $index) {
            <div class="line">
              <code>{{ line }}</code>
              <p-button
                icon="bi bi-clipboard"
                size="small"
                severity="secondary"
                [text]="true"
                ariaLabel="Copiar el comando"
                pTooltip="Copiar el comando"
                (onClick)="copy(line)"
              />
            </div>
          }
          @if (command().note; as note) {
            <small class="text-muted">{{ note }}</small>
          }
          <small class="text-muted">
            InfraWard no la aplica: ejecútalo tú en el servidor y pega la contraseña cuando la pida
            (no va en la línea de órdenes ni en el historial).
          </small>
        </div>
      }
    </div>
  `,
  styles: `
    .secret-field {
      display: grid;
      gap: 0.4rem;
    }
    label {
      font-weight: 600;
    }
    .row {
      display: flex;
      align-items: center;
      gap: 0.25rem;
    }
    .row p-password {
      flex: 1;
      min-width: 0;
    }
    .generator {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
    }
    .inline {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-weight: normal;
    }
    /* Dentro de un formulario que estira los p-inputnumber: aquí, compacto. */
    :host ::ng-deep .generator .p-inputnumber {
      width: auto !important;
    }
    .command {
      display: grid;
      gap: 0.35rem;
      padding: 0.6rem 0.75rem;
      border-radius: 6px;
      background: var(--p-content-hover-background);
    }
    .command .title {
      margin: 0;
      font-weight: 600;
    }
    .line {
      display: flex;
      align-items: center;
      gap: 0.25rem;
      min-width: 0;
    }
    .line code {
      overflow-wrap: anywhere;
      font-size: 0.85rem;
    }
  `,
})
export class VaultSecretField {
  readonly inputId = input.required<string>();
  readonly label = input('Contraseña');
  readonly kind = input<VaultEntryKind>('console');
  readonly username = input<string | null>(null);
  readonly roles = input<readonly string[]>([]);
  /** El valor escrito o generado (vacío = no cambiar). */
  readonly value = model('');

  protected readonly max = VAULT_SECRET_MAX;
  protected readonly minLength = GENERATED_PASSWORD_MIN;
  protected readonly maxLength = GENERATED_PASSWORD_MAX;
  protected length = GENERATED_PASSWORD_DEFAULT;
  protected symbols = true;
  protected readonly generated = signal(false);
  protected readonly copied = signal(false);
  protected readonly clearSeconds = VAULT_REVEAL_SECONDS * 2;
  protected readonly command = computed(() =>
    rotationCommand(this.kind(), this.username(), { roles: this.roles() }),
  );

  protected generate(): void {
    const length = Math.min(
      GENERATED_PASSWORD_MAX,
      Math.max(GENERATED_PASSWORD_MIN, Math.trunc(this.length || GENERATED_PASSWORD_DEFAULT)),
    );
    this.value.set(generatePassword(browserRandom, { length, symbols: this.symbols }));
    this.generated.set(true);
  }

  /** Para pegarla en el `passwd` del servidor; se vacía del portapapeles poco después. */
  protected async copySecret(): Promise<void> {
    if (!this.value()) return;
    try {
      await copyEphemeral(this.value(), this.clearSeconds);
      this.copied.set(true);
    } catch {
      this.copied.set(false);
    }
  }

  protected async copy(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Sin permiso de portapapeles: se puede seleccionar a mano.
    }
  }
}
