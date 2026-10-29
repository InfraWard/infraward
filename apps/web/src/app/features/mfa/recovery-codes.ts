import { Component, inject, input } from '@angular/core';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';

/**
 * Códigos de recuperación recién generados: se enseñan una sola vez (en la API solo queda su
 * hash), con copiar y descargar como texto.
 */
@Component({
  selector: 'app-recovery-codes',
  imports: [ButtonModule, MessageModule],
  template: `
    <p-message severity="warn" icon="bi bi-exclamation-triangle">
      Guárdalos en un sitio seguro (un gestor de contraseñas). Cada uno sirve una sola vez si pierdes
      el móvil, y no se volverán a enseñar.
    </p-message>
    <ol class="codes" data-recovery-codes>
      @for (code of codes(); track code) {
        <li><code>{{ code }}</code></li>
      }
    </ol>
    <div class="actions">
      <p-button label="Copiar" icon="bi bi-clipboard" severity="secondary" size="small" (onClick)="copy()"
        data-action="copy-codes" />
      <p-button label="Descargar .txt" icon="bi bi-download" severity="secondary" size="small"
        (onClick)="download()" data-action="download-codes" />
    </div>
  `,
  styles: `
    .codes {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(11rem, 1fr));
      gap: 0.4rem 1.25rem;
      margin: 1rem 0;
      padding-left: 1.5rem;
    }
    .codes code {
      font-size: 0.95rem;
      letter-spacing: 0.03em;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
  `,
})
export class RecoveryCodes {
  readonly codes = input.required<string[]>();
  readonly account = input<string>('');
  private readonly messages = inject(MessageService, { optional: true });

  protected async copy(): Promise<void> {
    await navigator.clipboard?.writeText(this.codes().join('\n'));
    this.messages?.add({ severity: 'success', summary: 'Códigos copiados', life: 2500 });
  }

  protected download(): void {
    const text = [
      `Códigos de recuperación de InfraWard${this.account() ? ` (${this.account()})` : ''}`,
      'Cada uno sirve una sola vez.',
      '',
      ...this.codes(),
      '',
    ].join('\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'infraward-codigos-de-recuperacion.txt';
    link.click();
    URL.revokeObjectURL(url);
  }
}
