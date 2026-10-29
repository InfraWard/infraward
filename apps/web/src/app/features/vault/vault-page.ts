import { Component, inject, signal, type OnInit } from '@angular/core';
import { RouterLink } from '@angular/router';
import type { VaultStatus } from '@infraward/shared-types';
import { MessageModule } from '@openng/optimus-ui/message';
import { VaultApi } from '../../core/api/vault-api';
import { AuthService } from '../../core/auth/auth.service';
import { VaultEntries } from './vault-entries';

/**
 * Caja fuerte de credenciales (QoL-7, DESIGN §19): las credenciales que usa una persona (consola de
 * emergencia, paneles web, IPMI…) y que InfraWard nunca usa para conectarse.
 */
@Component({
  selector: 'app-vault-page',
  imports: [RouterLink, MessageModule, VaultEntries],
  template: `
    <header class="page-head">
      <div>
        <h1><i class="bi bi-safe2" aria-hidden="true"></i> Caja fuerte</h1>
        <p class="muted">
          Credenciales para personas: la contraseña de root para la consola, paneles web, IPMI…
          InfraWard nunca las usa ni el worker puede leerlas.
          @if (auth.can('vault.admin')) {
            Revelar una pide confirmar tu identidad y queda en la auditoría.
          } @else {
            Puedes guardarlas y cambiarlas, pero solo un admin puede revelarlas.
          }
        </p>
      </div>
    </header>
    @if (status(); as s) {
      @if (s.provider === 'none') {
        <p-message severity="warn" icon="bi bi-exclamation-triangle" data-block="not-configured">
          La caja fuerte no está configurada: define <code>VAULT_PROVIDER</code> en la API (ver
          @if (auth.can('vault.admin')) {
            <a routerLink="/settings" [queryParams]="{ tab: 'vault' }">Ajustes › Caja fuerte</a>).
          } @else {
            Ajustes › Caja fuerte, con un admin).
          }
        </p-message>
      } @else if (!s.healthy) {
        <p-message severity="error" icon="bi bi-exclamation-octagon">
          El almacén de la caja fuerte ({{ s.provider === 'openbao' ? 'OpenBao' : 'local' }}) no responde.
        </p-message>
      }
    }
    <app-vault-entries />
  `,
  styles: `
    h1 {
      margin: 0.5rem 0 0.25rem;
      font-size: 1.5rem;
    }
    .muted {
      color: var(--p-text-muted-color);
      margin: 0;
      max-width: 60rem;
    }
    p-message {
      display: block;
      margin-bottom: 0.75rem;
    }
  `,
})
export class VaultPage implements OnInit {
  private readonly api = inject(VaultApi);
  protected readonly auth = inject(AuthService);
  protected readonly status = signal<VaultStatus | null>(null);

  ngOnInit(): void {
    this.api.status().subscribe({ next: (s) => this.status.set(s), error: () => undefined });
  }
}
