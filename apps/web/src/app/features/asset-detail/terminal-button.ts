import { Component, inject, input } from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import type { AssetTerminalStatus } from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { catchError, of, switchMap } from 'rxjs';
import { TerminalApi } from '../../core/api/terminal-api';

/**
 * «Abrir terminal» (sesión 22): solo para quien tiene `terminal.open` en este asset (rol o regla
 * de acceso); deshabilitado con el motivo si el asset no la admite ahora. Se abre en otra
 * pestaña: cada una es una sesión.
 */
@Component({
  selector: 'app-terminal-button',
  imports: [ButtonModule, TooltipModule],
  template: `
    @if (status(); as s) {
      @if (s.allowed) {
        <span [pTooltip]="s.available ? hint(s) : (s.reason ?? undefined)" tooltipPosition="bottom">
          <p-button
            label="Abrir terminal"
            icon="bi bi-terminal"
            size="small"
            [outlined]="true"
            [disabled]="!s.available"
            data-action="terminal"
            (onClick)="open()"
          />
        </span>
      }
    }
  `,
  styles: `
    :host {
      display: inline-block;
    }
  `,
})
export class TerminalButton {
  readonly assetId = input.required<string>();
  private readonly api = inject(TerminalApi);

  readonly status = toSignal(
    toObservable(this.assetId).pipe(
      switchMap((id) =>
        this.api.status(id).pipe(catchError(() => of<AssetTerminalStatus | null>(null))),
      ),
    ),
    { initialValue: null },
  );

  /** En otra pestaña, sin `opener`: la terminal no puede tocar esta página. */
  open(): void {
    window.open(`/assets/${encodeURIComponent(this.assetId())}/terminal`, '_blank', 'noopener');
  }

  hint(s: AssetTerminalStatus): string {
    return s.host ? `Como ${s.account} a través de ${s.host.name} (en otra pestaña)` : '';
  }
}
