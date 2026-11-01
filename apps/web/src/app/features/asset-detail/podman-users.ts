import { Component, computed, inject, input, signal } from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import {
  PODMAN_ENABLE_MAX_USERS,
  podmanEnableCommand,
  podmanUserNeedsEnable,
  podmanUserState,
  type Asset,
  type AssetTerminalStatus,
  type PodmanRootlessUser,
  type PodmanUserState,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { catchError, of, switchMap } from 'rxjs';
import { TerminalApi } from '../../core/api/terminal-api';
import type { TagSeverity } from '../../shared/labels';

export const PODMAN_USER_STATE_LABELS: Record<PodmanUserState, string> = {
  inventoried: 'Inventariado',
  no_socket: 'Sin socket',
  not_enabled: 'Sin habilitar',
};

const STATE_SEVERITY: Record<PodmanUserState, TagSeverity> = {
  inventoried: 'success',
  no_socket: 'warn',
  not_enabled: 'secondary',
};

/** Usuarios de Podman rootless detectados en la última recolección (`facts.detected.podmanUsers`). */
export function detectedPodmanUsers(asset: Asset): PodmanRootlessUser[] {
  const detected = (asset.facts as { detected?: { podmanUsers?: unknown } } | null)?.detected;
  return Array.isArray(detected?.podmanUsers) ? (detected.podmanUsers as PodmanRootlessUser[]) : [];
}

/** URL de la terminal de solo lectura que ejecuta «Habilitar» con el acceso de administración. */
export function podmanEnableTerminalUrl(assetId: string, users: readonly string[]): string {
  const query = new URLSearchParams({ action: 'podman-enable', users: users.join(',') });
  return `/assets/${encodeURIComponent(assetId)}/terminal?${query}`;
}

/**
 * «Usuarios de Podman» (DESIGN §8): los usuarios con Podman rootless que la recolección detecta
 * sola (contenedores en marcha, socket o almacenamiento en su home) y si se inventarían. Los que
 * faltan se habilitan con un comando para copiar o, si el servidor tiene el acceso de
 * administración y la persona puede abrir terminal, ejecutándolo en una terminal de solo lectura.
 */
@Component({
  selector: 'app-podman-users',
  imports: [ButtonModule, CardModule, DialogModule, TagModule, TooltipModule],
  template: `
    <p-card styleClass="card" data-section="podman-users">
      <ng-template #title>
        <i class="bi bi-people" aria-hidden="true"></i> Usuarios de Podman
      </ng-template>
      <ul class="list">
        @for (u of users(); track u.uid) {
          <li [attr.data-podman-user]="u.name ?? u.uid">
            <strong>{{ u.name ?? 'uid ' + u.uid }}</strong>
            <small class="muted">uid {{ u.uid }}</small>
            <p-tag
              [value]="stateLabels[state(u)]"
              [severity]="stateSeverity[state(u)]"
              [attr.data-podman-state]="state(u)"
            />
            @if (u.containers) {
              <small>{{ u.containers }} {{ u.containers === 1 ? 'contenedor' : 'contenedores' }} en marcha</small>
            }
            @if (state(u) !== 'inventoried' && !u.linger) {
              <small class="muted" pTooltip="Sin linger, su socket desaparece al cerrar su última sesión">sin linger</small>
            }
          </li>
        }
      </ul>
      @if (pending().length) {
        <p class="muted">
          Sus contenedores no se inventarían hasta habilitarlos: InfraWard solo pregunta al
          Podman de los usuarios que el servidor autoriza.
        </p>
        <p-button
          [label]="pending().length === 1 ? 'Habilitar ' + pending()[0] : 'Habilitar (' + pending().length + ')'"
          icon="bi bi-unlock"
          size="small"
          [outlined]="true"
          data-action="podman-enable"
          (onClick)="open.set(true)"
        />
      }
    </p-card>

    <p-dialog
      header="Habilitar Podman rootless"
      [visible]="open()"
      (visibleChange)="open.set($event)"
      [modal]="true"
      [style]="{ width: 'min(48rem, 95vw)' }"
      data-dialog="podman-enable"
    >
      <p>
        Para <strong>{{ pending().join(', ') }}</strong>: activa linger, el socket de Podman de cada
        usuario (<code>systemctl --user enable --now podman.socket</code>) y los añade a
        <code>/etc/infraward/podman-users</code>. Ejecútalo en el servidor con una cuenta con sudo:
      </p>
      <div class="command">
        <pre data-podman-command><code>{{ command() }}</code></pre>
        <p-button icon="bi bi-clipboard" [text]="true" severity="secondary" ariaLabel="Copiar el comando" data-action="podman-copy" (onClick)="copy()" />
      </div>
      @if (terminal(); as t) {
        @if (t.allowed) {
          <p class="muted">
            O ejecútalo desde aquí con <code>{{ t.account }}</code>: se abre una terminal de
            <strong>solo lectura</strong> en otra pestaña donde ves el comando y su salida.
          </p>
        }
      }
      <p class="muted">Después, vuelve a recolectar el servidor para ver sus contenedores.</p>
      <ng-template #footer>
        <p-button label="Cerrar" severity="secondary" [text]="true" (onClick)="open.set(false)" />
        @if (terminal(); as t) {
          @if (t.allowed) {
            <span [pTooltip]="t.available ? undefined : (t.reason ?? undefined)">
              <p-button
                [label]="'Ejecutar con ' + t.account"
                icon="bi bi-terminal"
                [disabled]="!t.available"
                data-action="podman-run"
                (onClick)="run()"
              />
            </span>
          }
        }
      </ng-template>
    </p-dialog>
  `,
  styles: `
    .list {
      list-style: none;
      margin: 0 0 0.5rem;
      padding: 0;
      display: grid;
      gap: 0.25rem;
    }
    li {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      flex-wrap: wrap;
    }
    .muted {
      color: var(--p-text-muted-color);
    }
    .command {
      display: flex;
      align-items: flex-start;
      gap: 0.25rem;
    }
    pre {
      flex: 1;
      min-width: 0;
      max-height: 16rem;
      overflow: auto;
      margin: 0;
      padding: 0.5rem;
      font-size: 0.8rem;
      background: var(--p-content-hover-background);
      border-radius: var(--p-content-border-radius);
    }
  `,
})
export class PodmanUsersCard {
  readonly asset = input.required<Asset>();
  private readonly api = inject(TerminalApi);
  private readonly messages = inject(MessageService);

  protected readonly stateLabels = PODMAN_USER_STATE_LABELS;
  protected readonly stateSeverity = STATE_SEVERITY;
  protected readonly open = signal(false);

  readonly users = computed(() => detectedPodmanUsers(this.asset()));
  /** Los que se pueden habilitar (con nombre y sin inventariar), hasta el máximo de una vez. */
  readonly pending = computed(() =>
    this.users()
      .filter(podmanUserNeedsEnable)
      .map((u) => u.name!)
      .slice(0, PODMAN_ENABLE_MAX_USERS),
  );
  readonly command = computed(() =>
    this.pending().length ? podmanEnableCommand(this.pending()) : '',
  );

  /** ¿Puede esta persona abrir terminal aquí? (la opción «Ejecutar con …»). */
  readonly terminal = toSignal(
    toObservable(computed(() => this.asset().id)).pipe(
      switchMap((id) =>
        this.api.status(id).pipe(catchError(() => of<AssetTerminalStatus | null>(null))),
      ),
    ),
    { initialValue: null },
  );

  protected state(user: PodmanRootlessUser): PodmanUserState {
    return podmanUserState(user);
  }

  async copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(this.command());
      this.messages.add({ severity: 'success', summary: 'Comando copiado' });
    } catch {
      // Sin permiso de portapapeles: el comando sigue a la vista para copiarlo a mano.
    }
  }

  /** En otra pestaña, sin `opener` (como «Abrir terminal»). */
  run(): void {
    window.open(podmanEnableTerminalUrl(this.asset().id, this.pending()), '_blank', 'noopener');
    this.open.set(false);
  }
}
