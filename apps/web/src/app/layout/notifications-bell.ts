import { DatePipe } from '@angular/common';
import { Component, inject, signal, viewChild } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink } from '@angular/router';
import type { Notification } from '@infraward/shared-types';
import { BadgeModule } from '@openng/optimus-ui/badge';
import { ButtonModule } from '@openng/optimus-ui/button';
import { Popover, PopoverModule } from '@openng/optimus-ui/popover';
import { filter, startWith } from 'rxjs';
import { MaintenanceApi } from '../core/api/maintenance-api';
import { apiErrorMessage } from '../shared/api-errors';
import { ASSET_TYPE_ICONS } from '../shared/labels';
import { NOTIFICATION_ICONS } from '../shared/maintenance-labels';

/** Cuántos avisos se ven en el desplegable. */
export const BELL_LIMIT = 15;

/**
 * Campana de la barra superior (DESIGN §10, §15): no leídas de la reconciliación (altas,
 * desaparecidos, retirados, reapariciones y fallos). Se pide al navegar y al abrirla; sin sondeo
 * en reposo.
 */
@Component({
  selector: 'app-notifications-bell',
  imports: [DatePipe, RouterLink, BadgeModule, ButtonModule, PopoverModule],
  template: `
    <span class="bell">
      <p-button
        icon="bi bi-bell"
        severity="secondary"
        [text]="true"
        [ariaLabel]="unread() ? unread() + ' notificaciones sin leer' : 'Notificaciones'"
        data-action="notifications"
        (onClick)="toggle($event)"
      />
      @if (unread()) {
        <p-badge
          [value]="unread() > 99 ? '99+' : unread()"
          severity="danger"
          size="small"
          class="count"
          data-unread
        />
      }
    </span>
    <p-popover #panel appendTo="body" styleClass="notifications-panel">
      <div class="panel" data-notifications>
        <div class="panel-head">
          <strong>Notificaciones</strong>
          <p-button
            label="Marcar como leídas"
            size="small"
            [text]="true"
            [disabled]="!unread()"
            (onClick)="markSeen()"
            data-action="notifications-seen"
          />
        </div>
        @if (error(); as message) {
          <p class="muted">{{ message }}</p>
        } @else if (items() === null) {
          <p class="muted">Cargando…</p>
        } @else {
          <ul>
            @for (n of items(); track n.id) {
              <li [class.unread]="n.unread" [attr.data-kind]="n.kind">
                <i class="bi {{ icons[n.kind] }} kind-{{ n.kind }}" aria-hidden="true"></i>
                <div class="body">
                  <p class="message">{{ n.message }}</p>
                  @if (n.items.length) {
                    <p class="links">
                      @for (item of n.items.slice(0, 6); track item.id) {
                        @if (item.type === 'vulnerability') {
                          <a [routerLink]="['/vulnerabilities', item.id]" (click)="panel.hide()">
                            <i class="bi bi-shield-exclamation" aria-hidden="true"></i> {{ item.name }}
                          </a>
                        } @else {
                          <a [routerLink]="['/assets', item.id]" (click)="panel.hide()">
                            <i class="bi {{ typeIcons[item.type] }}" aria-hidden="true"></i> {{ item.name }}
                          </a>
                        }
                      }
                    </p>
                  }
                  <p class="muted small">{{ n.createdAt | date: 'short' }}</p>
                </div>
              </li>
            } @empty {
              <li class="muted empty">Sin notificaciones. Aquí aparecerán las altas, desapariciones, fallos de la reconciliación y los CVE críticos explotados (KEV) que estén expuestos.</li>
            }
          </ul>
        }
      </div>
    </p-popover>
  `,
  styles: `
    .bell {
      position: relative;
      display: inline-flex;
    }
    .count {
      position: absolute;
      top: 0.1rem;
      right: 0.05rem;
      pointer-events: none;
    }
    .panel {
      width: min(26rem, calc(100vw - 2rem));
      max-height: min(32rem, 70vh);
      overflow-y: auto;
    }
    .panel-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.5rem;
    }
    ul {
      list-style: none;
      padding: 0;
      margin: 0;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    li {
      display: flex;
      gap: 0.6rem;
      padding: 0.65rem 0.6rem;
      border: 1px solid var(--p-content-border-color);
      border-radius: var(--p-content-border-radius);
    }
    li.unread {
      background: var(--p-highlight-background);
      border-radius: var(--p-content-border-radius);
    }
    li > .bi {
      font-size: 1.1rem;
      margin-top: 0.1rem;
    }
    .kind-asset_created {
      color: var(--p-app-success-color);
    }
    .kind-asset_missing {
      color: var(--p-app-warn-color);
    }
    .kind-reconcile_failed {
      color: var(--p-app-danger-color);
    }
    .kind-asset_reactivated {
      color: var(--p-app-info-color);
    }
    .kind-vulnerability_kev {
      color: var(--p-app-danger-color);
    }
    li[data-kind='vulnerability_kev'] .message {
      font-weight: 600;
    }
    .body {
      min-width: 0;
    }
    .message {
      margin: 0;
      overflow-wrap: anywhere;
    }
    .links {
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem 0.75rem;
      margin: 0.25rem 0 0;
    }
    .small {
      margin: 0.2rem 0 0;
    }
    .empty {
      border: 0;
    }
  `,
})
export class NotificationsBell {
  private readonly api = inject(MaintenanceApi);
  private readonly panel = viewChild.required<Popover>('panel');

  protected readonly icons: Readonly<Record<string, string>> = NOTIFICATION_ICONS;
  protected readonly typeIcons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
  protected readonly unread = signal(0);
  protected readonly items = signal<Notification[] | null>(null);
  protected readonly error = signal<string | null>(null);

  constructor() {
    // Al entrar y en cada navegación: una petición, sin sondeo.
    inject(Router)
      .events.pipe(
        filter((e) => e instanceof NavigationEnd),
        startWith(null),
        takeUntilDestroyed(),
      )
      .subscribe(() => this.refreshCount());
  }

  private refreshCount(): void {
    this.api.unreadNotifications().subscribe({
      next: (r) => this.unread.set(r.unread),
      // Sin la cuenta, la campana sigue funcionando (al abrirla lo vuelve a pedir).
      error: () => undefined,
    });
  }

  protected toggle(event: Event): void {
    this.panel().toggle(event);
    this.items.set(null);
    this.error.set(null);
    this.api.notifications(BELL_LIMIT).subscribe({
      next: (page) => {
        this.items.set(page.items);
        this.unread.set(page.unread);
      },
      error: (err: unknown) =>
        this.error.set(apiErrorMessage(err, 'No se pudieron cargar las notificaciones.')),
    });
  }

  protected markSeen(): void {
    this.api.markNotificationsSeen().subscribe({
      next: () => {
        this.unread.set(0);
        this.items.update((list) =>
          list ? list.map((n) => ({ ...n, unread: false })) : list,
        );
      },
      error: () => undefined,
    });
  }
}
