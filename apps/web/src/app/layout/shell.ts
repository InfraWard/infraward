import { formatDate, NgTemplateOutlet } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  inject,
  Injector,
  LOCALE_ID,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  NavigationEnd,
  Router,
  RouterLink,
  RouterLinkActive,
  RouterOutlet,
} from '@angular/router';
import {
  ConfirmationService,
  MessageService,
  type MenuItem,
} from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { ConfirmDialogModule } from '@openng/optimus-ui/confirmdialog';
import { DrawerModule } from '@openng/optimus-ui/drawer';
import { MenuModule } from '@openng/optimus-ui/menu';
import { TagModule } from '@openng/optimus-ui/tag';
import { ToastModule } from '@openng/optimus-ui/toast';
import { ToolbarModule } from '@openng/optimus-ui/toolbar';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { filter } from 'rxjs';
import { AuthService } from '../core/auth/auth.service';
import { ReauthDialog } from '../core/auth/reauth-dialog';
import { BrandMark } from '../shared/brand-mark';
import { GlobalSearch } from './global-search';
import { NotificationsBell } from './notifications-bell';
import { NAV_ITEMS } from '../shared/nav-items';
import { roleLabel, roleSeverity } from '../shared/role-labels';

/** Por debajo de este ancho el menú lateral pasa a un drawer. */
export const MOBILE_QUERY = '(max-width: 959.98px)';
const COLLAPSED_KEY = 'infraward.nav.collapsed';

/**
 * Estructura de la aplicación: barra superior (menú, marca, usuario y sesión), menú lateral
 * plegable con las secciones y el contenido. En móvil el menú es un drawer.
 */
@Component({
  selector: 'app-shell',
  imports: [
    NgTemplateOutlet,
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    ToolbarModule,
    ButtonModule,
    DrawerModule,
    MenuModule,
    TagModule,
    ToastModule,
    ConfirmDialogModule,
    TooltipModule,
    BrandMark,
    GlobalSearch,
    NotificationsBell,
    ReauthDialog,
  ],
  // Confirmaciones y avisos de las páginas (acciones de la ficha…).
  providers: [ConfirmationService, MessageService],
  templateUrl: './shell.html',
  styleUrl: './shell.scss',
})
export class Shell {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly locale = inject(LOCALE_ID);
  private readonly messages = inject(MessageService);
  private readonly injector = inject(Injector);

  protected readonly navItems = computed(() =>
    NAV_ITEMS.filter((i) => !i.permission || this.auth.can(i.permission)),
  );
  protected readonly roleLabel = roleLabel;
  protected readonly roleSeverity = roleSeverity;
  protected readonly mobile = signal(matches(MOBILE_QUERY));
  protected readonly collapsed = signal(readCollapsed());
  protected readonly drawerOpen = signal(false);
  /** Barra de búsqueda desplegada (solo en móvil; en escritorio siempre está). */
  protected readonly searchOpen = signal(false);

  protected readonly userMenu = computed<MenuItem[]>(() => {
    const user = this.auth.user();
    const expiresAt = this.auth.expiresAt();
    return [
      {
        label: user ? `${user.name} · ${user.email}` : '',
        items: [
          {
            label: 'Tu perfil',
            icon: 'bi bi-person',
            routerLink: '/settings',
          },
          {
            label: expiresAt
              ? `Sesión hasta las ${formatDate(expiresAt, 'HH:mm', this.locale)}`
              : 'Sin sesión',
            icon: 'bi bi-clock',
            disabled: true,
          },
          {
            label: 'Cerrar sesión',
            icon: 'bi bi-box-arrow-right',
            command: () => void this.logout(),
          },
        ],
      },
    ];
  });

  constructor() {
    const media =
      typeof window !== 'undefined' && window.matchMedia
        ? window.matchMedia(MOBILE_QUERY)
        : null;
    if (media) {
      const update = (e: MediaQueryListEvent) => {
        this.mobile.set(e.matches);
        if (!e.matches) {
          this.drawerOpen.set(false);
          this.searchOpen.set(false);
        }
      };
      media.addEventListener('change', update);
      inject(DestroyRef).onDestroy(() =>
        media.removeEventListener('change', update),
      );
    }
    // Al volver a la pestaña se comprueba que la sesión sigue viva (sin sondeo en reposo): si la
    // han revocado (p. ej. un admin desactivó al usuario), se vuelve al login.
    if (typeof document !== 'undefined') {
      const onVisible = () => {
        // Un 401 lo gestiona el interceptor (cierra y lleva al login con el aviso).
        if (document.visibilityState === 'visible') void this.auth.verify();
      };
      document.addEventListener('visibilitychange', onVisible);
      inject(DestroyRef).onDestroy(() =>
        document.removeEventListener('visibilitychange', onVisible),
      );
    }
    // Al navegar desde el drawer, se cierra. A la vuelta de reautenticarse en el proveedor OIDC
    // (`?reauth=ok|failed`), se avisa y se quita el parámetro.
    this.router.events
      .pipe(
        filter((e) => e instanceof NavigationEnd),
        takeUntilDestroyed(),
      )
      .subscribe((e) => {
        this.drawerOpen.set(false);
        this.reauthResult((e as NavigationEnd).urlAfterRedirects);
      });
  }

  toggleMenu(): void {
    if (this.mobile()) {
      this.drawerOpen.update((open) => !open);
      return;
    }
    this.collapsed.update((c) => !c);
    try {
      localStorage.setItem(COLLAPSED_KEY, this.collapsed() ? '1' : '0');
    } catch {
      // Sin almacenamiento (modo privado…): solo dura esta visita.
    }
  }

  async logout(): Promise<void> {
    // Con sesión del proveedor OIDC, el navegador sale a cerrarla y vuelve a /login.
    if (!(await this.auth.logout())) await this.router.navigate(['/login']);
  }

  /** Vuelta de la reautenticación en el proveedor: aviso y fuera el parámetro de la URL. */
  private reauthResult(url: string): void {
    const tree = this.router.parseUrl(url);
    const result = tree.queryParams['reauth'];
    if (result !== 'ok' && result !== 'failed') return;
    // Tras volver del proveedor (carga completa), el p-toast aún no está pintado.
    afterNextRender(() => this.showReauthResult(result), { injector: this.injector });
    if (result === 'ok') void this.auth.verify();
    delete tree.queryParams['reauth'];
    void this.router.navigateByUrl(tree, { replaceUrl: true });
  }

  private showReauthResult(result: 'ok' | 'failed'): void {
    this.messages.add(
      result === 'ok'
        ? {
            severity: 'success',
            summary: 'Identidad confirmada',
            detail: 'Ya puedes repetir la acción.',
            life: 6000,
          }
        : {
            severity: 'error',
            summary: 'No se confirmó tu identidad',
            detail: 'Vuelve a intentarlo.',
            life: 8000,
          },
    );
  }
}

function matches(query: string): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia?.(query).matches;
}

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === '1';
  } catch {
    return false;
  }
}
