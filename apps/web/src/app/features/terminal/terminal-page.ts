import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  effect,
  ElementRef,
  inject,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { Title } from '@angular/platform-browser';
import { RouterLink } from '@angular/router';
import {
  parseTerminalAction,
  terminalSocketUrl,
  type TerminalAction,
  type TerminalCloseReason,
  type TerminalServerMessage,
} from '@infraward/shared-types';
import { MessageService } from '@openng/optimus-ui/api';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { firstValueFrom } from 'rxjs';
import { InventoryApi } from '../../core/api/inventory-api';
import { TerminalApi } from '../../core/api/terminal-api';
import { AuthService } from '../../core/auth/auth.service';
import { apiErrorMessage } from '../../shared/api-errors';
import {
  readTerminalTheme,
  TERMINAL_ENGINE,
  TERMINAL_SOCKET,
  type TerminalView,
} from './terminal-engine';

/** Por qué terminó la sesión, para la persona. */
export const TERMINAL_CLOSE_LABELS: Record<TerminalCloseReason, string> = {
  exit: 'La sesión ha terminado',
  client: 'Te has desconectado',
  idle: 'Cerrada por inactividad',
  max_duration: 'Cerrada: llegó a su duración máxima',
  gateway_shutdown: 'Cerrada: el gateway se ha reiniciado',
  limit: 'Sin hueco para otra terminal',
  connect_failed: 'No se pudo conectar',
  expired: 'El ticket caducó',
  denied: 'Acceso denegado',
  revoked: 'Cortada por InfraWard',
  gateway_lost: 'El gateway dejó de responder',
};

export const LEAVE_QUESTION = 'La terminal sigue abierta. ¿Salir y cerrarla?';

type State =
  | { kind: 'connecting' }
  /** Acción de la URL a la espera de que la persona la confirme (nada se ha pedido aún). */
  | { kind: 'confirm' }
  | { kind: 'open'; account: string; readOnly: boolean }
  | { kind: 'closed'; message: string; error: boolean };

/** Rebote del ajuste de tamaño al redimensionar la ventana. */
const RESIZE_DEBOUNCE_MS = 120;

/**
 * Terminal web (sesión 22, DESIGN §11): xterm.js ↔ WebSocket del gateway, en su propia ruta
 * (`/assets/:id/terminal`, se abre en otra pestaña: cada pestaña es una sesión). El ticket lo da
 * la API (con reautenticación reciente; el interceptor la pide) y viaja en el primer mensaje,
 * nunca en la URL; la cookie de la sesión viaja sola en el upgrade (mismo origen).
 */
@Component({
  selector: 'app-terminal-page',
  imports: [RouterLink, ButtonModule, TagModule, TooltipModule],
  templateUrl: './terminal-page.html',
  styleUrl: './terminal-page.scss',
})
export class TerminalPage {
  /** Del parámetro `:id` de la ruta. */
  readonly id = input.required<string>();
  /**
   * Acción de solo lectura (query `?action=podman-enable&users=a,b`, desde «Habilitar» en
   * «Usuarios de Podman»): la sesión ejecuta ese comando fijo y no admite entrada. Nunca se
   * ejecuta al cargar: un enlace no basta, la persona tiene que pulsar «Ejecutar».
   */
  readonly action = input<string | undefined>(undefined);
  readonly users = input<string | undefined>(undefined);

  /** La acción pedida, validada (null = shell interactiva). */
  readonly terminalAction = computed<TerminalAction | null>(() => {
    const kind = this.action();
    if (!kind) return null;
    return parseTerminalAction({ kind, users: (this.users() ?? '').split(',') });
  });
  /** Hay acción en la URL, pero no es válida: no se abre nada. */
  private readonly badAction = computed(() => !!this.action() && !this.terminalAction());

  private readonly terminalApi = inject(TerminalApi);
  private readonly inventory = inject(InventoryApi);
  private readonly engine = inject(TERMINAL_ENGINE);
  private readonly openSocket = inject(TERMINAL_SOCKET);
  private readonly auth = inject(AuthService);
  private readonly title = inject(Title);
  private readonly messages = inject(MessageService);
  private readonly host = viewChild.required<ElementRef<HTMLElement>>('screen');

  readonly state = signal<State>({ kind: 'connecting' });
  readonly assetName = signal<string | null>(null);

  private view: TerminalView | null = null;
  private socket: WebSocket | null = null;
  private size = { cols: 80, rows: 24 };
  private resizeTimer?: ReturnType<typeof setTimeout>;
  private readonly encoder = new TextEncoder();
  private readonly dark = globalThis.matchMedia?.('(prefers-color-scheme: dark)');
  private readonly onScheme = () => this.view?.setTheme(this.theme());
  private readonly beforeUnload = (event: BeforeUnloadEvent) => {
    // Como canLeave: sin socket no hay nada que cerrar (p. ej. al salir al proveedor OIDC para
    // confirmar la identidad, con el ticket aún pendiente).
    if (this.isOpen() && this.socket) event.preventDefault();
  };

  constructor() {
    const destroyRef = inject(DestroyRef);
    afterNextRender(() => void this.start());
    // Al cerrar la sesión web en esta pestaña, la terminal también (la API la corta igual).
    effect(() => {
      if (!this.auth.user()) this.disconnect();
    });
    addEventListener('beforeunload', this.beforeUnload);
    this.dark?.addEventListener('change', this.onScheme);
    destroyRef.onDestroy(() => {
      removeEventListener('beforeunload', this.beforeUnload);
      this.dark?.removeEventListener('change', this.onScheme);
      this.observer?.disconnect();
      clearTimeout(this.resizeTimer);
      this.disconnect();
      this.view?.dispose();
    });
  }

  private observer?: ResizeObserver;

  /** ¿Hay una sesión abierta o abriéndose? (pide confirmación antes de salir). */
  isOpen(): boolean {
    const kind = this.state().kind;
    return kind === 'open' || kind === 'connecting';
  }

  /** `canDeactivate` de la ruta. */
  canLeave(): boolean {
    if (!this.isOpen() || !this.socket) return true;
    return confirm(LEAVE_QUESTION);
  }

  async copy(): Promise<void> {
    const text = this.view?.getSelection() ?? '';
    if (!text) {
      this.messages.add({ severity: 'info', summary: 'Selecciona primero el texto a copiar' });
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      this.messages.add({ severity: 'warn', summary: 'El navegador no deja copiar aquí' });
    }
    this.view?.focus();
  }

  async paste(): Promise<void> {
    if (this.readOnly()) return;
    try {
      const text = await navigator.clipboard.readText();
      if (text) this.view?.paste(text);
    } catch {
      this.messages.add({
        severity: 'warn',
        summary: 'El navegador no deja leer el portapapeles',
        detail: 'Usa Ctrl+Shift+V (Cmd+V en macOS)',
      });
    }
    this.view?.focus();
  }

  /** Ticket nuevo: vuelve a comprobar permiso y reautenticación. */
  reconnect(): void {
    this.disconnect();
    // Si xterm no llegó a cargarse, se reintenta antes: sin él no hay dónde pintar la sesión.
    if (!this.view) {
      void this.loadAndConnect();
      return;
    }
    // Con una acción, volver a ejecutarla también pide confirmación.
    if (this.terminalAction()) {
      this.awaitConfirmation();
      return;
    }
    this.view.write('\r\n\x1b[2m── Reconectando… ──\x1b[0m\r\n');
    void this.connect();
  }

  /** «Ejecutar»: la persona confirma la acción de la URL. */
  run(): void {
    if (this.state().kind !== 'confirm') return;
    this.view?.write('\r\n\x1b[2m── Ejecutando… ──\x1b[0m\r\n');
    void this.connect();
  }

  /** Lo que hará la acción, para confirmarla («habilitar Podman rootless para alice, bob»). */
  actionLabel(): string {
    const action = this.terminalAction();
    return action ? `habilitar Podman rootless para ${action.users.join(', ')}` : '';
  }

  /** Acción válida en la URL: se queda a la espera de «Ejecutar» sin pedir ticket. */
  private awaitConfirmation(): void {
    this.state.set({ kind: 'confirm' });
    this.view?.write(
      `\r\n\x1b[2m── Sin ejecutar: confirma arriba para ${this.actionLabel()} ──\x1b[0m\r\n`,
    );
  }

  private async start(): Promise<void> {
    void firstValueFrom(this.inventory.asset(this.id()))
      .then((asset) => {
        const name = asset.displayName ?? asset.name;
        this.assetName.set(name);
        this.title.setTitle(`Terminal · ${name}`);
      })
      .catch(() => this.title.setTitle('Terminal · InfraWard'));
    await this.loadAndConnect();
  }

  /** Carga xterm en el contenedor y pide el ticket; si xterm no carga, lo dice y se queda ahí. */
  private async loadAndConnect(): Promise<void> {
    const container = this.host().nativeElement;
    let view: TerminalView;
    try {
      view = await this.engine(container, this.theme());
    } catch (error) {
      console.error('No se pudo cargar la terminal', error);
      this.state.set({ kind: 'closed', message: 'No se pudo cargar la terminal', error: true });
      return;
    }
    this.view = view;
    view.onData((data) => this.sendInput(data));
    view.onKey((event) => this.shortcut(event));
    this.size = view.fit();
    this.observer ??= new ResizeObserver(() => this.scheduleFit());
    this.observer.observe(container);
    if (this.terminalAction()) this.awaitConfirmation();
    else await this.connect();
  }

  private async connect(): Promise<void> {
    this.state.set({ kind: 'connecting' });
    let ticket;
    try {
      if (this.badAction()) throw new Error('Acción no válida');
      ticket = await firstValueFrom(this.terminalApi.open(this.id(), this.terminalAction()));
    } catch (error) {
      this.closed(this.openError(error), true);
      return;
    }
    const socket = this.openSocket(terminalSocketUrl(ticket.gatewayUrl, location.origin));
    socket.binaryType = 'arraybuffer';
    this.socket = socket;
    socket.onopen = () =>
      socket.send(JSON.stringify({ type: 'auth', ticket: ticket.ticket, ...this.size }));
    socket.onmessage = (event: MessageEvent) => {
      // Control en texto (JSON); los datos de la terminal, en binario.
      if (typeof event.data === 'string') {
        this.control(JSON.parse(event.data) as TerminalServerMessage);
        return;
      }
      this.view?.write(new Uint8Array(event.data as ArrayBuffer));
    };
    socket.onclose = () => {
      if (this.socket !== socket) return;
      this.socket = null;
      if (this.isOpen()) this.closed('Se ha perdido la conexión con el gateway', true);
    };
    this.view?.focus();
  }

  private control(message: TerminalServerMessage): void {
    switch (message.type) {
      case 'ready':
        this.state.set({
          kind: 'open',
          account: message.account,
          readOnly: !!message.readOnly || !!this.terminalAction(),
        });
        if (this.terminalAction())
          this.view?.write(
            `\x1b[2m── Solo lectura: habilitar Podman rootless para ${this.terminalAction()!.users.join(', ')} (sudo sh -c <script de InfraWard>) ──\x1b[0m\r\n`,
          );
        return;
      case 'notice':
        // El gateway ya lo escribe en la terminal; aquí también por si la pestaña no se mira.
        this.messages.add({ severity: 'warn', summary: message.message, life: 10_000 });
        return;
      case 'exit': {
        const label = TERMINAL_CLOSE_LABELS[message.reason] ?? 'La sesión ha terminado';
        const text = message.message ? `${label}: ${message.message}` : label;
        const error = message.reason !== 'exit' && message.reason !== 'client';
        this.view?.write(`\r\n\x1b[${error ? '31' : '2'}m[InfraWard] ${text}\x1b[0m\r\n`);
        this.closed(text, error);
        return;
      }
    }
  }

  private closed(message: string, error: boolean): void {
    this.state.set({ kind: 'closed', message, error });
  }

  private disconnect(): void {
    const socket = this.socket;
    this.socket = null;
    if (socket && socket.readyState <= 1) socket.close(1000, 'client');
    if (this.isOpen()) this.closed('Te has desconectado', false);
  }

  /** ¿Terminal de solo lectura? (se ve la salida, no se escribe). */
  readOnly(): boolean {
    return !!this.terminalAction();
  }

  private sendInput(data: string): void {
    if (this.readOnly()) return;
    if (this.socket?.readyState === 1 && this.state().kind === 'open')
      this.socket.send(this.encoder.encode(data));
  }

  private scheduleFit(): void {
    clearTimeout(this.resizeTimer);
    this.resizeTimer = setTimeout(() => {
      if (!this.view) return;
      const next = this.view.fit();
      if (next.cols === this.size.cols && next.rows === this.size.rows) return;
      this.size = next;
      if (this.socket?.readyState === 1 && this.state().kind === 'open')
        this.socket.send(JSON.stringify({ type: 'resize', ...next }));
    }, RESIZE_DEBOUNCE_MS);
  }

  /** Ctrl+Shift+C / Ctrl+Shift+V copian y pegan (Ctrl+C sigue siendo la interrupción). */
  private shortcut(event: KeyboardEvent): boolean {
    if (event.type !== 'keydown' || !event.ctrlKey || !event.shiftKey) return true;
    const key = event.key.toLowerCase();
    if (key === 'c') {
      event.preventDefault();
      void this.copy();
      return false;
    }
    if (key === 'v') {
      event.preventDefault();
      void this.paste();
      return false;
    }
    return true;
  }

  private theme() {
    return readTerminalTheme(document.documentElement, this.dark?.matches ?? false);
  }

  private openError(error: unknown): string {
    if (error instanceof HttpErrorResponse && error.status === 403) {
      const code = (error.error as { code?: string } | null)?.code;
      if (code === 'recent_auth_required' || code === 'mfa_required_for_action')
        return 'Hace falta confirmar tu identidad para abrir la terminal';
      return 'No tienes permiso para abrir una terminal en este asset';
    }
    if (error instanceof Error && error.message === 'Acción no válida')
      return 'El enlace de la terminal no es válido';
    return apiErrorMessage(error, 'No se pudo abrir la terminal');
  }
}
