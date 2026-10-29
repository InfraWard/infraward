import { InjectionToken } from '@angular/core';

/** Colores de la terminal (de los tokens de OptimusNG: cambian con el modo claro/oscuro). */
export interface TerminalTheme {
  background: string;
  foreground: string;
  cursor: string;
  selectionBackground: string;
  /** Colores ANSI: en claro, más oscuros (el amarillo de serie no se lee sobre blanco). */
  black?: string;
  red?: string;
  green?: string;
  yellow?: string;
  blue?: string;
  magenta?: string;
  cyan?: string;
  white?: string;
  brightBlack?: string;
  brightRed?: string;
  brightGreen?: string;
  brightYellow?: string;
  brightBlue?: string;
  brightMagenta?: string;
  brightCyan?: string;
  brightWhite?: string;
}

/** Paleta ANSI legible sobre fondo claro (en oscuro, la de xterm). */
const LIGHT_ANSI = {
  black: '#1f2937',
  red: '#b91c1c',
  green: '#15803d',
  yellow: '#a16207',
  blue: '#1d4ed8',
  magenta: '#a21caf',
  cyan: '#0e7490',
  white: '#6b7280',
  brightBlack: '#4b5563',
  brightRed: '#dc2626',
  brightGreen: '#16a34a',
  brightYellow: '#b45309',
  brightBlue: '#2563eb',
  brightMagenta: '#c026d3',
  brightCyan: '#0891b2',
  brightWhite: '#374151',
};

/** Lo que la página usa de xterm.js: así los tests ponen uno falso y xterm se carga perezoso. */
export interface TerminalView {
  /** Datos del servidor (frames binarios). */
  write(data: Uint8Array | string): void;
  /** Lo que teclea o pega la persona. */
  onData(listener: (data: string) => void): void;
  /** Ajusta columnas y filas al contenedor y las devuelve. */
  fit(): { cols: number; rows: number };
  setTheme(theme: TerminalTheme): void;
  getSelection(): string;
  paste(text: string): void;
  focus(): void;
  /** Atajos propios antes que xterm (false = xterm no lo procesa). */
  onKey(handler: (event: KeyboardEvent) => boolean): void;
  dispose(): void;
}

export type TerminalEngine = (container: HTMLElement, theme: TerminalTheme) => Promise<TerminalView>;

/** xterm.js + el ajuste al contenedor, cargados solo al abrir una terminal. */
export const TERMINAL_ENGINE = new InjectionToken<TerminalEngine>('TERMINAL_ENGINE', {
  providedIn: 'root',
  factory: () => async (container, theme) => {
    const [{ Terminal }, { FitAddon }] = await Promise.all([
      import('@xterm/xterm'),
      import('@xterm/addon-fit'),
    ]);
    const term = new Terminal({
      theme,
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 14,
      scrollback: 5000,
      allowProposedApi: false,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    return {
      write: (data) => term.write(data),
      onData: (listener) => void term.onData(listener),
      fit: () => {
        fit.fit();
        return { cols: term.cols, rows: term.rows };
      },
      setTheme: (t) => (term.options.theme = t),
      getSelection: () => term.getSelection(),
      paste: (text) => term.paste(text),
      focus: () => term.focus(),
      onKey: (handler) => term.attachCustomKeyEventHandler(handler),
      dispose: () => term.dispose(),
    };
  },
});

/** Cómo se abre el WebSocket (los tests lo sustituyen). */
export const TERMINAL_SOCKET = new InjectionToken<(url: string) => WebSocket>('TERMINAL_SOCKET', {
  providedIn: 'root',
  factory: () => (url) => new WebSocket(url),
});

/** Tema a partir de las variables CSS del documento. */
export function readTerminalTheme(el: Element, dark: boolean): TerminalTheme {
  const css = getComputedStyle(el);
  const v = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  const primary = v('--p-primary-color', '#14b8a6');
  return {
    background: v('--p-content-background', dark ? '#18181b' : '#ffffff'),
    foreground: v('--p-text-color', dark ? '#e5e7eb' : '#1f2937'),
    cursor: primary,
    selectionBackground: dark ? 'rgba(45, 212, 191, 0.35)' : 'rgba(20, 184, 166, 0.25)',
    ...(dark ? {} : LIGHT_ANSI),
  };
}
