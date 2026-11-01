import { describe, expect, it } from 'vitest';
import {
  PODMAN_ENABLE_SCRIPT,
  podmanEnableCommand,
  podmanUserNeedsEnable,
  podmanUserState,
  type PodmanRootlessUser,
} from './podman.js';
import { parseTerminalAction } from './terminal.js';

const user = (over: Partial<PodmanRootlessUser> = {}): PodmanRootlessUser => ({
  uid: 1000,
  name: 'alice',
  enabled: false,
  socket: false,
  storage: true,
  linger: false,
  containers: 2,
  ...over,
});

describe('Podman rootless', () => {
  it('estado de cada usuario y a quién se le ofrece «Habilitar»', () => {
    expect(podmanUserState(user())).toBe('not_enabled');
    expect(podmanUserState(user({ enabled: true }))).toBe('no_socket');
    expect(podmanUserState(user({ enabled: true, socket: true }))).toBe('inventoried');
    expect(podmanUserNeedsEnable(user())).toBe(true);
    expect(podmanUserNeedsEnable(user({ enabled: true }))).toBe(true);
    expect(podmanUserNeedsEnable(user({ enabled: true, socket: true }))).toBe(false);
    expect(podmanUserNeedsEnable(user({ name: null }))).toBe(false);
  });

  it('comando para copiar: heredoc entre comillas con el script y los usuarios como argumentos', () => {
    const command = podmanEnableCommand(['alice', 'bob']);
    expect(command.startsWith("sudo sh -s -- alice bob <<'INFRAWARD_PODMAN'\n")).toBe(true);
    expect(command.endsWith('\nINFRAWARD_PODMAN\n')).toBe(true);
    expect(command).toContain(PODMAN_ENABLE_SCRIPT);
    expect(PODMAN_ENABLE_SCRIPT).not.toContain('INFRAWARD_PODMAN');
    expect(PODMAN_ENABLE_SCRIPT).not.toContain('${');
    expect(() => podmanEnableCommand([])).toThrow();
    expect(() => podmanEnableCommand(['a;id'])).toThrow('no válido');
    expect(() => podmanEnableCommand(['$(id)'])).toThrow('no válido');
  });

  it('acción de terminal: solo podman-enable con nombres válidos (sin repetir) y no demasiados', () => {
    expect(parseTerminalAction({ kind: 'podman-enable', users: ['alice', 'alice', 'bob'] })).toEqual({
      kind: 'podman-enable',
      users: ['alice', 'bob'],
    });
    expect(parseTerminalAction({ kind: 'podman-enable', users: [] })).toBeNull();
    expect(parseTerminalAction({ kind: 'podman-enable', users: ['Alice'] })).toBeNull();
    expect(parseTerminalAction({ kind: 'podman-enable', users: ['-rf'] })).toBeNull();
    expect(parseTerminalAction({ kind: 'shell', users: ['alice'] })).toBeNull();
    expect(parseTerminalAction({ kind: 'podman-enable', users: Array(21).fill('a') })).toBeNull();
    expect(parseTerminalAction(null)).toBeNull();
  });
});
