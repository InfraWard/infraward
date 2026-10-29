import {
  SUDOERS_CAPABILITIES,
  SUDOERS_VERSION,
  requiredSudoersVersion,
  sudoersAllows,
  sudoersCapabilitiesFor,
  sudoersGaps,
} from '@infraward/shared-types';
import { describe, expect, it } from 'vitest';

// La tabla vive en shared-types (sin tests propios); la cubre el worker, que es quien la aplica.
describe('SUDOERS_CAPABILITIES', () => {
  it('es la tabla documentada en DESIGN §14', () => {
    expect(SUDOERS_CAPABILITIES).toEqual({
      helper: expect.objectContaining({ version: 4, roles: ['*'], onMissing: 'outdated' }),
      'docker.save': expect.objectContaining({
        version: 4,
        roles: ['docker-host'],
        onMissing: 'outdated',
      }),
      plesk: expect.objectContaining({ version: 4, roles: ['plesk'], onMissing: 'outdated' }),
      // v5 (QoL-5b): rutas de los proxies; sin ella, una nota (no «desactualizado»).
      proxies: expect.objectContaining({ version: 5, roles: ['*'], onMissing: 'note' }),
      // v6 (sesión 19): paquetes de los procesos; sin ella, otra nota.
      processes: expect.objectContaining({ version: 6, roles: ['*'], onMissing: 'note' }),
      // v7 (QoL-7): autenticación efectiva de sshd; sin ella, otra nota.
      sshd: expect.objectContaining({ version: 7, roles: ['*'], onMissing: 'note' }),
    });
    expect(SUDOERS_VERSION).toBe(7);
    // Ninguna capacidad pide una versión que el script todavía no instala.
    for (const c of Object.values(SUDOERS_CAPABILITIES))
      expect(c.version).toBeLessThanOrEqual(SUDOERS_VERSION);
  });

  it('capacidades por roles: el ayudante, en cualquier servidor', () => {
    expect(sudoersCapabilitiesFor([])).toEqual(['helper', 'proxies', 'processes', 'sshd']);
    expect(sudoersCapabilitiesFor(['proxmox-node'])).toEqual(['helper', 'proxies', 'processes', 'sshd']);
    expect(sudoersCapabilitiesFor(['docker-host'])).toEqual([
      'helper',
      'docker.save',
      'proxies',
      'processes',
      'sshd',
    ]);
    expect(sudoersCapabilitiesFor(['plesk', 'web'])).toEqual([
      'helper',
      'plesk',
      'proxies',
      'processes',
      'sshd',
    ]);
  });

  it('versión exigida: la v4 en cualquier servidor (la v5 solo añade una nota)', () => {
    expect(requiredSudoersVersion([])).toBe(4);
    expect(requiredSudoersVersion(['proxmox-node'])).toBe(4);
    expect(requiredSudoersVersion(['docker-host', 'plesk'])).toBe(4);
  });

  it('sudoersAllows: por versión, y siempre por pct exec (root en el CT)', () => {
    expect(sudoersAllows('docker.save', 3)).toBe(false);
    expect(sudoersAllows('docker.save', 4)).toBe(true);
    expect(sudoersAllows('helper', 3)).toBe(false);
    expect(sudoersAllows('plesk', null)).toBe(false);
    expect(sudoersAllows('plesk', null, 'pct')).toBe(true);
  });

  it.each([
    // roles, versión, capacidades `outdated` que faltan
    [[], 3, ['helper']],
    [['docker-host'], 2, ['helper', 'docker.save']],
    [['plesk'], 3, ['helper', 'plesk']],
    [['docker-host', 'plesk'], 4, []],
    [['proxmox-node'], 4, []],
  ] as const)('gaps(%j, v%i)', (roles, version, outdated) => {
    const gaps = sudoersGaps(roles, version);
    expect(gaps.outdated).toEqual(outdated);
    expect(gaps.notes).toEqual([
      'Rutas de nginx, Nginx Proxy Manager, Traefik y Caddy (qué servicio sirve cada dominio): requiere sudoers v5. Vuelve a ejecutar el script de alta para actualizarlo',
      'Qué paquetes usan los procesos en marcha y en escucha (prioridad de las vulnerabilidades): requiere sudoers v6. Vuelve a ejecutar el script de alta para actualizarlo',
      'Si sshd admite el login de root o por contraseña (configuración efectiva de sshd): requiere sudoers v7. Vuelve a ejecutar el script de alta para actualizarlo',
    ]);
  });

  it('con la v5, las notas de la v6 y la v7; con la v6, la de la v7; con la v7, nada', () => {
    expect(sudoersGaps(['docker-host', 'plesk'], 5)).toEqual({
      outdated: [],
      notes: [
        expect.stringContaining('requiere sudoers v6'),
        expect.stringContaining('requiere sudoers v7'),
      ],
    });
    expect(sudoersGaps(['docker-host', 'plesk'], 6)).toEqual({
      outdated: [],
      notes: [expect.stringContaining('requiere sudoers v7')],
    });
    expect(sudoersGaps(['docker-host', 'plesk'], 7)).toEqual({ outdated: [], notes: [] });
  });
});
