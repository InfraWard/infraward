import type { Asset } from '@infraward/shared-types';
import { availableActions } from './available-actions';

const connection = { host: '10.0.0.5', port: 22, user: 'infraward' } as Asset['connection'];
const base = {
  roles: [] as string[],
  connection: null as Asset['connection'],
  sshAuth: 'static_key' as Asset['sshAuth'],
};
const idle = { runtimeState: null, sudoersOutdated: false };
const ids = (...args: Parameters<typeof availableActions>) =>
  availableActions(...args).map((a) => (a.disabledReason ? `${a.id}:off` : a.id));

describe('availableActions', () => {
  it('servidor activo: recoger, escanear (su SBOM), dar de baja y purgar; uno manual sin conexión, no', () => {
    expect(ids({ ...base, type: 'server', status: 'active', connection }, idle)).toEqual([
      'collect',
      'scan',
      'retire',
      'purge',
    ]);
    expect(
      ids({ ...base, type: 'server', status: 'active', connection, roles: ['docker-host'] }, idle),
    ).toEqual(['collect', 'scan', 'retire', 'purge']);
    expect(
      ids({ ...base, type: 'server', status: 'active', connection, roles: ['podman-host'] }, idle),
    ).toEqual(['collect', 'scan', 'retire', 'purge']);
    expect(ids({ ...base, type: 'server', status: 'active' }, idle)).toEqual([
      'retire',
      'purge',
    ]);
  });

  it('escaneo desactivado por la política: «Escanear», deshabilitado con el motivo', () => {
    const off = {
      ...base,
      type: 'container' as const,
      status: 'active' as const,
      effectivePolicy: {
        values: { reconcileIntervalMinutes: 360, scanEnabled: false, scanPeriodic: true },
        sources: {
          reconcileIntervalMinutes: { kind: 'global' as const },
          scanEnabled: { kind: 'own' as const },
          scanPeriodic: { kind: 'global' as const },
        },
      },
    };
    const scan = availableActions(off, idle).find((a) => a.id === 'scan');
    expect(scan?.disabledReason).toBe('Escaneo desactivado por la política de inventario');
  });

  it('servidor pendiente: ver y regenerar el comando; recoger, deshabilitado', () => {
    expect(
      ids({ ...base, type: 'server', status: 'pending_enrollment', connection }, idle),
    ).toEqual(['collect:off', 'enrollment', 'regenerate', 'retire', 'purge']);
  });

  it('sudoers desactualizado: regenerar el comando para actualizarlo', () => {
    expect(
      ids(
        { ...base, type: 'server', status: 'active', connection },
        { runtimeState: null, sudoersOutdated: true },
      ),
    ).toContain('regenerate');
  });

  it('CT parado: recoger y escanear deshabilitados con su motivo', () => {
    const [collect, scan] = availableActions(
      { ...base, type: 'lxc', status: 'active' },
      { runtimeState: 'stopped', sudoersOutdated: false },
    );
    expect(collect).toEqual({ id: 'collect', disabledReason: 'El CT está parado' });
    expect(scan).toEqual({ id: 'scan', disabledReason: 'El CT está parado' });
    expect(ids({ ...base, type: 'lxc', status: 'active' }, idle)).toEqual([
      'collect',
      'scan',
      'retire',
      'purge',
    ]);
  });

  it('contenedor e imagen: escanear; un retirado solo se puede purgar', () => {
    expect(ids({ ...base, type: 'container', status: 'active' }, idle)).toEqual([
      'scan',
      'retire',
      'purge',
    ]);
    expect(ids({ ...base, type: 'image', status: 'active' }, idle)).toEqual([
      'scan',
      'retire',
      'purge',
    ]);
    expect(ids({ ...base, type: 'container', status: 'retired' }, idle)).toEqual(['purge']);
    expect(ids({ ...base, type: 'domain', status: 'retired' }, idle)).toEqual(['purge']);
  });

  it('servidor activo del script con clave estática: pasar a certificados de la CA', () => {
    const inventory = { host: '10.0.0.5', port: 22, user: 'inventory' };
    expect(
      ids(
        { ...base, type: 'server', status: 'active', connection: inventory },
        { ...idle, caAvailable: true },
      ),
    ).toEqual(['collect', 'scan', 'migrate-ca', 'retire', 'purge']);
    // Sin proveedor con CA SSH (o sin saberlo aún): deshabilitado, con el motivo.
    const [, , migrate] = availableActions(
      { ...base, type: 'server', status: 'active', connection: inventory },
      { ...idle, caAvailable: false },
    );
    expect(migrate.id).toBe('migrate-ca');
    expect(migrate.disabledReason).toMatch(/Ningún proveedor de secretos activo tiene CA SSH/);
    expect(
      ids({ ...base, type: 'server', status: 'active', connection: inventory }, idle),
    ).toContain('migrate-ca:off');
    // Ya en modo CA, o dado de alta a mano con otro usuario: no.
    expect(
      ids(
        { ...base, type: 'server', status: 'active', connection: inventory, sshAuth: 'ca_certificate' },
        idle,
      ),
    ).not.toContain('migrate-ca');
    expect(ids({ ...base, type: 'server', status: 'active', connection }, idle)).not.toContain(
      'migrate-ca',
    );
  });

  it('CA SSH desactualizada: regenerar el comando para actualizar las claves', () => {
    expect(
      ids(
        { ...base, type: 'server', status: 'active', connection, sshAuth: 'ca_certificate' },
        { ...idle, sshCaOutdated: true },
      ),
    ).toContain('regenerate');
  });
});
