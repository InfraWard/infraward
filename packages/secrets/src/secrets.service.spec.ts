import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SecretProvider } from './secret-provider.js';
import { SecretsService } from './secrets.service.js';

/** Proveedor de prueba que cuenta las lecturas. */
function fakeProvider(
  id: string,
  data: Record<string, string> = {},
  extra: Partial<SecretProvider> & {
    signSshKey?: unknown;
    sshCaPublicKeys?: unknown;
  } = {},
) {
  const store = new Map(Object.entries(data));
  const provider = {
    id,
    get: vi.fn(async (path: string, field?: string) => {
      const value = store.get(field ? `${path}#${field}` : path);
      if (value === undefined) throw new Error(`no existe ${path}`);
      return value;
    }),
    set: vi.fn(async (path: string, fields: Record<string, string>) => {
      for (const [k, v] of Object.entries(fields)) store.set(`${path}#${k}`, v);
    }),
    delete: vi.fn(async (path: string) => {
      let existed = false;
      for (const key of [...store.keys()]) {
        if (key === path || key.startsWith(`${path}#`)) {
          store.delete(key);
          existed = true;
        }
      }
      return existed;
    }),
    healthCheck: vi.fn(async () => true),
    ...extra,
  };
  return provider;
}

describe('SecretsService', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('resuelve contra el proveedor de la referencia', async () => {
    const local = fakeProvider('local', { 'a/b#f': 'valor-local' });
    const other = fakeProvider('openbao', { 'a/b#f': 'valor-bao' });
    const service = new SecretsService([local, other], 60);
    expect(await service.resolve('secret://openbao/a/b#f')).toBe('valor-bao');
    expect(other.get).toHaveBeenCalledWith('a/b', 'f');
    expect(local.get).not.toHaveBeenCalled();
  });

  it('rechaza proveedores no configurados sin tocar los demás', async () => {
    const local = fakeProvider('local');
    const service = new SecretsService([local], 60);
    await expect(
      service.resolve('secret://vaultwarden/x#y'),
    ).rejects.toMatchObject({
      code: 'provider_not_configured',
      message: 'Proveedor de secretos no configurado: vaultwarden',
    });
    expect(local.get).not.toHaveBeenCalled();
    await expect(
      service.store('secret://openbao/x', { a: 'b' }),
    ).rejects.toMatchObject({ code: 'provider_not_configured' });
  });

  it('rechaza referencias mal formadas', async () => {
    const service = new SecretsService([fakeProvider('local')], 60);
    await expect(service.resolve('local/a')).rejects.toMatchObject({
      code: 'invalid_ref',
    });
  });

  describe('caché', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    it('sirve de la caché dentro del TTL y vuelve al proveedor al caducar', async () => {
      const local = fakeProvider('local', { 'a#f': 'v' });
      const service = new SecretsService([local], 30);
      await service.resolve('secret://local/a#f');
      await service.resolve('secret://local/a#f');
      expect(local.get).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(29_999);
      await service.resolve('secret://local/a#f');
      expect(local.get).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(1);
      await service.resolve('secret://local/a#f');
      expect(local.get).toHaveBeenCalledTimes(2);
    });

    it('fresh consulta al proveedor aunque esté en caché', async () => {
      const local = fakeProvider('local', { 'a#f': 'v' });
      const service = new SecretsService([local], 60);
      await service.resolve('secret://local/a#f');
      await service.resolve('secret://local/a#f', { fresh: true });
      expect(local.get).toHaveBeenCalledTimes(2);
    });

    it('TTL 0 desactiva la caché', async () => {
      const local = fakeProvider('local', { 'a#f': 'v' });
      const service = new SecretsService([local], 0);
      await service.resolve('secret://local/a#f');
      await service.resolve('secret://local/a#f');
      expect(local.get).toHaveBeenCalledTimes(2);
    });

    it('el TTL se limita a 300 s', async () => {
      const local = fakeProvider('local', { 'a#f': 'v' });
      const service = new SecretsService([local], 3600);
      await service.resolve('secret://local/a#f');
      vi.advanceTimersByTime(300_000);
      await service.resolve('secret://local/a#f');
      expect(local.get).toHaveBeenCalledTimes(2);
    });

    it('no cachea los fallos', async () => {
      const local = fakeProvider('local');
      const service = new SecretsService([local], 60);
      await expect(service.resolve('secret://local/a#f')).rejects.toThrow();
      await expect(service.resolve('secret://local/a#f')).rejects.toThrow();
      expect(local.get).toHaveBeenCalledTimes(2);
    });

    it('guardar invalida todos los campos de la ruta (y solo esos)', async () => {
      const local = fakeProvider('local', {
        'a#f': 'viejo',
        'a#g': 'viejo-g',
        'ab#f': 'otro',
      });
      const service = new SecretsService([local], 60);
      await service.resolve('secret://local/a#f');
      await service.resolve('secret://local/a#g');
      await service.resolve('secret://local/ab#f');
      expect(
        await service.store('secret://local/a', { f: 'nuevo', g: 'nuevo-g' }),
      ).toBe('secret://local/a');
      expect(await service.resolve('secret://local/a#f')).toBe('nuevo');
      expect(await service.resolve('secret://local/a#g')).toBe('nuevo-g');
      await service.resolve('secret://local/ab#f');
      expect(local.get).toHaveBeenCalledTimes(5);
    });

    it('borrar quita de la caché todos los campos de la ruta', async () => {
      const local = fakeProvider('local', { 'a#f': 'v', 'a#g': 'w' });
      const service = new SecretsService([local], 60);
      await service.resolve('secret://local/a#f');
      await service.resolve('secret://local/a#g');
      expect(await service.remove('secret://local/a')).toBe(true);
      await expect(service.resolve('secret://local/a#f')).rejects.toThrow();
      await expect(service.resolve('secret://local/a#g')).rejects.toThrow();
      expect(await service.remove('secret://local/a')).toBe(false);
    });

    it('si el borrado falla, la caché se invalida igualmente', async () => {
      const local = fakeProvider('local', { 'a#f': 'v' });
      const service = new SecretsService([local], 60);
      await service.resolve('secret://local/a#f');
      local.delete.mockRejectedValueOnce(new Error('BD caída'));
      await expect(service.remove('secret://local/a')).rejects.toThrow(
        'BD caída',
      );
      await service.resolve('secret://local/a#f');
      expect(local.get).toHaveBeenCalledTimes(2);
    });

    it('una lectura en curso durante un borrado no deja el valor en caché', async () => {
      const local = fakeProvider('local', { 'a#f': 'v' });
      let release!: () => void;
      local.get.mockImplementationOnce(
        () => new Promise((resolve) => (release = () => resolve('v'))),
      );
      const service = new SecretsService([local], 60);
      const inFlight = service.resolve('secret://local/a#f');
      await service.remove('secret://local/a');
      release();
      expect(await inFlight).toBe('v');
      // El valor leído antes del borrado no se cachea: la siguiente lectura va al proveedor.
      await expect(service.resolve('secret://local/a#f')).rejects.toThrow();
    });

    it('una lectura en curso durante un clearCache tampoco se cachea', async () => {
      const local = fakeProvider('local', { 'a#f': 'v' });
      let release!: () => void;
      local.get.mockImplementationOnce(
        () => new Promise((resolve) => (release = () => resolve('v'))),
      );
      const service = new SecretsService([local], 60);
      const inFlight = service.resolve('secret://local/a#f');
      service.clearCache();
      release();
      await inFlight;
      await service.resolve('secret://local/a#f');
      expect(local.get).toHaveBeenCalledTimes(2);
    });

    it('clearCache y onModuleDestroy vacían la caché', async () => {
      const local = fakeProvider('local', { 'a#f': 'v' });
      const service = new SecretsService([local], 60);
      await service.resolve('secret://local/a#f');
      service.onModuleDestroy();
      await service.resolve('secret://local/a#f');
      expect(local.get).toHaveBeenCalledTimes(2);
    });
  });

  it('store y remove exigen un proveedor con escritura y una referencia sin campo', async () => {
    const readOnly = fakeProvider(
      'vaultwarden',
      {},
      {
        set: undefined,
        delete: undefined,
      },
    );
    const service = new SecretsService([fakeProvider('local'), readOnly], 60);
    await expect(
      service.store('secret://vaultwarden/x', { a: 'b' }),
    ).rejects.toThrow(/solo lectura/);
    await expect(
      service.store('secret://local/x#a', { a: 'b' }),
    ).rejects.toThrow(/no lleva #campo/);
    await expect(service.remove('secret://vaultwarden/x')).rejects.toThrow(
      /no admite borrado/,
    );
    await expect(service.remove('secret://local/x#a')).rejects.toThrow(
      /no lleva #campo/,
    );
  });

  it('describe proveedores con salud y capacidades', async () => {
    const service = new SecretsService(
      [
        fakeProvider('local'),
        fakeProvider(
          'openbao',
          {},
          {
            signSshKey: async () => 'cert',
            sshCaPublicKeys: async () => [],
            healthCheck: async () => false,
          },
        ),
        fakeProvider(
          'vaultwarden',
          {},
          {
            set: undefined,
            healthCheck: async () => {
              throw new Error('caído');
            },
          },
        ),
      ],
      60,
    );
    expect(await service.describeProviders()).toEqual([
      { id: 'local', healthy: true, capabilities: ['write'] },
      {
        id: 'openbao',
        healthy: false,
        capabilities: ['write', 'ssh_certificates'],
      },
      { id: 'vaultwarden', healthy: false, capabilities: [] },
    ]);
  });

  it('sshCertificates: el primer proveedor con CA SSH, o ninguno', () => {
    const ca = fakeProvider(
      'openbao',
      {},
      { signSshKey: async () => 'cert', sshCaPublicKeys: async () => [] },
    );
    // Solo con signSshKey no basta: hacen falta las claves de la CA para el script de alta.
    const half = fakeProvider('otro', {}, { signSshKey: async () => 'cert' });
    expect(
      new SecretsService(
        [fakeProvider('local'), half, ca],
        60,
      ).sshCertificates(),
    ).toBe(ca);
    expect(
      new SecretsService([fakeProvider('local'), half], 60).sshCertificates(),
    ).toBeUndefined();
  });

  it('los valores en caché no salen al inspeccionar o serializar el servicio', async () => {
    const value = 'valor-centinela-en-cache';
    // Proveedor sin mocks (los vi.fn guardan los resultados) que guarda el valor en un cierre.
    const provider: SecretProvider = {
      id: 'local',
      get: async () => value,
      healthCheck: async () => true,
    };
    const service = new SecretsService([provider], 60);
    await service.resolve('secret://local/a#f');
    expect(inspect(service, { depth: 10, showHidden: true })).not.toContain(
      value,
    );
    expect(JSON.stringify(service)).not.toContain(value);
  });
});
