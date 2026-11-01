import { Asset, AssetRelation } from '@infraward/domain';
import type { DataSource } from 'typeorm';
import type { AssetRoute, AssetRoutes } from '../jobs/asset-routes.js';
import { PODMAN_ENABLE_SCRIPT } from '@infraward/shared-types';
import {
  DOCKER_SHELL_SCRIPT,
  InteractiveRoutes,
  PODMAN_SHELL_SCRIPT,
} from './interactive-routes.js';

const PIN = `SHA256:${'p'.repeat(43)}`;
const ID = 'c'.repeat(64);

function setup(assets: Record<string, Partial<Asset>>, parents: Record<string, string> = {}) {
  const repo = (entity: unknown) => ({
    findOneBy: (where: { id?: string; childId?: string }) =>
      Promise.resolve(
        entity === AssetRelation
          ? parents[where.childId!]
            ? { parentId: parents[where.childId!] }
            : null
          : (assets[where.id!] ?? null),
      ),
  });
  const node: AssetRoute = {
    connection: { host: '192.0.2.1', port: 22, user: 'inventory' },
    auth: 'ca_certificate',
    keyRef: null,
    pinned: PIN,
    host: { id: 'node', name: 'pve' },
  };
  const routes = {
    route: vi.fn((asset: Asset) =>
      Promise.resolve(
        asset.type === 'lxc' ? { ...node, via: { kind: 'pct', vmid: 101 } } : node,
      ),
    ),
  };
  return {
    routes,
    resolver: new InteractiveRoutes(
      { getRepository: repo } as unknown as DataSource,
      routes as unknown as AssetRoutes,
    ),
  };
}

describe('InteractiveRoutes', () => {
  it('servidor: SSH directo con la cuenta de administración y la shell de login', async () => {
    const { resolver } = setup({ s: { id: 's', type: 'server' } });
    const route = await resolver.resolve('s', 'infraward-admin');
    expect(route).toMatchObject({
      connection: { host: '192.0.2.1', user: 'infraward-admin' },
      pinned: PIN,
      command: null,
      hops: [],
    });
  });

  it('CT: sudo -n pct enter <vmid> en el nodo', async () => {
    const { resolver } = setup({ ct: { id: 'ct', type: 'lxc' } });
    expect((await resolver.resolve('ct', 'infraward-admin')).command).toEqual([
      'sudo', '-n', 'pct', 'enter', '101',
    ]);
  });

  it('contenedor en un servidor y en un CT: docker exec -it con la shell detectada, id como argumento', async () => {
    const { resolver } = setup(
      {
        c1: { id: 'c1', type: 'container', facts: { docker: { id: ID } } as never },
        c2: { id: 'c2', type: 'container', facts: { docker: { id: ID } } as never },
        srv: { id: 'srv', type: 'server' },
        ct: { id: 'ct', type: 'lxc' },
      },
      { c1: 'srv', c2: 'ct' },
    );
    expect((await resolver.resolve('c1', 'infraward-admin')).command).toEqual([
      'sudo', '-n', 'sh', '-c', DOCKER_SHELL_SCRIPT, 'sh', ID,
    ]);
    const nested = await resolver.resolve('c2', 'infraward-admin');
    expect(nested.command).toEqual([
      'sudo', '-n', 'pct', 'exec', '101', '--', 'sh', '-c', DOCKER_SHELL_SCRIPT, 'sh', ID,
    ]);
    expect(nested.hops).toEqual([
      { kind: 'pct', vmid: 101 },
      { kind: 'docker', containerId: ID },
    ]);
    // El script nunca lleva el id dentro: llega como $1.
    expect(DOCKER_SHELL_SCRIPT).not.toContain(ID);
    expect(DOCKER_SHELL_SCRIPT).toContain('exec docker exec -it "$id" /bin/bash');
    expect(DOCKER_SHELL_SCRIPT).toContain('El contenedor no tiene shell (sh ni bash)');
  });

  it('contenedor de Podman (root): podman exec -it; los rootless, no', async () => {
    const { resolver } = setup(
      {
        p: { id: 'p', type: 'container', facts: { docker: { id: ID, engine: 'podman' } } as never },
        r: {
          id: 'r',
          type: 'container',
          facts: { docker: { id: ID, engine: 'podman', rootlessUser: 'alice', rootlessUid: 1000 } } as never,
        },
        srv: { id: 'srv', type: 'server' },
      },
      { p: 'srv', r: 'srv' },
    );
    const route = await resolver.resolve('p', 'infraward-admin');
    expect(route.command).toEqual(['sudo', '-n', 'sh', '-c', PODMAN_SHELL_SCRIPT, 'sh', ID]);
    expect(route.hops).toEqual([{ kind: 'podman', containerId: ID }]);
    expect(PODMAN_SHELL_SCRIPT).toBe(DOCKER_SHELL_SCRIPT.replaceAll('docker ', 'podman '));
    expect(PODMAN_SHELL_SCRIPT).not.toMatch(/docker/);
    await expect(resolver.resolve('r', 'infraward-admin')).rejects.toThrow('Podman rootless');
  });

  it('rechaza inventory y root, ids de contenedor raros, tipos sin terminal y nodos sin CA o sin huella', async () => {
    const { resolver, routes } = setup({
      s: { id: 's', type: 'server' },
      bad: { id: 'bad', type: 'container', facts: { docker: { id: 'abc; rm -rf /' } } as never },
      d: { id: 'd', type: 'domain' },
    });
    await expect(resolver.resolve('s', 'inventory')).rejects.toThrow('Cuenta');
    await expect(resolver.resolve('s', 'root')).rejects.toThrow('Cuenta');
    await expect(resolver.resolve('bad', 'infraward-admin')).rejects.toThrow('id de Docker');
    await expect(resolver.resolve('d', 'infraward-admin')).rejects.toThrow('servidores, CT');
    routes.route.mockResolvedValueOnce({
      connection: { host: 'h', port: 22, user: 'inventory' },
      auth: 'static_key',
      keyRef: 'secret://x',
      pinned: PIN,
      host: { id: 's', name: 'srv' },
    });
    await expect(resolver.resolve('s', 'infraward-admin')).rejects.toThrow('modo CA');
    routes.route.mockResolvedValueOnce({
      connection: { host: 'h', port: 22, user: 'inventory' },
      auth: 'ca_certificate',
      keyRef: null,
      pinned: null,
      host: { id: 's', name: 'srv' },
    });
    await expect(resolver.resolve('s', 'infraward-admin')).rejects.toThrow('host key fijada');
  });

  it('acción «Habilitar Podman»: comando fijo de solo lectura con los usuarios como argumentos', async () => {
    const { resolver } = setup({
      s: { id: 's', type: 'server' },
      ct: { id: 'ct', type: 'lxc' },
      c: { id: 'c', type: 'container', facts: { docker: { id: ID } } as never },
    });
    const action = { kind: 'podman-enable' as const, users: ['alice', 'bob'] };
    const server = await resolver.resolve('s', 'infraward-admin', action);
    expect(server).toMatchObject({ readOnly: true, hops: [] });
    expect(server.command).toEqual([
      'sudo', '-n', 'sh', '-c', PODMAN_ENABLE_SCRIPT, 'sh', 'alice', 'bob',
    ]);
    expect((await resolver.resolve('ct', 'infraward-admin', action)).command).toEqual([
      'sudo', '-n', 'pct', 'exec', '101', '--', 'sh', '-c', PODMAN_ENABLE_SCRIPT, 'sh', 'alice', 'bob',
    ]);
    expect((await resolver.resolve('s', 'infraward-admin')).readOnly).toBe(false);
    await expect(resolver.resolve('c', 'infraward-admin', action)).rejects.toThrow('servidores y CT');
    await expect(
      resolver.resolve('s', 'infraward-admin', { kind: 'podman-enable', users: ['a;id'] }),
    ).rejects.toThrow('Acción no válida');
    await expect(
      resolver.resolve('s', 'infraward-admin', { kind: 'otra', users: ['alice'] } as never),
    ).rejects.toThrow('Acción no válida');
  });
});
