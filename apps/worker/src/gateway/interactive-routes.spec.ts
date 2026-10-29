import { Asset, AssetRelation } from '@infraward/domain';
import type { DataSource } from 'typeorm';
import type { AssetRoute, AssetRoutes } from '../jobs/asset-routes.js';
import { DOCKER_SHELL_SCRIPT, InteractiveRoutes } from './interactive-routes.js';

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
});
