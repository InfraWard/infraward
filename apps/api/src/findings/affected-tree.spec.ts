import type { AffectedNode, AffectedPackage } from '@infraward/shared-types';
import {
  buildAffectedTree,
  exposedPorts,
  type AffectedTreeInput,
  type TreeAsset,
} from './affected-tree.js';

function asset(
  id: string,
  type: TreeAsset['type'],
  extra: Partial<TreeAsset> = {},
): TreeAsset {
  return { id, name: id, type, status: 'active', state: null, ports: null, ...extra };
}

function pkg(name: string, installed = '1.0'): AffectedPackage {
  return {
    findingId: `f-${name}-${installed}`,
    packageName: name,
    installedVersion: installed,
    fixedVersion: null,
    pkgPath: null,
    status: 'open',
    fixStatus: 'will_not_fix',
    priority: null,
    noiseReason: null,
  };
}

function input(
  assets: TreeAsset[],
  rest: Partial<Omit<AffectedTreeInput, 'assets'>>,
): AffectedTreeInput {
  return {
    assets: new Map(assets.map((a) => [a.id, a])),
    parents: new Map(),
    packages: new Map(),
    containers: new Map(),
    stores: new Map(),
    ...rest,
  };
}

/** Árbol como texto: `nombre[A acción]` por nivel (A = afectado, sin uso marcado). */
function render(nodes: AffectedNode[], depth = 0): string[] {
  return nodes.flatMap((n) => [
    `${'  '.repeat(depth)}${n.name}${n.affected ? ` [${n.action ?? 'afectado'}${n.unused ? ', sin uso' : ''}]` : ''}`,
    ...render(n.children, depth + 1),
  ]);
}

describe('buildAffectedTree', () => {
  it('nodo → CT → contenedor → imagen, con el servidor y el CT afectados por su cuenta', () => {
    const tree = buildAffectedTree(
      input(
        [
          asset('pve', 'server'),
          asset('ct-web', 'lxc', { state: 'running' }),
          asset('web1', 'container', { state: 'running' }),
          asset('web2', 'container', { state: 'exited' }),
          asset('nginx:1.25', 'image'),
          asset('otro', 'server'),
        ],
        {
          parents: new Map([
            ['ct-web', 'pve'],
            ['web1', 'ct-web'],
            ['web2', 'ct-web'],
          ]),
          packages: new Map([
            ['nginx:1.25', [pkg('zlib1g')]],
            ['ct-web', [pkg('zlib1g', '1.2')]],
            ['otro', [pkg('zlib1g', '1.3')]],
          ]),
          containers: new Map([['nginx:1.25', ['web1', 'web2']]]),
        },
      ),
    );
    expect(render(tree)).toEqual([
      'otro [update_package]',
      'pve',
      '  ct-web [update_package]',
      '    web1 [afectado]',
      '      nginx:1.25 [rebuild_image]',
      '    web2 [afectado]',
      '      nginx:1.25 [rebuild_image]',
    ]);
    const ct = tree[1]!.children[0]!;
    expect(ct.runtimeState).toBe('running');
    expect(ct.packages.map((p) => p.installedVersion)).toEqual(['1.2']);
    expect(ct.children[1]!.runtimeState).toBe('stopped');
    expect(ct.children[0]!.children[0]!.packages[0]!.fixStatus).toBe('will_not_fix');
  });

  it('una imagen sin contenedor activo cuelga del host que la guarda, marcada sin uso', () => {
    const tree = buildAffectedTree(
      input(
        [
          asset('pve', 'server'),
          asset('ct', 'lxc'),
          asset('redis:7.0', 'image'),
          asset('huerfana', 'image'),
        ],
        {
          parents: new Map([['ct', 'pve']]),
          packages: new Map([
            ['redis:7.0', [pkg('zlib1g')]],
            ['huerfana', [pkg('zlib1g')]],
          ]),
          stores: new Map([['redis:7.0', ['ct']]]),
        },
      ),
    );
    expect(render(tree)).toEqual([
      'huerfana [rebuild_image, sin uso]',
      'pve',
      '  ct',
      '    redis:7.0 [rebuild_image, sin uso]',
    ]);
  });

  it('una imagen con un contenedor parado (pero sin ninguno activo) sale bajo él y bajo el host', () => {
    const tree = buildAffectedTree(
      input(
        [
          asset('ct', 'lxc'),
          asset('c1', 'container', { status: 'missing', state: 'exited' }),
          asset('img', 'image'),
        ],
        {
          parents: new Map([['c1', 'ct']]),
          packages: new Map([['img', [pkg('a')]]]),
          containers: new Map([['img', ['c1']]]),
          stores: new Map([['img', ['ct']]]),
        },
      ),
    );
    // Los activos primero: la imagen (activa) antes que el contenedor desaparecido.
    expect(render(tree)).toEqual([
      'ct',
      '  img [rebuild_image, sin uso]',
      '  c1 [afectado]',
      '    img [rebuild_image]',
    ]);
  });

  it('corta un ciclo de contains y no inventa assets que no se leyeron (retirados)', () => {
    const tree = buildAffectedTree(
      input([asset('a', 'server'), asset('b', 'lxc')], {
        parents: new Map([
          ['a', 'b'],
          ['b', 'a'],
        ]),
        packages: new Map([
          ['a', [pkg('x')]],
          ['retirado', [pkg('x')]],
        ]),
      }),
    );
    expect(render(tree).length).toBeLessThanOrEqual(2);
    expect(render(tree).join()).not.toContain('retirado');
  });
});

describe('exposedPorts', () => {
  it('servidor: fuera de loopback, una fila por puerto y proceso, la más abierta', () => {
    expect(
      exposedPorts({
        type: 'server',
        ports: [
          { proto: 'tcp', address: '0.0.0.0', port: 22, process: 'sshd' },
          { proto: 'tcp', address: '::', port: 22, process: 'sshd' },
          { proto: 'tcp', address: '127.0.0.1', port: 5432, process: 'postgres' },
          { proto: 'tcp', address: '10.0.0.5', port: 8080, process: 'java' },
          { proto: 'udp', address: '::1', port: 53, process: null },
        ],
      }),
    ).toEqual([
      { port: 22, proto: 'tcp', address: '0.0.0.0', process: 'sshd' },
      { port: 8080, proto: 'tcp', address: '10.0.0.5', process: 'java' },
    ]);
  });

  it('contenedor: solo los publicados y no en loopback; sin IP = todas', () => {
    expect(
      exposedPorts({
        type: 'container',
        ports: [
          { containerPort: 80, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080 },
          { containerPort: 80, proto: 'tcp', hostIp: '::', hostPort: 8080 },
          { containerPort: 6379, proto: 'tcp', hostIp: null, hostPort: null },
          { containerPort: 9000, proto: 'tcp', hostIp: '127.0.0.1', hostPort: 9000 },
          { containerPort: 443, proto: 'tcp', hostIp: '', hostPort: 443 },
        ],
      }),
    ).toEqual([
      { port: 443, proto: 'tcp', address: '0.0.0.0', process: null },
      { port: 8080, proto: 'tcp', address: '0.0.0.0', process: null },
    ]);
  });

  it('facts sin puertos o con basura: nada', () => {
    expect(exposedPorts({ type: 'server', ports: null })).toEqual([]);
    expect(exposedPorts({ type: 'server', ports: [1, 'x', { port: '22' }] })).toEqual([]);
  });
});
