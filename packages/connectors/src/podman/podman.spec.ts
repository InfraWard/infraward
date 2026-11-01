import type {
  DockerContainerFacts,
  DockerNetworkFacts,
  DockerVolumeFacts,
} from '@infraward/shared-types';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DiscoveryError,
  type HostCommandResult,
  type HostExec,
  type PrivilegedQuery,
} from '../index.js';
import { createDiscoverers } from '../index.js';
import {
  CONTAINER_FORMAT,
  IMAGE_FORMAT,
  NETWORK_FORMAT,
  parseContainer,
  parseNetwork,
  parseVolume,
  VOLUME_FORMAT,
} from '../docker/docker.js';
import {
  expandQuery,
  isSudoDenial,
  PODMAN_AS_USER_SCRIPT,
  validateQuery,
} from '../privileged.js';
import {
  parsePodmanUsers,
  PODMAN_CONTAINER_FORMAT,
  PODMAN_IMAGE_FORMAT,
  PODMAN_NETWORK_FORMAT,
  PODMAN_USERS_SCRIPT,
  PODMAN_VOLUME_FORMAT,
  PodmanDiscoverer,
  podmanNaturalKey,
  podmanNetworkKey,
  podmanRootlessWarnings,
  podmanVolumeKey,
} from './podman.js';

// Salidas reales de Podman 5.4.2 (Debian 13) por el ayudante de root: rootful (contenedor con
// volumen, bind de solo lectura, red propia y etiquetas de compose y Traefik; otro en la red por
// defecto `podman`; uno creado y nunca arrancado; un pod con su contenedor «infra») y un usuario
// rootless por su socket (contenedor con la unidad de systemd de Quadlet y un volumen).
const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
const docker = (name: string) =>
  readFileSync(new URL(`../docker/fixtures/docker26/${name}`, import.meta.url), 'utf8');
const PARENT = { id: 'host-1', name: 'rocky', facts: {} };
const NOW = new Date('2026-10-31T12:00:00Z');
const ALICE = 'P 1000 1 1 1 1 1 alice\n';

type Reply = HostCommandResult | string;
const ok = (stdout: string): HostCommandResult => ({ code: 0, stdout, stderr: '' });
const fail = (code: number, stderr: string): HostCommandResult => ({ code, stdout: '', stderr });

/** Respuestas por ámbito (`root` o uid) y subcomando; lo que no se da, sale de los fixtures. */
function host(
  over: { users?: Reply; byScope?: Record<string, Partial<Record<string, Reply>>> } = {},
) {
  const calls: { query: string; args: string[]; argv: string[] }[] = [];
  const base = (scope: string, sub: string): Reply => {
    const p = scope === 'root' ? '' : 'rootless-';
    const files: Record<string, string> = {
      ps: 'ps.txt',
      inspect: 'inspect.jsonl',
      images: 'images.txt',
      imageInspect: 'image-inspect.jsonl',
      volumes: 'volume-ls.txt',
      volumeInspect: 'volume-inspect.jsonl',
      networks: 'network-ls.txt',
      networkInspect: 'network-inspect.jsonl',
    };
    if (sub === 'pods') return scope === 'root' ? fixture('pods.jsonl') : '';
    if (sub === 'nginx') return '';
    return fixture(`${p}${files[sub]}`);
  };
  const subOf: Record<string, string> = {
    'podman-ps': 'ps',
    'podman-inspect-containers': 'inspect',
    'podman-images': 'images',
    'podman-image-inspect': 'imageInspect',
    'podman-volumes': 'volumes',
    'podman-volume-inspect': 'volumeInspect',
    'podman-networks': 'networks',
    'podman-network-inspect': 'networkInspect',
    'podman-pods': 'pods',
    'podman-nginx-routes': 'nginx',
  };
  const exec: HostExec = {
    run: () => Promise.reject(new Error('solo por el ayudante')),
    query: (q: PrivilegedQuery) => {
      const argv = expandQuery(q);
      calls.push({ query: q.name, args: [...(q.args ?? [])], argv });
      if (q.name === 'podman-users')
        return Promise.resolve(
          typeof over.users === 'object' ? over.users : ok(over.users ?? ''),
        );
      const [scope, ...rest] = q.args ?? [];
      const sub = subOf[q.name];
      if (!sub) throw new Error(`consulta inesperada: ${q.name}`);
      const r = over.byScope?.[scope]?.[sub] ?? base(scope, sub);
      if (typeof r !== 'string') return Promise.resolve(r);
      // Como Podman: de un inspect, solo lo pedido.
      if (sub === 'imageInspect' || sub === 'inspect')
        return Promise.resolve(
          ok(
            r
              .split('\n')
              .filter((l) => l && rest.includes((JSON.parse(l) as { id: string }).id))
              .join('\n'),
          ),
        );
      return Promise.resolve(ok(r));
    },
  };
  return { exec, calls };
}

const discoverer = new PodmanDiscoverer(() => NOW);
const factsOf = <T>(c: { facts: Record<string, unknown> }) => c.facts.docker as T;

describe('plantillas de Podman', () => {
  const keys = (format: string) =>
    [...format.matchAll(/"([A-Za-z]+)":/g)].map((m) => m[1]).sort();

  it('dan las mismas claves que las de Docker (más el pod, el «infra» y la unidad de systemd)', () => {
    expect(keys(PODMAN_CONTAINER_FORMAT)).toEqual(
      [...keys(CONTAINER_FORMAT), 'pod', 'infra', 'systemdUnit'].sort(),
    );
    expect(keys(PODMAN_IMAGE_FORMAT)).toEqual(keys(IMAGE_FORMAT));
    expect(keys(PODMAN_VOLUME_FORMAT)).toEqual(keys(VOLUME_FORMAT));
    expect(keys(PODMAN_NETWORK_FORMAT)).toEqual(keys(NETWORK_FORMAT));
  });

  it('las salidas reales se leen igual que las de Docker', () => {
    const lines = (s: string) => s.trim().split('\n');
    for (const l of lines(fixture('inspect.jsonl'))) expect(parseContainer(l), l).not.toBeNull();
    for (const l of lines(fixture('volume-inspect.jsonl'))) expect(parseVolume(l)).not.toBeNull();
    for (const l of lines(fixture('network-inspect.jsonl')))
      expect(parseNetwork(l), l).not.toBeNull();
    // Mismas claves JSON que Docker 26 en redes y volúmenes.
    const objKeys = (l: string) => Object.keys(JSON.parse(l) as object).sort();
    expect(objKeys(lines(fixture('network-inspect.jsonl'))[0])).toEqual(
      objKeys(lines(docker('network-inspect.jsonl'))[0]),
    );
    expect(objKeys(lines(fixture('volume-inspect.jsonl'))[0])).toEqual(
      objKeys(lines(docker('volume-inspect.jsonl'))[0]),
    );
  });

  it('no sacan del servidor ni el entorno ni las etiquetas fuera de la lista blanca', () => {
    // El contenedor `web` se creó con -e SECRET=hunter2 y -l secret.label=x.
    const all = fixture('inspect.jsonl');
    expect(all).not.toMatch(/hunter2|secret\.label|maintainer/);
    expect(PODMAN_CONTAINER_FORMAT).not.toMatch(/\.Env\b|json \.Config\.Labels\}/);
  });
});

describe('consultas de Podman del ayudante', () => {
  it('como root, el CLI; de un usuario, el CLI remoto contra su socket y como ese usuario', () => {
    expect(expandQuery({ name: 'podman-ps', args: ['root'] })).toEqual([
      'podman', 'ps', '-a', '-q', '--no-trunc',
    ]);
    expect(expandQuery({ name: 'podman-ps', args: ['1000'] })).toEqual([
      'sh', '-c', PODMAN_AS_USER_SCRIPT, 'sh', '1000',
      'env', 'XDG_RUNTIME_DIR=/run/user/1000',
      'podman', '--remote', '--url', 'unix:///run/user/1000/podman/podman.sock',
      'ps', '-a', '-q', '--no-trunc',
    ]);
    // El cliente nunca corre como root contra un socket que controla el usuario.
    expect(PODMAN_AS_USER_SCRIPT).toContain('exec runuser -u "$u" -- "$@"');
    const id = `sha256:${'b'.repeat(64)}`;
    expect(expandQuery({ name: 'podman-save', args: ['root', id] })).toEqual([
      'podman', 'save', '--format', 'docker-archive', id,
    ]);
    expect(expandQuery({ name: 'podman-users' })).toEqual([
      'sh', '-c', PODMAN_USERS_SCRIPT, 'sh',
    ]);
  });

  it.each([
    ['sin ámbito', 'podman-ps', []],
    ['uid 0', 'podman-ps', ['0']],
    ['ruta de socket como ámbito', 'podman-ps', ['unix:///run/podman/podman.sock']],
    ['opción tras el ámbito', 'podman-ps', ['root', '--url', 'x']],
    ['save con -o', 'podman-save', ['root', '-o', '/etc/passwd']],
    ['inspect sin ids', 'podman-inspect-containers', ['root']],
    ['inspect con opción', 'podman-inspect-containers', ['root', '--format', '{{.Config.Env}}']],
  ] as const)('rechaza %s', (_name, query, args) => {
    expect(() => validateQuery({ name: query, args: [...args] })).toThrow();
  });

  it('el script de usuarios se puede pasar a Ansible sin que lo interprete Jinja', () => {
    expect(PODMAN_USERS_SCRIPT).not.toMatch(/\{\{|\{%|\{#|\$\{/);
  });
});

describe('PodmanDiscoverer', () => {
  it('rootful: contenedores (sin el «infra» del pod), volúmenes, redes e imágenes', async () => {
    const listing = await discoverer.discover(PARENT, host().exec);
    expect(listing.warnings).toEqual([]);
    expect(listing.complete).toBe(true);
    const containers = listing.children.filter((c) => c.type === 'container');
    expect(containers.map((c) => c.name)).toEqual(['web', 'plain', 'parado', 'enpod']);
    const web = containers[0];
    expect(web.naturalKey).toBe(podmanNaturalKey('host-1', 'root', 'web'));
    expect(factsOf<DockerContainerFacts>(web)).toMatchObject({
      engine: 'podman',
      name: 'web',
      image: 'docker.io/library/nginx:alpine',
      imageId: 'sha256:3d6cab9c2941df2441024a2f02a65ebe1b8916c3cbe7b9527f62627accea8004',
      repoTags: ['docker.io/library/nginx:alpine'],
      platform: 'linux/amd64',
      state: 'running',
      composeProject: 'demo',
      composeService: 'web',
      ports: [{ containerPort: 80, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080 }],
      proxyRoutes: [expect.objectContaining({ hosts: ['w.example.com'] })],
      mounts: [
        { type: 'volume', name: 'datos', source: null, destination: '/data', readOnly: false },
        { type: 'bind', name: null, source: '/tmp/iwbind', destination: '/srv', readOnly: true },
      ],
      networks: [{ name: 'red-app', ipv4: '10.89.0.2', ipv6: null, aliases: ['webalias', '4e5331f7b45d'] }],
      // nginx en marcha: `podman exec <id> nginx -T` filtrado (aquí, vacío).
      proxy: { source: 'nginx', routes: [], readAt: NOW.toISOString() },
    });
    expect(factsOf<DockerContainerFacts>(web).rootlessUser).toBeUndefined();
    // Nunca arrancado: sin fecha de inicio y con los puertos configurados.
    expect(factsOf<DockerContainerFacts>(containers[2])).toMatchObject({
      state: 'created',
      startedAt: null,
      ports: [{ containerPort: 90, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 9090 }],
    });
    // Del pod: su nombre; el «infra» no está pero el listado sigue completo.
    expect(factsOf<DockerContainerFacts>(containers[3]).pod).toBe('mipod');
    expect(listing.children.filter((c) => c.type === 'volume').map((c) => c.name)).toEqual(['datos']);
    expect(listing.children.filter((c) => c.type === 'network').map((c) => c.name)).toEqual([
      'podman', 'red-app', 'red6',
    ]);
    const red = listing.children.find((c) => c.name === 'red6')!;
    expect(factsOf<DockerNetworkFacts>(red)).toMatchObject({
      engine: 'podman',
      driver: 'bridge',
      scope: 'local',
      internal: true,
      subnets: [
        { subnet: '10.89.1.0/24', gateway: '10.89.1.1' },
        { subnet: 'fd12:44d3:7081:624a::/64', gateway: 'fd12:44d3:7081:624a::1' },
      ],
    });
    // Imágenes del host, también la de pausa de los pods.
    expect(listing.hostImages?.complete).toBe(true);
    expect(listing.hostImages?.images.map((i) => i.imageId)).toHaveLength(3);
  });

  it('la red por defecto se llama `podman` en el contenedor y en el listado: `attached_to` se resuelve', async () => {
    const listing = await discoverer.discover(PARENT, host().exec);
    const plain = podmanNaturalKey('host-1', 'root', 'plain');
    expect(listing.links).toEqual(
      expect.arrayContaining([
        {
          type: 'attached_to',
          from: { type: 'container', naturalKey: plain },
          to: { type: 'network', naturalKey: podmanNetworkKey('host-1', 'root', 'podman') },
        },
        {
          type: 'mounts',
          from: { type: 'container', naturalKey: podmanNaturalKey('host-1', 'root', 'web') },
          to: { type: 'volume', naturalKey: podmanVolumeKey('host-1', 'root', 'datos') },
        },
      ]),
    );
    expect(listing.links?.filter((l) => l.type === 'attached_to')).toHaveLength(4);
  });

  it('rootless: los de cada usuario de la lista por su socket, con su usuario', async () => {
    const { exec, calls } = host({ users: ALICE });
    const listing = await discoverer.discover(PARENT, exec);
    expect(listing.warnings).toEqual([]);
    expect(listing.complete).toBe(true);
    const uweb = listing.children.find((c) => c.name === 'alice/uweb')!;
    expect(uweb.naturalKey).toBe(podmanNaturalKey('host-1', 'alice', 'uweb'));
    expect(factsOf<DockerContainerFacts>(uweb)).toMatchObject({
      engine: 'podman',
      rootlessUser: 'alice',
      rootlessUid: 1000,
      name: 'uweb',
      systemdUnit: 'uweb.service',
      networks: [],
    });
    const vol = listing.children.find((c) => c.name === 'alice/udatos')!;
    expect(vol.naturalKey).toBe(podmanVolumeKey('host-1', 'alice', 'udatos'));
    expect(factsOf<DockerVolumeFacts>(vol)).toMatchObject({ rootlessUser: 'alice', name: 'udatos' });
    expect(listing.links).toContainEqual({
      type: 'mounts',
      from: { type: 'container', naturalKey: uweb.naturalKey },
      to: { type: 'volume', naturalKey: vol.naturalKey },
    });
    // La red `podman` del usuario es otro asset que la de root.
    expect(
      listing.children.filter((c) => c.type === 'network' && c.name.endsWith('podman')).map((c) => c.naturalKey),
    ).toEqual([
      podmanNetworkKey('host-1', 'root', 'podman'),
      podmanNetworkKey('host-1', 'alice', 'podman'),
    ]);
    // Imágenes de root y del usuario juntas, sin repetir.
    expect(listing.hostImages?.images).toHaveLength(3);
    // Del usuario, todo por su uid (el ayudante lo resuelve a su socket).
    const scoped = calls.filter((c) => c.query !== 'podman-users');
    expect(new Set(scoped.map((c) => c.args[0]))).toEqual(new Set(['root', '1000']));
    for (const c of scoped.filter((c) => c.args[0] === '1000'))
      expect(c.argv.slice(0, 11)).toEqual([
        'sh', '-c', PODMAN_AS_USER_SCRIPT, 'sh', '1000',
        'env', 'XDG_RUNTIME_DIR=/run/user/1000',
        'podman', '--remote', '--url', 'unix:///run/user/1000/podman/podman.sock',
      ]);
  });

  it('un usuario sin socket: aviso y listado incompleto (nada suyo pasa a missing)', async () => {
    const { exec, calls } = host({ users: 'P 1000 1 0 1 0 0 alice\n' });
    const listing = await discoverer.discover(PARENT, exec);
    expect(listing.complete).toBe(false);
    expect(listing.warnings).toEqual([expect.stringContaining('Podman rootless de alice: sin socket activo')]);
    expect(calls.some((c) => c.args[0] === '1000')).toBe(false);
    expect(listing.hostImages?.complete).toBe(false);
  });

  it('un usuario cuyo Podman falla: aviso e incompleto; lo de root sigue', async () => {
    const listing = await discoverer.discover(
      PARENT,
      host({
        users: ALICE,
        byScope: { '1000': { ps: fail(125, 'Error: unable to connect to Podman socket') } },
      }).exec,
    );
    expect(listing.complete).toBe(false);
    expect(listing.warnings).toEqual([
      'No se pudo listar Podman de alice: podman (alice) ps falló (código 125): Error: unable to connect to Podman socket',
    ]);
    expect(listing.children.some((c) => c.name === 'web')).toBe(true);
  });

  it('sin `podman ps` como root (sudoers anterior a la v8): falla el descubridor', async () => {
    const denied = fail(64, 'infraward-query: rechazado: consulta desconocida');
    expect(isSudoDenial(denied.stderr, denied.code)).toBe(true);
    await expect(
      discoverer.discover(PARENT, host({ byScope: { root: { ps: denied, pods: denied } } }).exec),
    ).rejects.toThrow(DiscoveryError);
  });

  it('sin la lista de usuarios: lo de root, pero incompleto', async () => {
    const listing = await discoverer.discover(
      PARENT,
      host({ users: fail(1, 'algo raro') }).exec,
    );
    expect(listing.complete).toBe(false);
    expect(listing.warnings).toEqual([
      'no se pudo leer la lista de usuarios de Podman (código 1): algo raro',
    ]);
  });

  it('está entre los descubridores, con el rol podman-host', () => {
    expect(createDiscoverers().get('podman-host')).toBeInstanceOf(PodmanDiscoverer);
  });
});

describe('usuarios de Podman rootless', () => {
  it('lee los detectados (habilitados o no) y deja aparte los habilitados con nombre', () => {
    const parsed = parsePodmanUsers(
      [
        'P 1000 1 1 1 1 2 alice',
        'P 1001 1 0 1 0 0 bob',
        'P 1002 0 0 1 0 1 carol',
        'P 1003 0 0 0 0 1 ?',
        'P 1000 0 0 0 0 9 repetido',
        'basura',
        'P 0 1 1 1 1 1 root',
        'P 1004 2 0 0 0 0 malo',
        'P 1005 0 0 0 0 0 dave extra',
        'U 1000 alice 1',
      ].join('\n'),
    );
    expect(parsed.detected).toEqual([
      { uid: 1000, name: 'alice', enabled: true, socket: true, storage: true, linger: true, containers: 2 },
      { uid: 1001, name: 'bob', enabled: true, socket: false, storage: true, linger: false, containers: 0 },
      { uid: 1002, name: 'carol', enabled: false, socket: false, storage: true, linger: false, containers: 1 },
      { uid: 1003, name: null, enabled: false, socket: false, storage: false, linger: false, containers: 1 },
    ]);
    expect(parsed.users).toEqual([
      { uid: 1000, name: 'alice', socket: true },
      { uid: 1001, name: 'bob', socket: false },
    ]);
  });

  it('avisa de los contenedores rootless sin habilitar y de los habilitados sin socket', () => {
    expect(
      podmanRootlessWarnings(
        parsePodmanUsers(
          'P 1000 1 1 1 1 2 alice\nP 1001 1 0 1 0 0 bob\nP 1002 0 0 1 0 3 carol\nP 1003 0 0 0 0 1 ?\nP 1004 0 1 1 1 0 dave\n',
        ),
      ),
    ).toEqual([
      'Podman rootless de bob: sin socket activo, sus contenedores no se ven (vuelve a habilitarlo desde la ficha)',
      '3 contenedores de Podman rootless de carol sin inventariar: habilítalo desde la ficha («Usuarios de Podman»)',
      '1 contenedor de Podman rootless de uid 1003 sin inventariar: habilítalo desde la ficha («Usuarios de Podman»)',
    ]);
  });

  it('el script de detección no usa `${`, plantillas de Jinja ni comillas simples en el awk final', () => {
    expect(PODMAN_USERS_SCRIPT).not.toMatch(/\{\{|\{%|\{#|\$\{/);
    expect(PODMAN_USERS_SCRIPT).toContain('head -n 200');
  });
});
