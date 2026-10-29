import type { DockerContainerFacts } from '@infraward/shared-types';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DiscoveryError,
  type HostCommandResult,
  type HostExec,
} from '../discoverer.js';
import { createDiscoverers } from '../index.js';
import { expandQuery } from '../privileged.js';
import {
  CONTAINER_FORMAT,
  DockerDiscoverer,
  dockerNaturalKey,
  dockerNetworkKey,
  dockerVolumeKey,
  IMAGE_FORMAT,
  NETWORK_FORMAT,
  VOLUME_FORMAT,
} from './docker.js';

// Salidas reales de Docker 29.9 en un CT Debian 13 (almacén de imágenes de containerd).
const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
const INSPECT = fixture('inspect.jsonl');
const IDS = INSPECT.trim()
  .split('\n')
  .map((l) => (JSON.parse(l) as { id: string }).id);
const PARENT = { id: 'ct-100', name: 'pruebas', facts: {} };
const NOW = new Date('2026-10-10T12:00:00Z');

type Reply = HostCommandResult | string;

interface Replies {
  ps?: Reply;
  inspect?: Reply;
  images?: Reply;
  imagesLs?: Reply;
  volumeLs?: Reply;
  volumeInspect?: Reply;
  networkLs?: Reply;
  networkInspect?: Reply;
  /** `docker exec <id> nginx -T` ya filtrado (v5). */
  nginx?: Reply;
}

const IMAGE_IDS = fixture('image-inspect.jsonl')
  .trim()
  .split('\n')
  .map((l) => (JSON.parse(l) as { id: string }).id);

/** Host simulado: cada subcomando de Docker responde con su fixture (Docker 29 por defecto). */
function host(replies: Replies = {}) {
  const calls: { argv: string[]; sudo?: boolean; query?: string }[] = [];
  const reply = (r: Reply): HostCommandResult =>
    typeof r === 'string' ? { code: 0, stdout: r, stderr: '' } : r;
  const route = (argv: string[]): Reply => {
    if (argv[0] === 'sh') return replies.nginx ?? '';
    const [, sub, second] = argv;
    if (sub === 'ps') return replies.ps ?? IDS.join('\n') + '\n';
    if (sub === 'images') return replies.imagesLs ?? IMAGE_IDS.join('\n') + '\n';
    if (sub === 'image') {
      const r = replies.images ?? fixture('image-inspect.jsonl');
      // Como Docker: solo las imágenes pedidas.
      if (typeof r !== 'string') return r;
      return r
        .split('\n')
        .filter((l) => l && argv.includes((JSON.parse(l) as { id: string }).id))
        .join('\n');
    }
    if (sub === 'volume') return replies.volumeLs ?? '';
    if (sub === 'network') return replies.networkLs ?? '';
    if (sub === 'inspect' && second === '--type')
      return argv[3] === 'volume'
        ? (replies.volumeInspect ?? '')
        : (replies.networkInspect ?? '');
    if (sub === 'inspect') return replies.inspect ?? INSPECT;
    throw new Error(`comando inesperado: ${argv.join(' ')}`);
  };
  const exec: HostExec = {
    run: (argv) => {
      calls.push({ argv });
      return Promise.resolve(reply(route(argv)));
    },
    // Por el ayudante: se anota el comando real que ejecutaría como root.
    query: (q) => {
      const argv = expandQuery(q);
      calls.push({ argv, sudo: true, query: q.name });
      return Promise.resolve(reply(route(argv)));
    },
  };
  return { exec, calls };
}

const discoverer = new DockerDiscoverer(() => NOW);
const dockerOf = (facts: Record<string, unknown>) =>
  facts.docker as DockerContainerFacts;


describe('DockerDiscoverer', () => {
  it('lista contenedores en marcha y parados con imagen, estado y puertos', async () => {
    const listing = await discoverer.discover(PARENT, host().exec);
    expect(listing.complete).toBe(true);
    expect(listing.warnings).toEqual([]);
    expect(listing.children.map((c) => c.name)).toEqual([
      'local1',
      'cache',
      'web2',
      'web1',
    ]);
    const web1 = listing.children[3];
    expect(web1).toMatchObject({
      type: 'container',
      naturalKey: 'docker:ct-100:web1',
      aliases: [],
      collect: false,
    });
    expect(dockerOf(web1.facts)).toEqual({
      id: IDS[3],
      name: 'web1',
      image: 'nginx:1.25',
      imageId:
        'sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c',
      repoDigests: [
        'nginx@sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c',
      ],
      repoTags: ['nginx:1.25'],
      platform: 'linux/amd64',
      imageSizeBytes: 273144874,
      state: 'running',
      ports: [
        { containerPort: 80, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080 },
        { containerPort: 80, proto: 'tcp', hostIp: '::', hostPort: 8080 },
      ],
      composeProject: null,
      composeService: null,
      createdAt: '2026-10-09T22:11:05.376Z',
      startedAt: '2026-10-09T22:11:05.474Z',
      // Fixture anterior a la sesión 14 (sin montajes ni redes en la plantilla).
      mounts: [],
      networks: [],
      // Imagen de nginx en marcha: su configuración, filtrada en el servidor (aquí, vacía).
      proxy: { source: 'nginx', routes: [], readAt: NOW.toISOString() },
      discoveredAt: NOW.toISOString(),
    });
    // Expuesto sin publicar; parado y nunca arrancado.
    expect(dockerOf(listing.children[2].facts).ports).toEqual([
      { containerPort: 80, proto: 'tcp', hostIp: null, hostPort: null },
    ]);
    const cache = dockerOf(listing.children[1].facts);
    expect(cache.state).toBe('created');
    expect(cache.startedAt).toBeNull();
    expect([...listing.seen].sort()).toEqual(
      ['cache', 'local1', 'web1', 'web2']
        .map((n) => `container|${dockerNaturalKey('ct-100', n)}`)
        .sort(),
    );
  });

  it('un contenedor parado usa los puertos configurados', async () => {
    const stopped = JSON.stringify({
      ...(JSON.parse(INSPECT.split('\n')[3]) as object),
      state: 'exited',
      ports: {},
    });
    const listing = await discoverer.discover(
      PARENT,
      host({ ps: IDS[3], inspect: stopped }).exec,
    );
    expect(dockerOf(listing.children[0].facts).ports).toEqual([
      { containerPort: 80, proto: 'tcp', hostIp: '0.0.0.0', hostPort: 8080 },
    ]);
  });

  it('solo lanza subcomandos de lectura del sudoers, con sudo, y una vez cada imagen', async () => {
    const { exec, calls } = host();
    await discoverer.discover(PARENT, exec);
    expect(calls.every((c) => c.sudo === true)).toBe(true);
    // v5: `docker exec <id> nginx -T` (filtrado en el servidor) de cada nginx en marcha.
    const nginx = calls.filter((c) => c.query === 'docker-nginx-routes');
    expect(nginx.length).toBeGreaterThan(0);
    for (const c of nginx) {
      expect(c.argv.slice(0, 2)).toEqual(['sh', '-c']);
      expect(c.argv.slice(4)).toEqual([
        'docker',
        'exec',
        expect.stringMatching(/^[0-9a-f]{64}$/),
        'nginx',
        '-T',
      ]);
    }
    calls.splice(0, calls.length, ...calls.filter((c) => c.argv[0] !== 'sh'));
    expect(calls.map((c) => c.argv.slice(0, 3))).toEqual([
      ['docker', 'ps', '-a'],
      ['docker', 'inspect', '--format'],
      ['docker', 'images', '-q'],
      ['docker', 'image', 'inspect'],
      ['docker', 'volume', 'ls'],
      ['docker', 'network', 'ls'],
    ]);
    expect(calls[1].argv).toEqual([
      'docker',
      'inspect',
      '--format',
      CONTAINER_FORMAT,
      ...IDS,
    ]);
    expect(calls[2].argv).toEqual(['docker', 'images', '-q', '--no-trunc']);
    expect(calls[3].argv[4]).toBe(IMAGE_FORMAT);
    // nginx:1.25 en dos contenedores ⇒ una sola vez.
    expect(calls[3].argv.slice(5)).toHaveLength(3);
    // Exactamente los argumentos fijos de las consultas del ayudante.
    expect(calls[4].argv).toEqual(['docker', 'volume', 'ls', '-q']);
    expect(calls[5].argv).toEqual([
      'docker',
      'network',
      'ls',
      '--format',
      '{{.Name}}',
    ]);
  });

  it('las plantillas nunca piden el entorno, las etiquetas ni las opciones de drivers', () => {
    // Las etiquetas solo se recorren en `proxyLabels`, que emite únicamente las de su lista
    // blanca: cada par sale detrás de una condición sobre la clave.
    const labels = /"proxyLabels":\[\{\{range \$k, \$v := \.Config\.Labels\}\}(.*?)null\],/.exec(
      CONTAINER_FORMAT,
    );
    expect(labels).not.toBeNull();
    const pairs = [...labels![1].matchAll(/\[\{\{json \$k\}\},\{\{json \$v\}\}\]/g)];
    expect(pairs).toHaveLength(5);
    for (const p of pairs)
      expect(labels![1].slice(0, p.index)).toMatch(/\}\}$/);
    expect(labels![1]).toMatch(/^\{\{\$p := split \$k "\."\}\}/);
    expect(labels![1]).not.toMatch(/middlewares|basic|tls|Env/);
    const rest = CONTAINER_FORMAT.replace(labels![0], '');
    expect(rest).not.toMatch(/Env|\.Config\.Labels\}/);
    expect(CONTAINER_FORMAT).not.toMatch(/json \.Config\b(?!\.)/);
    // Montajes y redes campo a campo: nada de `json .Mounts` ni DriverOpts.
    expect(CONTAINER_FORMAT).not.toMatch(/json \.Mounts|json \.NetworkSettings\.Networks|DriverOpts/);
    for (const f of [VOLUME_FORMAT, NETWORK_FORMAT])
      expect(f).not.toMatch(/Options|Labels|Status/);
  });

  it('si docker ps falla o devuelve basura, el job falla entero', async () => {
    await expect(
      discoverer.discover(
        PARENT,
        host({
          ps: {
            code: 1,
            stdout: '',
            stderr: 'Cannot connect to the Docker daemon',
          },
        }).exec,
      ),
    ).rejects.toThrow(
      'No se pudo listar Docker: docker ps falló (código 1): Cannot connect to the Docker daemon',
    );
    await expect(
      discoverer.discover(PARENT, host({ ps: 'hola; rm -rf /\n' }).exec),
    ).rejects.toThrow(DiscoveryError);
  });

  it('un inspect a medias (contenedor borrado entretanto) deja el listado incompleto', async () => {
    const listing = await discoverer.discover(
      PARENT,
      host({
        inspect: {
          code: 1,
          stdout: INSPECT.split('\n').slice(0, 3).join('\n'),
          stderr: 'error: no such object: d04d1a29718b',
        },
      }).exec,
    );
    expect(listing.complete).toBe(false);
    expect(listing.children).toHaveLength(3);
    expect(listing.warnings[0]).toContain('no such object');
  });

  it('nombres o ids no válidos se descartan y el listado queda incompleto', async () => {
    const bad = JSON.stringify({
      ...(JSON.parse(INSPECT.split('\n')[0]) as object),
      name: '/../../x',
    });
    const listing = await discoverer.discover(
      PARENT,
      host({ ps: IDS[0], inspect: bad }).exec,
    );
    expect(listing.children).toEqual([]);
    expect(listing.complete).toBe(false);
  });

  it('sin contenedores: listado vacío y completo (los que hubiera pasan a missing)', async () => {
    const { exec, calls } = host({ ps: '', imagesLs: '' });
    const listing = await discoverer.discover(PARENT, exec);
    expect(listing).toMatchObject({ children: [], complete: true });
    // Ni inspect de contenedores ni de imágenes; sí los listados del host.
    expect(calls.map((c) => c.argv[1])).toEqual([
      'ps',
      'images',
      'volume',
      'network',
    ]);
  });

  it('un fallo de image inspect es un aviso; los contenedores siguen completos', async () => {
    const listing = await discoverer.discover(
      PARENT,
      host({ images: { code: 1, stdout: '', stderr: 'boom' } }).exec,
    );
    expect(listing.complete).toBe(true);
    expect(dockerOf(listing.children[0].facts).repoDigests).toEqual([]);
    expect(listing.warnings).toEqual([
      'docker image inspect falló (código 1): boom',
    ]);
  });

  it('los contenedores no se recogen con Ansible', () => {
    expect(discoverer.collectTarget().target).toBeNull();
  });

  it('está registrado para el rol docker-host', () => {
    expect(createDiscoverers().get('docker-host')).toBeInstanceOf(
      DockerDiscoverer,
    );
  });
});

// Docker 26.1 (docker.io de Debian 13, almacén clásico) en el CT 100: web1 y cache con el
// volumen `datos`, web2 con un bind de solo lectura, web1 y web2 en `app-net`; `huerfano`,
// `sin-uso` y alpine:3.20 sin usar.
describe('DockerDiscoverer: volúmenes, redes e imágenes del host (Docker 26 real)', () => {
  const d26 = (name: string) => fixture(`docker26/${name}`);
  const real = (extra: Replies = {}) =>
    host({
      ps: d26('ps.txt'),
      inspect: d26('inspect.jsonl'),
      imagesLs: d26('images.txt'),
      images: d26('image-inspect.jsonl'),
      volumeLs: d26('volume-ls.txt'),
      volumeInspect: d26('volume-inspect.jsonl'),
      networkLs: d26('network-ls.txt'),
      networkInspect: d26('network-inspect.jsonl'),
      ...extra,
    });
  const H = 'host-1';
  const parent = { id: H, name: 'pruebas', facts: {} };
  const ALPINE =
    'sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731';

  it('volúmenes y redes del host como hijos, con sus enlaces desde los contenedores', async () => {
    const listing = await discoverer.discover(parent, real().exec);
    expect(listing.complete).toBe(true);
    expect(listing.partialTypes).toEqual([]);
    expect(listing.warnings).toEqual([]);
    const names = (type: string) =>
      listing.children.filter((c) => c.type === type).map((c) => c.name);
    expect(names('container')).toEqual(['cache', 'web2', 'web1']);
    expect(names('volume')).toEqual(['datos', 'huerfano']);
    expect(names('network')).toEqual(['app-net', 'bridge', 'host', 'none', 'sin-uso']);

    const volume = listing.children.find((c) => c.name === 'datos')!;
    expect(volume).toMatchObject({
      naturalKey: dockerVolumeKey(H, 'datos'),
      facts: {
        docker: {
          name: 'datos',
          driver: 'local',
          scope: 'local',
          mountpoint: '/var/lib/docker/volumes/datos/_data',
          createdAt: '2026-10-11T00:31:11.000Z',
          discoveredAt: NOW.toISOString(),
        },
      },
    });
    const net = listing.children.find((c) => c.name === 'app-net')!;
    expect(net.facts.docker).toMatchObject({
      driver: 'bridge',
      internal: false,
      subnets: [{ subnet: '172.18.0.0/16', gateway: '172.18.0.1' }],
    });
    expect(
      (listing.children.find((c) => c.name === 'host')!.facts.docker as { subnets: unknown[] })
        .subnets,
    ).toEqual([]);

    const link = (type: string, from: string, to: string) => ({
      type,
      from: { type: 'container', naturalKey: dockerNaturalKey(H, from) },
      to:
        type === 'mounts'
          ? { type: 'volume', naturalKey: dockerVolumeKey(H, to) }
          : { type: 'network', naturalKey: dockerNetworkKey(H, to) },
    });
    expect(listing.links).toEqual([
      link('mounts', 'cache', 'datos'),
      link('attached_to', 'cache', 'bridge'),
      link('attached_to', 'web2', 'app-net'),
      link('mounts', 'web1', 'datos'),
      link('attached_to', 'web1', 'app-net'),
    ]);
    // En los facts del contenedor: el bind con su ruta y solo lectura; el volumen sin ruta.
    const web2 = dockerOf(listing.children.find((c) => c.name === 'web2')!.facts);
    expect(web2.mounts).toEqual([
      { type: 'bind', name: null, source: '/srv', destination: '/srv', readOnly: true },
    ]);
    expect(web2.networks).toEqual([{ name: 'app-net', ipv4: '172.18.0.3', ipv6: null }]);
    expect(
      dockerOf(listing.children.find((c) => c.name === 'web1')!.facts).mounts,
    ).toEqual([
      { type: 'volume', name: 'datos', source: null, destination: '/usr/share/nginx/html', readOnly: false },
    ]);
  });

  it('imágenes del host, también las que no usa ningún contenedor', async () => {
    const listing = await discoverer.discover(parent, real().exec);
    expect(listing.hostImages?.complete).toBe(true);
    expect(listing.hostImages?.images.map((i) => i.repoTags[0])).toEqual([
      'alpine:3.20',
      'redis:7.0',
      'nginx:1.25',
    ]);
    expect(listing.hostImages?.images[0]).toEqual({
      imageId: ALPINE,
      repoDigests: [
        'alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc',
      ],
      repoTags: ['alpine:3.20'],
      platform: 'linux/amd64',
      size: 7802737,
    });
  });

  it('sin `volume ls`/`network ls` en el sudoers (v2): los que usan los contenedores, listado parcial y sin aviso', async () => {
    const denied = {
      code: 1,
      stdout: '',
      stderr: 'sudo: a password is required\n',
    };
    const { exec, calls } = real({ volumeLs: denied, networkLs: denied });
    const listing = await discoverer.discover(parent, exec);
    expect(listing.complete).toBe(true);
    expect(listing.partialTypes).toEqual(['volume', 'network']);
    // La nota la da la tabla de capacidades del sudoers, no el descubridor.
    expect(listing.warnings).toEqual([]);
    expect(
      listing.children.filter((c) => c.type !== 'container').map((c) => c.name),
    ).toEqual(['datos', 'app-net', 'bridge']);
    // Solo se inspeccionan los nombres que usan los contenedores (ya validados).
    expect(calls.find((c) => c.argv.includes('volume') && c.argv.includes('--type'))!.argv.slice(6)).toEqual(['datos']);
  });

  it('`volume ls` que falla por otra cosa: aviso y parcial', async () => {
    const listing = await discoverer.discover(
      parent,
      real({ volumeLs: { code: 1, stdout: '', stderr: 'Error: boom' } }).exec,
    );
    expect(listing.partialTypes).toEqual(['volume']);
    expect(listing.warnings).toEqual(['docker volume ls falló (código 1): Error: boom']);
  });

  it('un volumen borrado entre `ls` e `inspect`: listado parcial de volúmenes', async () => {
    const listing = await discoverer.discover(
      parent,
      real({
        volumeInspect: {
          code: 1,
          stdout: d26('volume-inspect.jsonl').split('\n')[0]!,
          stderr: 'Error: No such volume: huerfano',
        },
      }).exec,
    );
    expect(listing.partialTypes).toEqual(['volume']);
    expect(listing.children.filter((c) => c.type === 'volume').map((c) => c.name)).toEqual(['datos']);
  });

  it('nombres de volumen no válidos en `volume ls`: se descartan y es parcial', async () => {
    const listing = await discoverer.discover(
      parent,
      real({ volumeLs: 'datos\n--format=x\n' }).exec,
    );
    expect(listing.partialTypes).toContain('volume');
    expect(listing.warnings).toContain('Respuesta de docker volume ls no válida');
  });

  it('`docker images` que falla: imágenes del host incompletas (no se quita ninguna)', async () => {
    const listing = await discoverer.discover(
      parent,
      real({ imagesLs: { code: 1, stdout: '', stderr: 'boom' } }).exec,
    );
    expect(listing.hostImages?.complete).toBe(false);
    // Las de los contenedores siguen saliendo.
    expect(listing.hostImages?.images).toHaveLength(2);
    expect(listing.complete).toBe(true);
  });

  it('nunca salen Options ni etiquetas aunque Docker las devolviera', async () => {
    const leaky = d26('volume-inspect.jsonl').replace(
      '"name":"datos",',
      '"name":"datos","options":{"o":"addr=nas,password=centinela-secreto"},',
    );
    const listing = await discoverer.discover(parent, real({ volumeInspect: leaky }).exec);
    expect(JSON.stringify(listing.children)).not.toContain('centinela-secreto');
  });
});

