import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { expandQuery } from '@infraward/connectors';
import { Asset, ContainerImage } from '@infraward/domain';
import type { SecretsService } from '@infraward/secrets';
import type {
  DockerContainerFacts,
  ImageScanJobResult,
  ImageVulnerability,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { HostScanner } from '../scan/host-scanner.js';
import type { SbomReevaluator } from '../scan/sbom-reevaluator.js';
import type { ScanScheduler } from '../scan/scan-scheduler.js';
import type { TrivyScan } from '../scan/trivy-report.js';
import type { TrivyRunner } from '../scan/trivy-runner.js';
import type { ScannedHostKey } from '../ssh/host-keys.js';
import type {
  ProcessRunner,
  SshClient,
  StreamResult,
  StreamingHostExec,
} from '../ssh/ssh-client.js';
import type { AssetRoute, AssetRoutes } from './asset-routes.js';
import { ScanProcessor } from './scan.processor.js';
import { SshIdentities } from '../ssh/ssh-identity.js';

const IMAGE = `sha256:${'a'.repeat(64)}`;
/** SBOM real de `trivy image` (nginx:1.25 recortado), con una etiqueta de la imagen. */
const NGINX_SBOM = readFileSync(
  new URL('../scan/fixtures/sbom-image.cdx.json', import.meta.url),
  'utf8',
);

/** SBOM mínimo como el de Trivy, con el ImageID de la imagen analizada. */
const sbomOf = (imageId: string) =>
  JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    metadata: {
      tools: { components: [{ name: 'trivy', version: '0.75.0' }] },
      component: {
        type: 'container',
        properties: [{ name: 'aquasecurity:trivy:ImageID', value: imageId }],
      },
    },
    components: [
      { type: 'operating-system', name: 'debian', version: '12.5' },
      {
        type: 'library',
        name: 'openssl',
        version: '3.0.11-1',
        purl: 'pkg:deb/debian/openssl@3.0.11-1',
      },
    ],
  });
const FP = `SHA256:${'g'.repeat(43)}`;
const NODE_ROUTE: AssetRoute = {
  connection: { host: '192.0.2.20', port: 22, user: 'inventory' },
  auth: 'static_key',
  keyRef: 'secret://local/assets/node/ssh#privateKey',
  pinned: FP,
  via: { kind: 'pct', vmid: 100 },
  host: { id: 'node', name: 'pve' },
};

const vuln = (id: string): ImageVulnerability => ({
  vulnerabilityId: id,
  packageName: 'openssl',
  installedVersion: '3.0.11-1',
  fixedVersion: null,
  severity: 'HIGH',
  title: null,
  fixStatus: 'affected',
  class: 'os-pkgs',
  pkgType: 'debian',
  pkgPath: null,
  purl: null,
  primaryUrl: null,
  cvss: null,
  fingerprint: id.padEnd(64, '0').slice(0, 64),
});

const docker = (extra: Partial<DockerContainerFacts> = {}) =>
  ({
    imageId: IMAGE,
    imageSizeBytes: 1000,
    repoDigests: [],
    repoTags: ['nginx:1.25'],
    platform: 'linux/amd64',
    ...extra,
  }) as DockerContainerFacts;

beforeAll(() => {
  vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
});

describe('ScanProcessor: image.scan', () => {
  let base: string;
  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'scan-base-'));
  });
  afterEach(() => rmSync(base, { recursive: true, force: true }));

  function setup(
    options: {
      image?: Partial<ContainerImage>;
      containers?: {
        id: string;
        hostId: string;
        docker: DockerContainerFacts;
      }[];
      host?: Partial<Asset>;
      route?: AssetRoute;
      stream?: Partial<StreamResult>;
      scan?: TrivyScan | 'timeout';
      /** SBOM que genera Trivy (por defecto, uno con el ImageID de `scan` o de la imagen). */
      sbom?: string | 'timeout';
      /** La imagen ya tiene SBOM guardado. */
      hasSbom?: boolean;
      backfillHostId?: string;
      indexDigests?: string[];
      force?: boolean;
      imageId?: string;
      /** Hosts con la imagen (`stores`); por defecto, los de los contenedores. */
      hosts?: string[];
      /** `facts.image.sizeBytes` de la imagen. */
      imageSize?: string | null;
    } = {},
  ) {
    const image: Partial<ContainerImage> = {
      assetId: 'img-nginx',
      imageId: IMAGE,
      scanStatus: 'pending',
      scanReason: null,
      vulnerabilityCount: null,
      ...options.image,
    };
    const updates: Record<string, unknown>[] = [];
    const queries: unknown[][] = [];
    const imageRepo = {
      findOneBy: vi.fn(() => Promise.resolve({ ...image })),
      findOneByOrFail: vi.fn(() => Promise.resolve({ ...image })),
      update: vi.fn((_where: unknown, data: Record<string, unknown>) => {
        updates.push(data);
        Object.assign(image, data);
        return Promise.resolve();
      }),
    };
    const manager = {
      update: vi.fn(
        (_e: unknown, _w: unknown, data: Record<string, unknown>) => {
          updates.push(data);
          Object.assign(image, data);
          return Promise.resolve();
        },
      ),
      query: vi.fn((sql: string, params: unknown[]) => {
        queries.push([sql, params]);
        if (sql.startsWith('INSERT INTO findings'))
          return Promise.resolve(
            (JSON.parse(params[1] as string) as unknown[]).map(() => ({
              inserted: true,
            })),
          );
        if (sql.startsWith('INSERT INTO sboms')) {
          sha = params[4] as string;
          return Promise.resolve([{ id: 'sbom-1' }]);
        }
        if (sql.startsWith('SELECT content_sha256'))
          return Promise.resolve([{ content_sha256: sha }]);
        return Promise.resolve([[], 0]);
      }),
    };
    let sha = '';
    const host = {
      id: 'ct-100',
      name: 'pruebas',
      status: 'active',
      facts: {},
      ...options.host,
    };
    const db = {
      getRepository: (entity: unknown) =>
        entity === ContainerImage
          ? imageRepo
          : {
              findOneBy: () => Promise.resolve(entity === Asset ? host : null),
            },
      transaction: (cb: (m: unknown) => Promise<unknown>) => cb(manager),
      query: vi.fn((sql: string) =>
        Promise.resolve(
          sql.includes('FROM sboms')
            ? options.hasSbom
              ? [{ id: 'sbom-0', content_sha256: 'x', packages_sha256: 'y' }]
              : []
            : // Tamaño guardado en la ficha de la imagen (imágenes sin contenedores).
              [{ size: options.imageSize ?? null }],
        ),
      ),
    } as unknown as DataSource;
    const containers = options.containers ?? [
      { id: 'web1', hostId: 'ct-100', docker: docker() },
      { id: 'web2', hostId: 'ct-100', docker: docker() },
    ];
    const scheduler = {
      containers: vi.fn(() => Promise.resolve(containers)),
      register: vi.fn(() => Promise.resolve({ ...image })),
      hostsOf: vi.fn(() =>
        Promise.resolve(
          options.hosts ?? [...new Set(containers.map((c) => c.hostId))],
        ),
      ),
      afterBackfill: vi.fn(() => Promise.resolve()),
    };
    const routes = {
      route: vi.fn(() => Promise.resolve(options.route ?? NODE_ROUTE)),
    };
    const streamed: { argv: string[]; sudo?: boolean; dest: string }[] = [];
    const node: StreamingHostExec = {
      run: () => Promise.reject(new Error('no se usa')),
      query: () => Promise.reject(new Error('no se usa')),
      // Se anota el comando real que ejecuta el ayudante del nodo como root.
      streamToFile: (query, dest) => {
        streamed.push({ argv: expandQuery(query), sudo: true, dest });
        writeFileSync(dest, 'tar');
        return Promise.resolve({
          code: 0,
          bytes: 3,
          stderr: '',
          limit: null,
          ...options.stream,
        });
      },
      streamArgvToFile: () => Promise.reject(new Error('no se usa')),
    };
    const ssh = {
      scanHostKeys: vi.fn(() =>
        Promise.resolve([
          { fingerprint: FP, type: 'ED25519' } as ScannedHostKey,
        ]),
      ),
      session: vi.fn(
        (
          _t: unknown,
          _k: string,
          _h: unknown,
          fn: (h: StreamingHostExec) => Promise<unknown>,
        ) => fn(node),
      ),
    };
    const secrets = {
      resolve: vi.fn(() => Promise.resolve('clave')),
      sshCertificates: () => undefined,
    };
    const trivy = {
      ensureDb: vi.fn(() => Promise.resolve(new Date('2026-10-09T19:00:00Z'))),
      sbom: vi.fn(() =>
        Promise.resolve(
          options.sbom ??
            sbomOf(
              (options.scan !== 'timeout' && options.scan?.configDigest) ||
                IMAGE,
            ),
        ),
      ),
      evaluate: vi.fn((file: string) => {
        evaluated.push(readFileSync(file, 'utf8'));
        return Promise.resolve(
          options.scan ?? {
            configDigest: IMAGE,
            trivyVersion: '0.75.0',
            vulnerabilities: [vuln('CVE-2024-1'), vuln('CVE-2024-2')],
          },
        );
      }),
    };
    const evaluated: string[] = [];
    const run: ProcessRunner = vi.fn(() =>
      Promise.resolve({
        code: 0,
        stdout: JSON.stringify({
          manifests: (options.indexDigests ?? []).map((digest) => ({ digest })),
        }),
        stderr: '',
      }),
    );
    const values: Partial<EnvironmentVariables> = {
      WORKER_SCAN_DIR: base,
      TRIVY_MAX_IMAGE_SIZE: 1_000_000,
      TRIVY_SCAN_TIMEOUT: 60,
      SCAN_CONCURRENCY: 1,
    };
    const config = {
      get: (k: keyof EnvironmentVariables) => values[k],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    const processor = new ScanProcessor(
      config,
      db,
      secrets as unknown as SecretsService,
      ssh as unknown as SshClient,
      routes as unknown as AssetRoutes,
      scheduler as unknown as ScanScheduler,
      trivy as unknown as TrivyRunner,
      run,
      new SshIdentities(secrets as unknown as SecretsService, config),
      {} as HostScanner,
      {} as SbomReevaluator,
    );
    const job = {
      id: 'job-1',
      name: 'image.scan',
      data: {
        imageId: options.imageId ?? IMAGE,
        ...(options.force ? { force: true } : {}),
        ...(options.backfillHostId
          ? { backfillHostId: options.backfillHostId }
          : {}),
      },
      log: () => Promise.resolve(),
      updateProgress: () => Promise.resolve(),
    } as unknown as Job;
    const process = () => processor.process(job) as Promise<ImageScanJobResult>;
    return {
      process,
      image,
      updates,
      queries,
      streamed,
      ssh,
      trivy,
      run,
      scheduler,
      evaluated,
    };
  }

  it('una imagen sin contenedores se saca del host que la tiene (`stores`)', async () => {
    const t = setup({ containers: [], hosts: ['ct-100'], imageSize: '1000' });
    const result = await t.process();
    expect(t.streamed.map((s) => s.argv.slice(-3))).toEqual([
      ['docker', 'save', IMAGE],
    ]);
    expect(result).toMatchObject({ scanStatus: 'scanned', containers: 0 });
  });

  it('saca la imagen del CT con pct exec, la analiza y guarda los findings una vez, en la imagen', async () => {
    const t = setup();
    const result = await t.process();
    expect(t.streamed).toHaveLength(1);
    expect(t.streamed[0].argv).toEqual([
      'pct',
      'exec',
      '100',
      '--',
      'docker',
      'save',
      IMAGE,
    ]);
    expect(t.streamed[0].sudo).toBe(true);
    expect(t.image).toMatchObject({
      scanStatus: 'scanned',
      scanReason: null,
      scanSource: 'docker_save',
      sourceAssetId: 'ct-100',
      trivyVersion: '0.75.0',
    });
    expect(t.image.vulnerabilityCount).toBe(2);
    // Un solo upsert de findings, en el asset de la imagen, aunque la usen dos contenedores; y
    // su SBOM con sus paquetes.
    const inserts = (prefix: string) =>
      t.queries
        .filter(([sql]) => String(sql).startsWith(prefix))
        .map(([, p]) => (p as unknown[])[0]);
    expect(inserts('INSERT INTO findings')).toEqual(['img-nginx']);
    expect(inserts('INSERT INTO sboms')).toEqual(['img-nginx']);
    expect(inserts('INSERT INTO packages')).toEqual(['img-nginx']);
    // Se evalúa con `trivy sbom` el mismo SBOM que se guarda.
    expect(t.trivy.sbom).toHaveBeenCalledWith(
      { image: expect.stringMatching(/image\.tar$/) as string },
      expect.any(String),
      expect.any(Number),
    );
    expect(t.evaluated).toHaveLength(1);
    expect(result).toMatchObject({
      scanStatus: 'scanned',
      cached: false,
      vulnerabilityCount: 2,
      containers: 2,
      findingsCreated: 2,
    });
    // El directorio del job (con el tar) se borra siempre.
    // Cada réplica trabaja en su subdirectorio (aquí, sin nombre reservado: `local`).
    expect(readdirSync(join(base, 'local'))).toEqual([]);
  });

  it('una imagen ya escaneada con SBOM no se vuelve a analizar ni se tocan sus findings', async () => {
    const t = setup({
      image: { scanStatus: 'scanned', vulnerabilityCount: 1 },
      hasSbom: true,
    });
    const result = await t.process();
    expect(result).toMatchObject({
      cached: true,
      containers: 2,
      vulnerabilityCount: 1,
      findingsCreated: 0,
    });
    expect(t.ssh.session).not.toHaveBeenCalled();
    expect(t.trivy.sbom).not.toHaveBeenCalled();
    expect(t.queries).toEqual([]);
  });

  it('una imagen escaneada antes de los SBOMs sí se escanea, para tenerlo', async () => {
    const t = setup({
      image: { scanStatus: 'scanned', vulnerabilityCount: 1 },
    });
    await expect(t.process()).resolves.toMatchObject({ cached: false });
    expect(t.trivy.evaluate).toHaveBeenCalledOnce();
  });

  it('con force sí la vuelve a analizar', async () => {
    const t = setup({
      image: { scanStatus: 'scanned', vulnerabilityCount: 1 },
      hasSbom: true,
      force: true,
    });
    await t.process();
    expect(t.trivy.sbom).toHaveBeenCalledOnce();
    expect(t.trivy.evaluate).toHaveBeenCalledOnce();
  });

  it('guarda el SBOM comprimido sin las etiquetas de la imagen y es lo que evalúa', async () => {
    const real = `sha256:${'8dd77ef2d82eade8dcf2c08ea032bd9cba04c9d28ace2ccf08ad6804c27bf14f'}`;
    const t = setup({
      imageId: real,
      sbom: NGINX_SBOM,
      containers: [
        { id: 'w', hostId: 'ct-100', docker: docker({ imageId: real }) },
      ],
      scan: { configDigest: real, trivyVersion: '0.75.0', vulnerabilities: [] },
    });
    await t.process();
    const insert = t.queries.find(([sql]) =>
      String(sql).startsWith('INSERT INTO sboms'),
    )![1] as unknown[];
    const stored = gunzipSync(insert[3] as Buffer).toString('utf8');
    expect(NGINX_SBOM).toContain('aquasecurity:trivy:Labels:maintainer');
    expect(stored).not.toContain('Labels');
    expect(stored).toContain('pkg:deb/debian/adduser@3.134');
    expect(t.evaluated).toEqual([stored]);
    // El tar no sobrevive al job.
    // Cada réplica trabaja en su subdirectorio (aquí, sin nombre reservado: `local`).
    expect(readdirSync(join(base, 'local'))).toEqual([]);
  });

  it('relleno: saca la imagen de su host y, acabe como acabe, sigue con la siguiente', async () => {
    const ok = setup({
      image: { scanStatus: 'scanned' },
      backfillHostId: 'ct-100',
    });
    await ok.process();
    expect(ok.scheduler.afterBackfill).toHaveBeenCalledWith(
      IMAGE,
      'ct-100',
      'job-1',
    );
    const failing = setup({
      image: { scanStatus: 'scanned' },
      backfillHostId: 'ct-100',
      stream: { code: 1, stderr: 'Error response from daemon: no such image' },
    });
    await expect(failing.process()).rejects.toThrow(/docker save falló/);
    expect(failing.scheduler.afterBackfill).toHaveBeenCalledOnce();
    // Sigue escaneada con su escaneo anterior; el motivo, anotado.
    expect(failing.image.scanStatus).toBe('scanned');
  });

  it.each([
    [
      'el tamaño de la imagen supera el límite (sin transferir nada)',
      {
        containers: [
          {
            id: 'w',
            hostId: 'ct-100',
            docker: docker({ imageSizeBytes: 5e9 }),
          },
        ],
      },
      /^Supera TRIVY_MAX_IMAGE_SIZE \(4\.66 GiB > 1 MiB\)$/,
      false,
    ],
    [
      'la imagen sin uso supera el límite (tamaño de su ficha)',
      { containers: [], hosts: ['ct-100'], imageSize: '5000000000' },
      /^Supera TRIVY_MAX_IMAGE_SIZE \(4\.66 GiB > 1 MiB\)$/,
      false,
    ],
    [
      'ningún host tiene ya la imagen',
      { containers: [], hosts: [] },
      /^Ningún host del inventario tiene esta imagen$/,
      false,
    ],
    [
      'el servidor tiene el sudoers v1',
      {
        route: { ...NODE_ROUTE, via: undefined },
        host: {
          name: 'docker01',
          facts: { infraward: { sudoersVersion: 1 } },
        },
      },
      /docker01: sudoers desactualizado \(v1 < v4\)/,
      false,
    ],
    [
      'la descarga supera el límite',
      { stream: { limit: 'size' as const, code: null } },
      /Supera TRIVY_MAX_IMAGE_SIZE/,
      true,
    ],
    [
      'la descarga agota el tiempo',
      { stream: { limit: 'time' as const, code: null } },
      /Tiempo agotado tras 60 s/,
      true,
    ],
    [
      'sudo no permite docker save',
      {
        route: { ...NODE_ROUTE, via: undefined },
        host: { facts: { infraward: { sudoersVersion: 4 } } },
        stream: {
          code: 1,
          stderr: 'sudo: a password is required\n',
        },
      },
      /sudo no permite docker save/,
      true,
    ],
    [
      'el ayudante rechaza la consulta',
      {
        route: { ...NODE_ROUTE, via: undefined },
        host: { facts: { infraward: { sudoersVersion: 4 } } },
        stream: {
          code: 64,
          stderr: 'infraward-query: rechazado: consulta desconocida\n',
        },
      },
      /sudo no permite docker save.*sudoers v4/,
      true,
    ],
    [
      'Trivy agota el tiempo',
      { scan: 'timeout' as const },
      /Tiempo agotado/,
      true,
    ],
  ])(
    'no escaneada si %s: skipped con motivo y el job termina bien',
    async (_name, options, reason, transferred) => {
      const t = setup(options);
      const result = await t.process();
      expect(result.scanStatus).toBe('skipped');
      expect(result.scanReason).toMatch(reason);
      expect(t.image.scanStatus).toBe('skipped');
      expect(t.streamed.length > 0).toBe(transferred);
      // Cada réplica trabaja en su subdirectorio (aquí, sin nombre reservado: `local`).
    expect(readdirSync(base).flatMap((d) => readdirSync(join(base, d)))).toEqual([]);
    },
  );

  it('un re-escaneo forzado que no se completa conserva el escaneo anterior', async () => {
    const t = setup({
      image: { scanStatus: 'scanned', vulnerabilityCount: 1 },
      force: true,
      stream: { limit: 'size', code: null },
    });
    await t.process();
    expect(t.image.scanStatus).toBe('scanned');
    expect(t.image.scanReason).toMatch(
      /^Último re-escaneo no completado: Supera/,
    );
  });

  it('si docker save falla, la imagen queda failed, el job falla y no quedan ficheros', async () => {
    const t = setup({
      stream: { code: 1, stderr: 'Error response from daemon: no such image' },
    });
    await expect(t.process()).rejects.toThrow(
      'docker save falló (código 1): Error response from daemon: no such image',
    );
    expect(t.image).toMatchObject({
      scanStatus: 'failed',
      scanReason:
        'docker save falló (código 1): Error response from daemon: no such image',
    });
    // Cada réplica trabaja en su subdirectorio (aquí, sin nombre reservado: `local`).
    expect(readdirSync(join(base, 'local'))).toEqual([]);
  });

  it('almacén de containerd: vale si index.json referencia el image ID; si no, no se guarda', async () => {
    const other = `sha256:${'c'.repeat(64)}`;
    const ok = setup({
      scan: {
        configDigest: other,
        trivyVersion: '0.75.0',
        vulnerabilities: [],
      },
      indexDigests: [IMAGE],
    });
    // El ImageID sale del SBOM (el del config, como en el informe de Trivy).
    await expect(ok.process()).resolves.toMatchObject({
      scanStatus: 'scanned',
    });
    expect(ok.run).toHaveBeenCalledWith(
      'tar',
      ['-xOf', expect.stringMatching(/image\.tar$/) as string, 'index.json'],
      30_000,
    );

    const bad = setup({
      scan: {
        configDigest: other,
        trivyVersion: '0.75.0',
        vulnerabilities: [],
      },
      indexDigests: [other],
    });
    await expect(bad.process()).rejects.toThrow(/no coincide con el image ID/);
    expect(bad.image.scanStatus).toBe('failed');
    // Cada réplica trabaja en su subdirectorio (aquí, sin nombre reservado: `local`).
    expect(readdirSync(join(base, 'local'))).toEqual([]);
  });

  it('rechaza un image ID mal formado sin tocar nada', async () => {
    const t = setup({ imageId: 'nginx; rm -rf /' });
    await expect(t.process()).rejects.toThrow('Image ID no válido');
    expect(t.streamed).toEqual([]);
    expect(t.updates).toEqual([]);
  });
});
