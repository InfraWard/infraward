import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { Asset } from '@infraward/domain';
import type { SecretsService } from '@infraward/secrets';
import type { HostScanJobResult } from '@infraward/shared-types';
import type { Job } from 'bullmq';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import type { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { AssetRoute, AssetRoutes } from '../jobs/asset-routes.js';
import type { ScannedHostKey } from '../ssh/host-keys.js';
import type { SshClient, StreamingHostExec } from '../ssh/ssh-client.js';
import { SshIdentities } from '../ssh/ssh-identity.js';
import { HostScanner } from './host-scanner.js';
import type { TrivyScan } from './trivy-report.js';
import type { TrivyRunner } from './trivy-runner.js';

const FP = `SHA256:${'g'.repeat(43)}`;
const DB_DATE = new Date('2026-10-11T06:00:00Z');
const ROOTFS_SBOM = readFileSync(
  new URL('./fixtures/sbom-rootfs.cdx.json', import.meta.url),
  'utf8',
);
const CT_ROUTE: AssetRoute = {
  connection: { host: '192.0.2.20', port: 22, user: 'inventory' },
  auth: 'static_key',
  keyRef: 'secret://local/assets/node/ssh#privateKey',
  pinned: FP,
  via: { kind: 'pct', vmid: 101 },
  host: { id: 'node', name: 'pve' },
};

beforeAll(() => {
  vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
});

describe('HostScanner: host.scan', () => {
  let base: string;
  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'host-scan-'));
  });
  afterEach(() => rmSync(base, { recursive: true, force: true }));

  function setup(
    options: {
      asset?: Partial<Asset>;
      route?: AssetRoute;
      /** SBOM ya guardado del asset. */
      existing?: {
        packages_sha256: string;
        evaluated_at: Date | null;
        db_updated_at: Date | null;
      };
      force?: boolean;
      scan?: TrivyScan;
    } = {},
  ) {
    const asset = {
      id: 'ct-101',
      type: 'lxc',
      status: 'active',
      connection: null,
      ...options.asset,
    };
    const queries: [string, unknown[]][] = [];
    const db = {
      getRepository: () => ({ findOneBy: () => Promise.resolve(asset) }),
      query: vi.fn((sql: string) =>
        Promise.resolve(
          sql.includes('FROM sboms WHERE asset_id') && options.existing
            ? [
                {
                  id: 'sbom-old',
                  content_sha256: 'sha-old',
                  package_count: 7,
                  ...options.existing,
                },
              ]
            : sql.startsWith('SELECT content FROM sboms')
              ? [{ content: gzipSync('{}') }]
              : [],
        ),
      ),
      transaction: (cb: (m: unknown) => Promise<unknown>) =>
        cb({
          query: (sql: string, params: unknown[]) => {
            queries.push([sql, params]);
            if (sql.startsWith('INSERT INTO sboms'))
              return Promise.resolve([{ id: 'sbom-new' }]);
            if (sql.startsWith('SELECT content_sha256'))
              return Promise.resolve([
                {
                  content_sha256:
                    params[0] === 'sbom-old'
                      ? 'sha-old'
                      : (queries.find(([q]) =>
                          q.startsWith('INSERT INTO sboms'),
                        )?.[1][4] as string),
                },
              ]);
            if (sql.startsWith('INSERT INTO findings'))
              return Promise.resolve(
                (JSON.parse(params[1] as string) as unknown[]).map(() => ({
                  inserted: true,
                })),
              );
            return Promise.resolve([[], 0]);
          },
        }),
    } as unknown as DataSource;
    const commands: string[][] = [];
    const node: StreamingHostExec = {
      run: () => Promise.reject(new Error('no se usa')),
      // Dentro del CT, por la consulta pct-exec del ayudante del nodo.
      query: (q) => {
        commands.push([q.name, ...(q.args ?? [])]);
        return Promise.resolve({
          code: 2,
          stdout: '/etc/os-release\n/var/lib/dpkg/status\n',
          stderr: '',
        });
      },
      streamToFile: (q, dest) => {
        commands.push([q.name, ...(q.args ?? [])]);
        writeFileSync(dest, 'contenido');
        return Promise.resolve({ code: 0, bytes: 9, stderr: '', limit: null });
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
          _k: unknown,
          _h: unknown,
          fn: (h: StreamingHostExec) => Promise<unknown>,
        ) => fn(node),
      ),
    };
    let rootfsSeen: string[] = [];
    const trivy = {
      ensureDb: vi.fn(() => Promise.resolve(DB_DATE)),
      sbom: vi.fn((target: { rootfs: string }) => {
        rootfsSeen = readdirSync(target.rootfs, { recursive: true }).map(
          String,
        );
        return Promise.resolve(ROOTFS_SBOM);
      }),
      evaluate: vi.fn(() =>
        Promise.resolve(
          options.scan ?? {
            configDigest: null,
            trivyVersion: '0.75.0',
            vulnerabilities: [],
          },
        ),
      ),
    };
    const routes = {
      route: vi.fn(() => Promise.resolve(options.route ?? CT_ROUTE)),
    };
    const secrets = {
      resolve: vi.fn(() => Promise.resolve('clave')),
      sshCertificates: () => undefined,
    };
    const values: Partial<EnvironmentVariables> = {
      WORKER_SCAN_DIR: base,
      HOST_SBOM_MAX_SIZE: 1024 * 1024,
      TRIVY_SCAN_TIMEOUT: 60,
    };
    const config = {
      get: (k: keyof EnvironmentVariables) => values[k],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    const scanner = new HostScanner(
      config,
      db,
      ssh as unknown as SshClient,
      routes as unknown as AssetRoutes,
      trivy as unknown as TrivyRunner,
      new SshIdentities(secrets as unknown as SecretsService, config),
    );
    const job = {
      id: 'job-h',
      name: 'host.scan',
      data: { assetId: 'ct-101', ...(options.force ? { force: true } : {}) },
      log: () => Promise.resolve(),
      updateProgress: () => Promise.resolve(),
    } as unknown as Job;
    return {
      scan: () => scanner.scan(job) as Promise<HostScanJobResult>,
      commands,
      queries,
      trivy,
      ssh,
      rootfs: () => rootfsSeen,
    };
  }

  it('CT: copia las BDs de paquetes por pct-exec, genera el SBOM con rootfs, lo guarda y lo evalúa', async () => {
    const t = setup();
    const result = await t.scan();
    expect(t.commands).toEqual([
      ['pct-exec', '101', 'ls', '-1d', '--', ...t.commands[0].slice(5)],
      ['pct-exec', '101', 'cat', '--', '/etc/os-release'],
      ['pct-exec', '101', 'cat', '--', '/var/lib/dpkg/status'],
    ]);
    expect(t.rootfs().sort()).toEqual([
      'etc',
      'etc/os-release',
      'var',
      'var/lib',
      'var/lib/dpkg',
      'var/lib/dpkg/status',
    ]);
    expect(result).toEqual({
      assetId: 'ct-101',
      status: 'scanned',
      reason: null,
      unchanged: false,
      cached: false,
      packageCount: 7,
      vulnerabilityCount: 0,
      findingsCreated: 0,
      findingsFixed: 0,
    });
    const inserted = t.queries
      .filter(([sql]) => /^INSERT INTO (sboms|packages)/.test(sql))
      .map(([sql, p]) => [sql.split(/\s+/)[2], p[0]]);
    expect(inserted).toEqual([
      ['sboms', 'ct-101'],
      ['packages', 'ct-101'],
    ]);
    // Cada réplica trabaja en su subdirectorio (aquí, sin nombre reservado: `local`).
    expect(readdirSync(join(base, 'local'))).toEqual([]);
  });

  it('mismos paquetes y misma BD de Trivy: no evalúa ni reescribe nada', async () => {
    const sha = (await import('./sbom.js')).parseCycloneDx(
      ROOTFS_SBOM,
    ).packagesSha256;
    const t = setup({
      existing: {
        packages_sha256: sha,
        evaluated_at: new Date(),
        db_updated_at: DB_DATE,
      },
    });
    await expect(t.scan()).resolves.toMatchObject({
      status: 'scanned',
      unchanged: true,
      cached: true,
    });
    expect(t.trivy.evaluate).not.toHaveBeenCalled();
    expect(t.queries).toEqual([]);
  });

  it('mismos paquetes con una BD más nueva: evalúa el SBOM guardado sin reescribirlo', async () => {
    const sha = (await import('./sbom.js')).parseCycloneDx(
      ROOTFS_SBOM,
    ).packagesSha256;
    const t = setup({
      existing: {
        packages_sha256: sha,
        evaluated_at: new Date(),
        db_updated_at: new Date('2026-10-01T00:00:00Z'),
      },
    });
    await expect(t.scan()).resolves.toMatchObject({
      unchanged: true,
      cached: false,
    });
    expect(t.trivy.evaluate).toHaveBeenCalledOnce();
    expect(t.queries.some(([sql]) => sql.startsWith('INSERT INTO sboms'))).toBe(
      false,
    );
    expect(t.queries.some(([sql]) => sql.startsWith('UPDATE sboms'))).toBe(
      true,
    );
  });

  it('sin host key fijada o sin estar activo: no escaneado, sin conectarse', async () => {
    for (const t of [
      setup({ route: { ...CT_ROUTE, pinned: null } }),
      setup({ asset: { status: 'missing' } }),
    ]) {
      await expect(t.scan()).resolves.toMatchObject({ status: 'skipped' });
      expect(t.ssh.session).not.toHaveBeenCalled();
    }
    expect(existsSync(base) && readdirSync(base)).toEqual([]);
  });

  it('solo servidores con conexión y CT', async () => {
    await expect(
      setup({ asset: { type: 'container' } }).scan(),
    ).rejects.toThrow(
      'Solo se genera el SBOM de servidores con conexión y de CT',
    );
    await expect(
      setup({ asset: { type: 'server', connection: null } }).scan(),
    ).rejects.toThrow(/Solo se genera el SBOM/);
  });
});
