import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type {
  ImageVulnerability,
  SbomReevaluateJobResult,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import type { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { SbomReevaluator } from './sbom-reevaluator.js';
import type { ScanScheduler } from './scan-scheduler.js';
import { TrivyError, type TrivyScan } from './trivy-report.js';
import type { TrivyRunner } from './trivy-runner.js';

const DB_DATE = new Date('2026-10-11T06:00:00Z');

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

beforeAll(() => {
  vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
});

describe('SbomReevaluator', () => {
  let base: string;
  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'reevaluate-'));
  });
  afterEach(() => rmSync(base, { recursive: true, force: true }));

  /** SBOMs guardados: id → asset, contenido y lo que «ve» Trivy al evaluarlo. */
  function setup(
    sboms: {
      id: string;
      assetId: string;
      json: string;
      scan: TrivyScan | 'timeout' | Error;
      /** Un escaneo lo reemplaza mientras se evalúa. */
      replaced?: boolean;
    }[],
    options: { dbError?: boolean; noDb?: boolean; downloadDb?: boolean } = {},
  ) {
    const writes: [string, unknown[]][] = [];
    const evaluatedFiles: string[] = [];
    const db = {
      query: vi.fn((sql: string, params: unknown[] = []) => {
        if (sql.includes('FROM sboms s'))
          return Promise.resolve(
            sboms.map((s) => ({
              id: s.id,
              asset_id: s.assetId,
              content_sha256: `sha-${s.id}`,
            })),
          );
        if (sql.startsWith('SELECT content FROM sboms')) {
          const s = sboms.find((x) => x.id === params[0]);
          return Promise.resolve(s ? [{ content: gzipSync(s.json) }] : []);
        }
        writes.push([sql, params]);
        return Promise.resolve([]);
      }),
      transaction: (cb: (m: unknown) => Promise<unknown>) =>
        cb({
          query: (sql: string, params: unknown[]) => {
            if (sql.startsWith('SELECT content_sha256')) {
              const s = sboms.find((x) => x.id === params[0])!;
              return Promise.resolve([
                { content_sha256: s.replaced ? 'otro' : `sha-${s.id}` },
              ]);
            }
            writes.push([sql, params]);
            if (sql.startsWith('INSERT INTO findings'))
              return Promise.resolve(
                (JSON.parse(params[1] as string) as unknown[]).map(() => ({
                  inserted: true,
                })),
              );
            // UPDATE findings … → fixed (uno por SBOM).
            return Promise.resolve([
              [],
              sql.startsWith('UPDATE findings') ? 1 : 0,
            ]);
          },
        }),
    } as unknown as DataSource;
    const trivy = {
      ensureDb: vi.fn(() =>
        options.dbError
          ? Promise.reject(
              new TrivyError('No se pudo descargar la base de datos de Trivy'),
            )
          : Promise.resolve(DB_DATE),
      ),
      dbUpdatedAt: vi.fn(() => Promise.resolve(options.noDb ? null : DB_DATE)),
      evaluate: vi.fn((file: string) => {
        evaluatedFiles.push(file);
        const json = readFileSync(file, 'utf8');
        const s = sboms.find((x) => x.json === json)!;
        return s.scan instanceof Error
          ? Promise.reject(s.scan)
          : Promise.resolve(s.scan);
      }),
    };
    const scheduler = { startBackfill: vi.fn(() => Promise.resolve(2)) };
    const values: Partial<EnvironmentVariables> = {
      WORKER_SCAN_DIR: base,
      TRIVY_SCAN_TIMEOUT: 60,
    };
    const config = {
      get: (k: keyof EnvironmentVariables) => values[k],
    } as unknown as ConfigService<EnvironmentVariables, true>;
    const reevaluator = new SbomReevaluator(
      config,
      db,
      trivy as unknown as TrivyRunner,
      scheduler as unknown as ScanScheduler,
    );
    const job = {
      id: 'job-r',
      name: 'sbom.reevaluate',
      data: options.downloadDb ? { downloadDb: true } : {},
      log: () => Promise.resolve(),
      updateProgress: () => Promise.resolve(),
    } as unknown as Job;
    const run = () => reevaluator.run(job) as Promise<SbomReevaluateJobResult>;
    return { run, writes, trivy, scheduler, evaluatedFiles };
  }

  const scan = (...ids: string[]): TrivyScan => ({
    configDigest: null,
    trivyVersion: '0.75.0',
    vulnerabilities: ids.map(vuln),
  });

  it('evalúa cada SBOM guardado con Trivy, sincroniza sus findings y arranca el relleno', async () => {
    const t = setup([
      {
        id: 's1',
        assetId: 'srv',
        json: '{"a":1}',
        scan: scan('CVE-1', 'CVE-2'),
      },
      { id: 's2', assetId: 'img', json: '{"b":2}', scan: scan() },
    ]);
    const result = await t.run();
    expect(result).toEqual({
      sboms: 2,
      evaluated: 2,
      superseded: 0,
      failed: 0,
      findingsCreated: 2,
      findingsFixed: 2,
      dbUpdatedAt: DB_DATE.toISOString(),
      dbUpdateError: null,
      backfillQueued: 2,
    });
    // Findings del asset de cada SBOM; lo que ya no ve Trivy pasa a fixed.
    const upserts = t.writes.filter(([sql]) =>
      sql.startsWith('INSERT INTO findings'),
    );
    expect(upserts.map(([, p]) => p[0])).toEqual(['srv']);
    const fixes = t.writes.filter(([sql]) => sql.startsWith('UPDATE findings'));
    expect(fixes.map(([, p]) => p)).toEqual([
      ['srv', [vuln('CVE-1').fingerprint, vuln('CVE-2').fingerprint]],
      ['img', []],
    ]);
    expect(
      t.writes
        .filter(([sql]) => sql.startsWith('UPDATE sboms'))
        .map(([, p]) => p),
    ).toEqual([
      ['s1', DB_DATE, 2],
      ['s2', DB_DATE, 0],
    ]);
    expect(t.scheduler.startBackfill).toHaveBeenCalledWith('job-r');
    // Nada queda en el directorio de trabajo.
    // Cada réplica trabaja en su subdirectorio (aquí, sin nombre reservado: `local`).
    expect(readdirSync(join(base, 'local'))).toEqual([]);
  });

  it('un SBOM que falla se anota y no para al resto; uno reemplazado entretanto no se toca', async () => {
    const t = setup([
      {
        id: 's1',
        assetId: 'a1',
        json: '{"a":1}',
        scan: new TrivyError('Trivy falló (código 1): bad SBOM'),
      },
      { id: 's2', assetId: 'a2', json: '{"b":2}', scan: 'timeout' },
      {
        id: 's3',
        assetId: 'a3',
        json: '{"c":3}',
        scan: scan('CVE-9'),
        replaced: true,
      },
      { id: 's4', assetId: 'a4', json: '{"d":4}', scan: scan('CVE-4') },
    ]);
    const result = await t.run();
    expect(result).toMatchObject({
      sboms: 4,
      evaluated: 1,
      superseded: 1,
      failed: 2,
      findingsCreated: 1,
    });
    const errors = t.writes
      .filter(([sql]) => sql.includes('evaluation_error = $2'))
      .map(([, p]) => p);
    expect(errors).toEqual([
      ['s1', 'Trivy falló (código 1): bad SBOM'],
      ['s2', 'Tiempo agotado tras 60 s (TRIVY_SCAN_TIMEOUT)'],
    ]);
    // El reemplazado no toca findings.
    const touched = t.writes
      .filter(([sql]) => sql.startsWith('UPDATE findings'))
      .map(([, p]) => p[0]);
    expect(touched).toEqual(['a4']);
  });

  it('sin red para actualizar la BD, evalúa con la de la caché y lo dice', async () => {
    const t = setup([{ id: 's1', assetId: 'a1', json: '{}', scan: scan() }], {
      dbError: true,
    });
    await expect(t.run()).resolves.toMatchObject({
      evaluated: 1,
      dbUpdateError: 'No se pudo descargar la base de datos de Trivy',
    });
  });

  it('pedida desde Vulnerabilidades con downloadDb, fuerza la descarga de la BD; la periódica, no', async () => {
    const forced = setup([{ id: 's1', assetId: 'a1', json: '{}', scan: scan() }], {
      downloadDb: true,
    });
    await forced.run();
    expect(forced.trivy.ensureDb).toHaveBeenCalledWith(true);
    const periodic = setup([{ id: 's1', assetId: 'a1', json: '{}', scan: scan() }]);
    await periodic.run();
    expect(periodic.trivy.ensureDb).toHaveBeenCalledWith(false);
  });

  it('sin ninguna BD de Trivy, falla sin evaluar nada', async () => {
    const t = setup([{ id: 's1', assetId: 'a1', json: '{}', scan: scan() }], {
      dbError: true,
      noDb: true,
    });
    await expect(t.run()).rejects.toThrow(
      'Sin base de datos de Trivy en la caché: No se pudo descargar la base de datos de Trivy',
    );
    expect(t.trivy.evaluate).not.toHaveBeenCalled();
  });
});
