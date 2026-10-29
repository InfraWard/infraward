import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  fnv64a,
  readBoltValue,
  TrivyDb,
  TrivyDbError,
} from './trivy-db.js';

/** BoltDB generada con bbolt (fixtures/trivy-db/generate.go): ramas, overflow y bucket inline. */
const FIXTURE = join(
  dirname(fileURLToPath(import.meta.url)),
  'fixtures',
  'trivy-db',
  'trivy.db',
);

const METADATA = {
  Version: 2,
  NextUpdate: '2026-10-11T18:59:50Z',
  UpdatedAt: '2026-10-10T18:59:50Z',
  DownloadedAt: '2026-10-11T00:50:55Z',
};

describe('TrivyDb', () => {
  let cache: string;

  beforeEach(async () => {
    cache = await mkdtemp(join(tmpdir(), 'iw-trivy-db-'));
    await mkdir(join(cache, 'db'));
    await copyFile(FIXTURE, join(cache, 'db', 'trivy.db'));
    await writeFile(join(cache, 'db', 'metadata.json'), JSON.stringify(METADATA));
  });

  afterEach(async () => {
    await rm(cache, { recursive: true, force: true });
  });

  it('devuelve los detalles de un CVE conocido', async () => {
    const r = await new TrivyDb(cache).lookup('CVE-2023-45853');
    expect(r.status).toBe('found');
    expect(r.dbUpdatedAt).toBe('2026-10-10T18:59:50Z');
    expect(r.details).toMatchObject({
      title: expect.stringContaining('zlib: integer overflow'),
      description: 'MiniZip in zlib through 1.3 has an integer overflow.',
      severity: 'CRITICAL',
      cweIds: ['CWE-190'],
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-45853',
        'https://github.com/madler/zlib/pull/843',
      ],
      publishedAt: '2023-10-14T02:15:09.323Z',
    });
    expect(r.details!.cvss).toContainEqual(
      expect.objectContaining({
        source: 'nvd',
        v3Score: 9.8,
        v3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      }),
    );
  });

  it('recorre las páginas rama y lee valores en páginas de overflow', async () => {
    const db = new TrivyDb(cache);
    for (const id of ['CVE-2024-00000', 'CVE-2024-00199', 'CVE-2024-00399'])
      expect((await db.lookup(id)).details?.title).toBe(
        `Vulnerabilidad ${Number(id.slice(-5))}`,
      );
    const big = await db.lookup('CVE-2025-99999');
    expect(big.status).toBe('found');
    expect(big.details!.description!.length).toBeGreaterThan(4096);
  });

  it('lee un bucket inline', async () => {
    const v = await readBoltValue(join(cache, 'db', 'trivy.db'), ['small'], 'k');
    expect(v?.toString()).toBe('v');
  });

  it('un CVE que Trivy no conoce da not_found', async () => {
    for (const id of ['CVE-2099-99999', 'CVE-0000-0000', 'ZZZ-1'])
      expect(await new TrivyDb(cache).lookup(id)).toEqual({
        status: 'not_found',
        details: null,
        dbUpdatedAt: '2026-10-10T18:59:50Z',
        reason: null,
      });
  });

  it('con un esquema de Trivy desconocido da unavailable y no lee la BD', async () => {
    await writeFile(
      join(cache, 'db', 'metadata.json'),
      JSON.stringify({ ...METADATA, Version: 3 }),
    );
    const r = await new TrivyDb(cache).lookup('CVE-2023-45853');
    expect(r).toMatchObject({ status: 'unavailable', details: null });
    expect(r.reason).toMatch(/Esquema de la BD de Trivy no reconocido \(versión 3/);
  });

  it('sin BD descargada da unavailable', async () => {
    await rm(join(cache, 'db'), { recursive: true });
    const r = await new TrivyDb(cache).lookup('CVE-2023-45853');
    expect(r).toMatchObject({ status: 'unavailable', dbUpdatedAt: null });
  });

  it('lee la generación de `current`; una descarga a medias en otra generación no le afecta', async () => {
    // Generación publicada (como la deja TrivyRunner): la raíz ya no tiene `db/`.
    await mkdir(join(cache, 'gen-a'));
    await rename(join(cache, 'db'), join(cache, 'gen-a', 'db'));
    await symlink('gen-a', join(cache, 'current'));
    // Otra réplica descargando: BD truncada y sin metadatos en una generación aún sin publicar.
    await mkdir(join(cache, 'gen-b', 'db'), { recursive: true });
    await writeFile(
      join(cache, 'gen-b', 'db', 'trivy.db'),
      (await readFile(FIXTURE)).subarray(0, 4096),
    );
    const db = new TrivyDb(cache);
    expect(await db.lookup('CVE-2023-45853')).toMatchObject({
      status: 'found',
      dbUpdatedAt: METADATA.UpdatedAt,
    });
    // Se publica (rename atómico del enlace): la siguiente consulta ya lee la nueva.
    await copyFile(FIXTURE, join(cache, 'gen-b', 'db', 'trivy.db'));
    await writeFile(
      join(cache, 'gen-b', 'db', 'metadata.json'),
      JSON.stringify({ ...METADATA, UpdatedAt: '2026-10-12T00:00:00Z' }),
    );
    await symlink('gen-b', join(cache, '.current-tmp'));
    await rename(join(cache, '.current-tmp'), join(cache, 'current'));
    expect(await db.lookup('CVE-2023-45853')).toMatchObject({
      status: 'found',
      dbUpdatedAt: '2026-10-12T00:00:00Z',
    });
  });

  it('con las dos meta corruptas da unavailable', async () => {
    const path = join(cache, 'db', 'trivy.db');
    const data = await readFile(path);
    // Un byte del txid de cada meta: el checksum ya no cuadra.
    data[16 + 48] ^= 0xff;
    data[4096 + 16 + 48] ^= 0xff;
    await writeFile(path, data);
    const r = await new TrivyDb(cache).lookup('CVE-2023-45853');
    expect(r).toMatchObject({ status: 'unavailable' });
    expect(r.reason).toMatch(/cabecera de BoltDB/);
  });

  it('con la meta antigua corrupta usa la vigente', async () => {
    const path = join(cache, 'db', 'trivy.db');
    const data = await readFile(path);
    // La de txid menor (bbolt alterna las dos y se queda con la de txid mayor).
    const older =
      data.readBigUInt64LE(16 + 48) < data.readBigUInt64LE(4096 + 16 + 48)
        ? 0
        : 4096;
    data[older + 16 + 48] ^= 0xff;
    await writeFile(path, data);
    expect((await new TrivyDb(cache).lookup('CVE-2023-45853')).status).toBe(
      'found',
    );
  });

  it('un fichero truncado no da un resultado a medias', async () => {
    const path = join(cache, 'db', 'trivy.db');
    await writeFile(path, (await readFile(path)).subarray(0, 3 * 4096));
    expect((await new TrivyDb(cache).lookup('CVE-2024-00399')).status).toBe(
      'unavailable',
    );
  });

  it('no deja la BD abierta: se puede reemplazar entre consultas, como hace Trivy al descargar', async () => {
    const db = new TrivyDb(cache);
    expect((await db.lookup('CVE-2023-45853')).status).toBe('found');
    await rm(join(cache, 'db', 'trivy.db'));
    await copyFile(FIXTURE, join(cache, 'db', 'trivy.db'));
    expect((await db.lookup('CVE-2023-45853')).status).toBe('found');
  });

  it('FNV-1a de 64 bits como el checksum de bbolt', () => {
    expect(fnv64a(Buffer.from(''))).toBe(0xcbf29ce484222325n);
    expect(fnv64a(Buffer.from('a'))).toBe(0xaf63dc4c8601ec8cn);
  });

  it('TrivyDbError es el único error que se convierte en unavailable', () => {
    expect(new TrivyDbError('x')).toBeInstanceOf(Error);
  });
});
