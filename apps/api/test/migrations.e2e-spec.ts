import { DataSource } from 'typeorm';
import { databaseOptions } from '../src/database/database.options.js';
import { ImagesAsAssets1791586561533 } from '../src/database/migrations/1791586561533-ImagesAsAssets.js';
import { DockerPleskModel1791679091000 } from '../src/database/migrations/1791679091000-DockerPleskModel.js';
import { migrations } from '../src/database/migrations/index.js';
import { prepareEnv } from './support/app.js';

const NGINX = `sha256:${'1'.repeat(64)}`;
const FP = (n: number) => String(n).repeat(64);

/**
 * Migraciones con datos: se migra hasta la anterior, se siembran filas con el esquema viejo y se
 * comprueba la migración (y su vuelta atrás) sobre ellas.
 */
describe('Migración ImagesAsAssets (e2e)', () => {
  let db: DataSource;

  beforeAll(async () => {
    await prepareEnv('e2e_migrations');
    const env = process.env;
    const before = migrations.indexOf(ImagesAsAssets1791586561533);
    db = new DataSource({
      ...databaseOptions({
        host: env.DATABASE_HOST!,
        port: Number(env.DATABASE_PORT),
        username: env.DATABASE_USER!,
        password: env.DATABASE_PASSWORD!,
        database: env.DATABASE_NAME!,
      }),
      migrations: migrations.slice(0, before + 1),
      logging: ['error'],
    });
    await db.initialize();
    // Hasta ImagesAsAssets y vuelta atrás de esa: queda el esquema de la anterior.
    await db.runMigrations({ transaction: 'each' });
    await db.undoLastMigration({ transaction: 'each' });
  });

  afterAll(async () => {
    await db?.destroy();
  });

  /** Dos contenedores con nginx (findings copiados en cada uno, uno de ellos aceptado). */
  async function seed() {
    const [web1, web2]: { id: string }[] = await db.query(
      `INSERT INTO assets (type, name, status, facts)
       VALUES ('container', 'web1', 'active', $1), ('container', 'web2', 'active', $1)
       RETURNING id`,
      [{ docker: { imageId: NGINX } }],
    );
    await db.query(
      `INSERT INTO container_images (image_id, repo_tags, scan_status, vulnerabilities)
       VALUES ($1, '{nginx:1.25}', 'scanned', '[{}, {}]')`,
      [NGINX],
    );
    const finding = (
      asset: string,
      fp: string,
      status: string,
      firstSeen: string,
      lastSeen: string,
    ) =>
      db.query(
        `INSERT INTO findings (asset_id, image_id, fingerprint, vulnerability_id, package_name,
                               installed_version, severity, status, first_seen_at, last_seen_at)
         VALUES ($1, $2, $3, 'CVE-1', 'openssl', '1', 'HIGH', $4, $5, $6)`,
        [asset, NGINX, fp, status, firstSeen, lastSeen],
      );
    await finding(web1.id, FP(1), 'accepted', '2026-10-01', '2026-10-05');
    await finding(web2.id, FP(1), 'open', '2026-09-01', '2026-10-09');
    await finding(web1.id, FP(2), 'open', '2026-10-01', '2026-10-09');
    await finding(web2.id, FP(2), 'open', '2026-10-01', '2026-10-09');
    return { web1: web1.id, web2: web2.id };
  }

  it('crea el asset image, enlaza los contenedores y deja un finding por imagen', async () => {
    const { web1, web2 } = await seed();
    await db.runMigrations({ transaction: 'each' });

    const images: {
      id: string;
      name: string;
      natural_key: string;
      vulnerability_count: number;
    }[] = await db.query(
      `SELECT a.id, a.name, a.natural_key, ci.vulnerability_count
         FROM assets a JOIN container_images ci ON ci.asset_id = a.id
        WHERE a.type = 'image'`,
    );
    expect(images).toEqual([
      expect.objectContaining({
        name: 'nginx:1.25',
        natural_key: NGINX,
        vulnerability_count: 2,
      }),
    ]);
    const image = images[0].id;
    const links: { parent_id: string; child_id: string }[] = await db.query(
      `SELECT parent_id, child_id FROM asset_relations WHERE type = 'instance_of'
        ORDER BY parent_id = $1 DESC`,
      [web1],
    );
    expect(links).toEqual([
      { parent_id: web1, child_id: image },
      { parent_id: web2, child_id: image },
    ]);

    const findings: {
      asset_id: string;
      fingerprint: string;
      status: string;
      first_seen_at: Date;
      last_seen_at: Date;
    }[] = await db.query(
      `SELECT asset_id, fingerprint, status, first_seen_at, last_seen_at
         FROM findings ORDER BY fingerprint`,
    );
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.asset_id === image)).toBe(true);
    // accepted gana; fechas extremas de las dos copias.
    expect(findings[0]).toMatchObject({
      fingerprint: FP(1),
      status: 'accepted',
    });
    expect(findings[0].first_seen_at.toISOString()).toMatch(/^2026-09-01/);
    expect(findings[0].last_seen_at.toISOString()).toMatch(/^2026-10-09/);
    expect(findings[1]).toMatchObject({ fingerprint: FP(2), status: 'open' });
  });

  it('la vuelta atrás copia los findings a cada contenedor', async () => {
    await db.undoLastMigration({ transaction: 'each' });
    const rows: { name: string; n: number }[] = await db.query(
      `SELECT a.name, count(*)::int AS n FROM findings f JOIN assets a ON a.id = f.asset_id
        GROUP BY a.name ORDER BY a.name`,
    );
    expect(rows).toEqual([
      { name: 'web1', n: 2 },
      { name: 'web2', n: 2 },
    ]);
    const images: unknown[] = await db.query(
      `SELECT 1 FROM assets WHERE type::text = 'image'`,
    );
    expect(images).toEqual([]);
  });
});

/** Sesión 14: `stores` host → imagen a partir de los `instance_of` existentes, y vuelta atrás. */
describe('Migración DockerPleskModel (e2e)', () => {
  let db: DataSource;

  beforeAll(async () => {
    await prepareEnv('e2e_migrations_s14');
    const env = process.env;
    const before = migrations.indexOf(DockerPleskModel1791679091000);
    db = new DataSource({
      ...databaseOptions({
        host: env.DATABASE_HOST!,
        port: Number(env.DATABASE_PORT),
        username: env.DATABASE_USER!,
        password: env.DATABASE_PASSWORD!,
        database: env.DATABASE_NAME!,
      }),
      migrations: migrations.slice(0, before + 1),
      logging: ['error'],
    });
    await db.initialize();
    await db.runMigrations({ transaction: 'each' });
    await db.undoLastMigration({ transaction: 'each' });
  });

  afterAll(async () => {
    await db?.destroy();
  });

  it('crea stores desde los contenedores de cada host y la vuelta atrás borra lo nuevo', async () => {
    const [host, web1, web2, nginx]: { id: string }[] = await db.query(
      `INSERT INTO assets (type, name, status, natural_key)
       VALUES ('server', 'docker01', 'active', NULL), ('container', 'web1', 'active', NULL),
              ('container', 'web2', 'active', NULL), ('image', 'nginx:1.25', 'active', $1)
       RETURNING id`,
      [NGINX],
    );
    await db.query(
      `INSERT INTO asset_relations (parent_id, child_id, type)
       VALUES ($1, $2, 'contains'), ($1, $3, 'contains'), ($2, $4, 'instance_of'), ($3, $4, 'instance_of')`,
      [host.id, web1.id, web2.id, nginx.id],
    );
    await db.runMigrations({ transaction: 'each' });
    const stores: { parent_id: string; child_id: string }[] = await db.query(
      `SELECT parent_id, child_id FROM asset_relations WHERE type = 'stores'`,
    );
    // Dos contenedores del mismo host con la misma imagen: una sola relación.
    expect(stores).toEqual([{ parent_id: host.id, child_id: nginx.id }]);
    // Los valores nuevos de los enums se pueden usar.
    await db.query(
      `INSERT INTO assets (type, name, status) VALUES ('volume', 'datos', 'active'), ('certificate', 'le', 'active')`,
    );

    await db.undoLastMigration({ transaction: 'each' });
    const left: { type: string; n: number }[] = await db.query(
      `SELECT type::text, count(*)::int AS n FROM assets GROUP BY 1 ORDER BY 1`,
    );
    expect(left).toEqual([
      { type: 'container', n: 2 },
      { type: 'image', n: 1 },
      { type: 'server', n: 1 },
    ]);
    const relations: { type: string }[] = await db.query(
      `SELECT DISTINCT type::text FROM asset_relations ORDER BY 1`,
    );
    expect(relations.map((r) => r.type)).toEqual(['contains', 'instance_of']);
  });
});
