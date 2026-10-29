import { recomputePolicies } from '@infraward/domain';
import type { DataSource } from 'typeorm';

export const NGINX = `sha256:${'1'.repeat(64)}`;
export const REDIS = `sha256:${'2'.repeat(64)}`;
export const PG = `sha256:${'3'.repeat(64)}`;

/** Lo que nunca puede salir en una exportación ni en una respuesta (referencias y facts). */
export const SECRET_SENTINELS = [
  'secret://local/qol6-centinela',
  'facts-centinela-qol6',
  'BEGIN OPENSSH PRIVATE KEY',
];

export interface SeededInventory {
  node: string;
  ct: string;
  pending: string;
  web: string;
  cache: string;
  db: string;
  images: Record<'nginx' | 'redis' | 'pg', string>;
}

/**
 * Inventario de prueba sin pasar por SSH (QoL-6):
 * `pve-lab` (servidor con conexión y referencia a su clave) › `ct-docker` (CT activo) ›
 * `web`, `cache` y `db` (contenedores activos, cada uno con su imagen y findings), más
 * `pendiente` (servidor sin dar de alta). Los facts llevan un centinela que no debe salir nunca.
 */
export async function seedInventory(db: DataSource): Promise<SeededInventory> {
  const insert = async (
    type: string,
    name: string,
    status: string,
    extra: { facts?: object; connection?: object; credentials?: object } = {},
  ): Promise<string> => {
    const [row]: { id: string }[] = await db.query(
      `INSERT INTO assets (type, discovered_name, status, facts, connection, credentials)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [
        type,
        name,
        status,
        { ...extra.facts, nota: 'facts-centinela-qol6' },
        extra.connection ?? null,
        extra.credentials ?? {},
      ],
    );
    return row!.id;
  };
  const relate = (parent: string, child: string, type = 'contains') =>
    db.query(
      `INSERT INTO asset_relations (parent_id, child_id, type) VALUES ($1, $2, $3)`,
      [parent, child, type],
    );

  const node = await insert('server', 'pve-lab', 'active', {
    connection: { host: '10.9.9.1', port: 22, user: 'inventory' },
    credentials: { sshPrivateKey: 'secret://local/qol6-centinela/pve#private_key' },
  });
  const ct = await insert('lxc', 'ct-docker', 'active');
  await relate(node, ct);
  const pending = await insert('server', 'pendiente', 'pending_enrollment');

  const containers: Record<string, string> = {};
  const images: Record<string, string> = {};
  for (const [name, image, imageId] of [
    ['web', 'nginx', NGINX],
    ['cache', 'redis', REDIS],
    ['db', 'pg', PG],
  ] as const) {
    containers[name] = await insert('container', name, 'active', {
      facts: { docker: { imageId, image: `${image}:latest` } },
    });
    await relate(ct, containers[name]!);
    images[image] = await insert('image', `${image}:latest`, 'active');
    await db.query(
      `INSERT INTO container_images (image_id, asset_id, repo_tags, scan_status)
       VALUES ($1, $2, $3, 'scanned')`,
      [imageId, images[image], [`${image}:latest`]],
    );
    await relate(containers[name]!, images[image]!, 'instance_of');
  }

  const finding = (
    asset: string,
    cve: string,
    severity: string,
    fixed: string | null,
    title: string | null = null,
  ) =>
    db.query(
      `INSERT INTO findings (asset_id, fingerprint, vulnerability_id, package_name,
                             installed_version, fixed_version, severity, title)
       VALUES ($1, md5($6), $2, 'openssl', '3.0.1', $3, $4, $5)`,
      [asset, cve, fixed, severity, title, `${asset}|${cve}`],
    );
  // El título intenta una inyección de fórmula en la hoja de cálculo.
  await finding(images['nginx']!, 'CVE-2026-0001', 'CRITICAL', '3.0.2', '=HYPERLINK("http://x")');
  await finding(images['nginx']!, 'CVE-2026-0002', 'HIGH', '3.0.2');
  await finding(images['redis']!, 'CVE-2026-0002', 'HIGH', '3.0.2');
  await finding(images['pg']!, 'CVE-2026-0003', 'CRITICAL', null);
  await finding(ct, 'CVE-2026-0001', 'CRITICAL', '3.0.2');

  await db.transaction((m) => recomputePolicies(m));
  return {
    node,
    ct,
    pending,
    web: containers['web']!,
    cache: containers['cache']!,
    db: containers['db']!,
    images: images as SeededInventory['images'],
  };
}
