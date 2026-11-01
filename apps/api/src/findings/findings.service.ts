import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { IMAGE_ID } from '@infraward/connectors';
import {
  Asset,
  AssetRelation,
  ContainerImage,
  policyValues,
  scanEnabledSql,
  EXPOSED_ASSETS_SQL,
} from '@infraward/domain';
import {
  hostScanDeduplicationId,
  JOB_NAMES,
  scanDisabledReason,
  SEVERITIES,
  scanDeduplicationId,
  type AffectedAsset,
  type AssetFindingsPage,
  type AssetVulnerabilitiesPage,
  type ContainerImageSummary,
  type DockerContainerFacts,
  type Finding as FindingContract,
  type FindingSearchResult,
  type Page,
  type PublicExposure,
  type SbomSummary,
  type ScanAssetResponse,
  type HiddenReason,
  type NoiseReason,
  type PriorityReason,
  type VulnerabilitiesPage,
  type VulnerablePackage,
  PRIORITY_BAND_MIN,
  priorityInfo,
} from '@infraward/shared-types';
import { effectivePolicyOf } from '../assets/assets.mapper.js';
import { namedPolicySources } from '../inventory/policy-sources.js';
import { DataSource } from 'typeorm';
import { JobsService } from '../jobs/jobs.service.js';
import {
  findingWhere,
  NOT_UNUSED_IMAGE,
  SCAN_ENABLED_OWNER,
} from './finding-where.js';
import { SbomsService } from './sboms.service.js';
import type { FindingListQueryDto } from './findings.dto.js';
import {
  ACCEPTANCE_JSON,
  acceptanceOf,
  type AcceptanceRow,
} from './finding-acceptance.service.js';

const DEFAULT_LIMIT = 50;

/** Severidades de más a menos graves (el orden de las listas). */
const SEVERITY_BY_RANK = [...SEVERITIES].reverse();
const SEVERITY_RANK = `ARRAY[${SEVERITY_BY_RANK.map((s) => `'${s}'`).join(',')}]::text[]`;

interface VulnerabilityGroupRow {
  vulnerability_id: string;
  rank: number;
  title: string | null;
  primary_url: string | null;
  fixable: boolean;
  priority: number | null;
  reasons: PriorityReason[] | null;
  noise_reason: NoiseReason | null;
  cvss: number | null;
  kev: boolean | null;
  epss: number | null;
  packages: VulnerablePackage[];
  total: number;
}

/**
 * Prioridad de un CVE: la de sus findings que no son ruido (un CVE del kernel en uso y de sus
 * cabeceras es del kernel en uso); si todos son ruido, la mayor.
 */
const GROUP_PRIORITY = `COALESCE(max(f.priority) FILTER (WHERE f.noise_reason IS NULL), max(f.priority))`;
/** Los findings del grupo del más al menos representativo: primero lo que no es ruido. */
const GROUP_FIRST = `(f.noise_reason IS NOT NULL), f.priority DESC NULLS LAST`;

/** Severidad máxima del grupo como posición en `SEVERITY_BY_RANK` (la columna `rank`). */
const PAGE_RANK = `min(array_position(${SEVERITY_RANK}, f.severity::text))`;

/**
 * Orden de las listas por CVE: por prioridad (por defecto) o por severidad. `rank`: la columna
 * de GROUP_COLUMNS o, donde no está (la página de `vulnerabilities`), su expresión.
 */
function groupOrder(
  sort: 'priority' | 'severity' | undefined,
  rank = 'rank',
): string {
  return sort === 'severity'
    ? `${rank}, ${GROUP_PRIORITY} DESC NULLS LAST, f.vulnerability_id`
    : `${GROUP_PRIORITY} DESC NULLS LAST, ${rank}, f.vulnerability_id`;
}

/**
 * Escaneos de imágenes y findings (DESIGN §9). La API solo encola: Trivy lo ejecuta el worker.
 */
@Injectable()
export class FindingsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly jobs: JobsService,
    private readonly sboms: SbomsService,
  ) {}

  /**
   * Encola el escaneo de un asset:
   * - servidor con conexión o CT activo: su SBOM (`host.scan`, deduplicado por asset) y, si es
   *   un host Docker, también las imágenes de sus contenedores activos;
   * - contenedor, imagen o host Docker: un job por imagen, deduplicado por image ID.
   * Sin `force`, una imagen ya escaneada (con SBOM) no se vuelve a analizar y un SBOM sin cambios
   * no se vuelve a evaluar con la misma BD de Trivy. Con el escaneo desactivado en su política,
   * 409.
   */
  async scan(
    assetId: string,
    force = false,
    options: { parentJobId?: string } = {},
  ): Promise<ScanAssetResponse> {
    const { parentJobId } = options;
    const asset = await this.findAsset(assetId);
    // Política de inventario (§10): con el escaneo desactivado, tampoco bajo demanda.
    if (!policyValues(asset.effectivePolicy).scanEnabled) {
      // El motivo concreto, con los nombres (la regla de qué nodo, proyecto o etiqueta).
      const effective = effectivePolicyOf(asset);
      throw new ConflictException(
        scanDisabledReason({
          ...effective,
          sources: await namedPolicySources(this.db.manager, effective),
        }),
      );
    }
    const host =
      asset.type === 'lxc' || (asset.type === 'server' && !!asset.connection);
    const jobs = [];
    if (host) {
      if (asset.status !== 'active')
        throw new ConflictException('Solo se escanean servidores y CT activos');
      jobs.push(
        await this.jobs.enqueue(
          JOB_NAMES.hostScan,
          { assetId, ...(force ? { force } : {}) },
          { deduplicationId: hostScanDeduplicationId(assetId), parentJobId },
        ),
      );
    }
    for (const imageId of (await this.imagesToScan(asset, host)).filter((id) =>
      IMAGE_ID.test(id),
    ))
      jobs.push(
        await this.jobs.enqueue(
          JOB_NAMES.imageScan,
          { imageId, ...(force ? { force } : {}) },
          { deduplicationId: scanDeduplicationId(imageId), parentJobId },
        ),
      );
    return { jobs };
  }

  /** Imágenes a escanear con el asset (las de sus contenedores, en un host Docker). */
  private async imagesToScan(asset: Asset, host: boolean): Promise<string[]> {
    if (asset.type === 'image') {
      const image = await this.db
        .getRepository(ContainerImage)
        .findOneBy({ assetId: asset.id });
      if (!image) throw new ConflictException('Imagen sin ficha de escaneo');
      return [image.imageId];
    }
    if (asset.type === 'container') {
      const imageId = dockerOf(asset)?.imageId;
      if (asset.status !== 'active' || !imageId)
        throw new ConflictException(
          'Solo se escanean contenedores activos con imagen conocida',
        );
      return [imageId];
    }
    if (asset.roles.includes('docker-host') || asset.roles.includes('podman-host')) {
      const rows: { image_id: string }[] = await this.db.query(
        `SELECT DISTINCT a.facts->'docker'->>'imageId' AS image_id
           FROM assets a
           JOIN asset_relations r ON r.child_id = a.id AND r.type = 'contains'
          WHERE r.parent_id = $1 AND a.type = 'container' AND a.status = 'active'`,
        [asset.id],
      );
      if (rows.length === 0 && !host)
        throw new ConflictException(
          'El host no tiene contenedores activos: descúbrelos antes (POST /assets/:id/discover)',
        );
      return rows.map((r) => r.image_id);
    }
    if (!host)
      throw new ConflictException(
        'Solo se escanean servidores con conexión, CT, contenedores, imágenes y hosts Docker o Podman',
      );
    return [];
  }

  /**
   * Findings de un asset. Un contenedor no tiene findings propios: devuelve los de su imagen
   * (relación `instance_of`), que se guardan una sola vez para todos sus contenedores.
   */
  async assetFindings(
    assetId: string,
    query: FindingListQueryDto,
  ): Promise<AssetFindingsPage> {
    const { ownerId, image, sbom } = await this.findingsOwner(assetId);
    const page = ownerId
      ? await this.list(query, ownerId)
      : { items: [], total: 0 };
    return { ...page, image, sbom };
  }

  /**
   * Findings de un asset agrupados por vulnerabilidad: una fila por CVE con los paquetes en los que
   * aparece. Los filtros se aplican a cada finding (con `fixable`, solo salen los paquetes con
   * parche) y la paginación es por CVE.
   */
  async assetVulnerabilities(
    assetId: string,
    query: FindingListQueryDto,
  ): Promise<AssetVulnerabilitiesPage> {
    const { ownerId, image, sbom } = await this.findingsOwner(assetId);
    if (!ownerId) return { items: [], total: 0, image, sbom };
    // La de un asset incluye siempre los de escaneo desactivado (la ficha lo avisa). El ruido
    // (marcado) sale salvo con `includeNoise=false`, que es lo que pide la ficha por defecto: los
    // kernels antiguos que guarda dnf llenaban la pestaña de CVE ya corregidos en el que corre.
    const withNoise = query.includeNoise !== false;
    const { where, params } = findingWhere(
      { ...query, includeScanDisabled: true, includeNoise: withNoise },
      { where: ['f.asset_id = $1'], params: [ownerId] },
    );
    const page = pageParams(params, query);
    const rows: VulnerabilityGroupRow[] = await this.db.query(
      `SELECT f.vulnerability_id, ${GROUP_COLUMNS},
              jsonb_agg(jsonb_build_object(
                'findingId', f.id,
                'packageName', f.package_name,
                'installedVersion', f.installed_version,
                'fixedVersion', f.fixed_version,
                'pkgPath', f.pkg_path,
                'status', f.status,
                'priority', f.priority,
                'noiseReason', f.noise_reason,
                'acceptance', ${ACCEPTANCE_JSON}
              ) ORDER BY ${GROUP_FIRST}, f.package_name, f.pkg_path NULLS FIRST,
                         f.id) AS packages,
              count(*) OVER ()::int AS total
         FROM findings f
         ${INTEL_JOIN}
        WHERE ${where.join(' AND ')}
        GROUP BY f.vulnerability_id
        ORDER BY ${groupOrder(query.sort)}
        ${page.sql}`,
      page.params,
    );
    return {
      items: rows.map((r) => ({ ...toGroup(r), packages: r.packages })),
      total:
        rows[0]?.total ?? (await this.countGroups('findings f', where, params)),
      hidden: withNoise ? null : await this.assetNoise(ownerId, query),
      image,
      sbom,
      exposure: await this.exposureOf([assetId, ownerId]),
    };
  }

  /**
   * Vulnerabilidades de todo el inventario, una fila por CVE: severidad máxima, paquetes, imágenes
   * y contenedores afectados (sin retirados). Los filtros se aplican a cada finding y la
   * paginación es por CVE.
   */
  async vulnerabilities(query: FindingListQueryDto): Promise<VulnerabilitiesPage> {
    const { where, params } = findingWhere(query, {
      where: [`o.status <> 'retired'`],
      params: [],
    });
    const from = `findings f JOIN assets o ON o.id = f.asset_id`;
    // Con proyecto, solo cuentan sus contenedores (la imagen puede estar también en otros).
    let containerProject = '';
    const groupParams = [...params];
    if (query.projectId) {
      groupParams.push(query.projectId);
      containerProject = `AND c.effective_projects @> ARRAY[$${groupParams.length}]::uuid[]`;
    }
    const page = pageParams(groupParams, query);
    // En dos pasos: primero los CVE de la página (solo lo que ordena, sin uniones que multipliquen
    // filas) y después las columnas caras solo de esos. Agregarlo todo antes del LIMIT recorría
    // y ordenaba en disco todos los findings (de 2,1 s a 0,3 s con 725 000).
    const rows: (VulnerabilityGroupRow & {
      package_names: string[];
      images: number;
      containers: number;
      other_assets: number;
      unused_images: number;
      public_domains: number | null;
      public_sample: string | null;
    })[] = await this.db.query(
      `WITH page AS (
         SELECT f.vulnerability_id, count(*) OVER ()::int AS total
           FROM ${from}
          WHERE ${where.join(' AND ')}
          GROUP BY f.vulnerability_id
          ORDER BY ${groupOrder(query.sort, PAGE_RANK)}
          ${page.sql})
       SELECT f.vulnerability_id, ${GROUP_COLUMNS},
              array_agg(DISTINCT f.package_name ORDER BY f.package_name) AS package_names,
              count(DISTINCT f.asset_id) FILTER (WHERE o.type = 'image')::int AS images,
              count(DISTINCT c.id)::int AS containers,
              count(DISTINCT f.asset_id) FILTER (WHERE o.type <> 'image')::int AS other_assets,
              count(DISTINCT f.asset_id) FILTER (
                WHERE o.type = 'image' AND NOT EXISTS (
                  SELECT 1 FROM asset_relations ur
                    JOIN assets uc ON uc.id = ur.parent_id AND uc.status = 'active'
                   WHERE ur.child_id = o.id AND ur.type = 'instance_of'))::int AS unused_images,
              max(e.n) AS public_domains, min(e.names[1]) AS public_sample,
              p.total
         FROM page p
         JOIN findings f ON f.vulnerability_id = p.vulnerability_id
         JOIN assets o ON o.id = f.asset_id
         ${INTEL_JOIN}
         -- Exposición con nombre público (QoL-5b; también es un motivo de la prioridad).
         LEFT JOIN (${EXPOSED_ASSETS_SQL}) e ON e.asset_id = f.asset_id
         -- Contenedores (no retirados) de cada imagen (contenedor instance_of imagen).
         LEFT JOIN asset_relations i
           ON o.type = 'image' AND i.child_id = o.id AND i.type = 'instance_of'
         LEFT JOIN assets c ON c.id = i.parent_id AND c.status <> 'retired'
                            AND (${query.includeScanDisabled === true} OR ${scanEnabledSql('c')})
                            ${containerProject}
        WHERE ${where.join(' AND ')}
        GROUP BY f.vulnerability_id, p.total
        ORDER BY ${groupOrder(query.sort)}`,
      page.params,
    );
    return {
      hidden: await this.hidden(query),
      items: rows.map((r) => ({
        ...toGroup(r),
        exposure: r.public_domains
          ? { publicDomains: r.public_domains, sample: r.public_sample }
          : null,
        packageNames: r.package_names,
        images: r.images,
        containers: r.containers,
        otherAssets: r.other_assets,
        unusedImages: r.unused_images,
      })),
      total: rows[0]?.total ?? (await this.countGroups(from, where, params)),
    };
  }

  /**
   * Findings de un asset que la pestaña deja fuera por ruido, por motivo: los que cumplen el resto
   * del filtro salvo la prioridad (como `hidden` de la lista global, «Fuera de esta vista»).
   */
  private async assetNoise(
    ownerId: string,
    query: FindingListQueryDto,
  ): Promise<Partial<Record<NoiseReason, number>>> {
    const { where, params } = findingWhere(
      {
        ...query,
        includeScanDisabled: true,
        includeNoise: true,
        minPriority: undefined,
      },
      { where: ['f.asset_id = $1', 'f.noise_reason IS NOT NULL'], params: [ownerId] },
    );
    const rows: { reason: NoiseReason; n: number }[] = await this.db.query(
      `SELECT f.noise_reason AS reason, count(*)::int AS n
         FROM findings f WHERE ${where.join(' AND ')} GROUP BY 1`,
      params,
    );
    return Object.fromEntries(rows.map((r) => [r.reason, r.n]));
  }

  /**
   * Findings que el filtro deja fuera de la vista, por el primer motivo que los oculta (DESIGN
   * §9): escaneo desactivado, imagen sin uso, ruido (kernel no en uso, sin corrección prevista) y
   * prioridad por debajo de la pedida. Solo los motivos que aplica el filtro; null si ninguno.
   */
  async hidden(
    query: FindingListQueryDto,
  ): Promise<Partial<Record<HiddenReason, number>> | null> {
    if (query.hidden) return null;
    const cases: string[] = [];
    if (query.includeScanDisabled !== true)
      cases.push(`WHEN NOT ${SCAN_ENABLED_OWNER} THEN 'scan_disabled'`);
    if (query.inUse === true)
      cases.push(`WHEN NOT ${NOT_UNUSED_IMAGE} THEN 'unused_image'`);
    if (query.includeNoise !== true)
      cases.push('WHEN f.noise_reason IS NOT NULL THEN f.noise_reason');
    if (query.minPriority)
      cases.push(
        `WHEN f.priority < ${PRIORITY_BAND_MIN[query.minPriority]} THEN 'low_priority'`,
      );
    if (cases.length === 0) return null;
    const { where, params } = findingWhere(
      {
        ...query,
        includeScanDisabled: true,
        includeNoise: true,
        inUse: false,
        minPriority: undefined,
      },
      { where: [`o.status <> 'retired'`], params: [] },
    );
    const rows: { reason: HiddenReason | null; n: number }[] = await this.db.query(
      `SELECT CASE ${cases.join(' ')} END AS reason, count(*)::int AS n
         FROM findings f JOIN assets o ON o.id = f.asset_id
        WHERE ${where.join(' AND ')}
        GROUP BY 1`,
      params,
    );
    return Object.fromEntries(
      rows.filter((r) => r.reason).map((r) => [r.reason, r.n]),
    );
  }

  /**
   * Vulnerabilidades agrupadas por asset afectado (exportación, QoL-6): servidores, CT e imágenes
   * con findings que cumplen los mismos filtros que la lista por CVE, con los CVE distintos por
   * severidad, los que tienen parche y, en una imagen, los contenedores que la usan (los del
   * proyecto, si se filtra por uno). Los más graves primero.
   */
  async vulnerabilitiesByAsset(
    query: FindingListQueryDto,
    limit: number,
  ): Promise<VulnerabilitiesByAssetRow[]> {
    const { where, params } = findingWhere(query, {
      where: [`o.status <> 'retired'`],
      params: [],
    });
    const all = [...params];
    let containerProject = '';
    if (query.projectId) {
      all.push(query.projectId);
      containerProject = `AND c.effective_projects @> ARRAY[$${all.length}]::uuid[]`;
    }
    all.push(limit);
    const count = (severity: string) =>
      `count(DISTINCT f.vulnerability_id) FILTER (WHERE f.severity = '${severity}')::int`;
    return this.db.query(
      `SELECT o.id, o.name, o.type, o.effective_projects AS projects,
              count(DISTINCT f.vulnerability_id)::int AS cves,
              ${count('CRITICAL')} AS critical, ${count('HIGH')} AS high,
              ${count('MEDIUM')} AS medium, ${count('LOW')} AS low,
              ${count('UNKNOWN')} AS unknown,
              count(DISTINCT f.vulnerability_id) FILTER (WHERE f.fixed_version IS NOT NULL)::int
                AS fixable,
              jsonb_agg(DISTINCT jsonb_build_object(
                'id', f.vulnerability_id, 'severity', f.severity,
                'package', f.package_name, 'installed', f.installed_version,
                'fixed', f.fixed_version, 'status', f.status)) AS findings,
              (SELECT coalesce(array_agg(c.name ORDER BY c.name), '{}')
                 FROM asset_relations i JOIN assets c ON c.id = i.parent_id
                WHERE o.type = 'image' AND i.child_id = o.id AND i.type = 'instance_of'
                  AND c.status <> 'retired' ${containerProject}) AS containers
         FROM findings f JOIN assets o ON o.id = f.asset_id
        WHERE ${where.join(' AND ')}
        GROUP BY o.id
        ORDER BY critical DESC, high DESC, cves DESC, o.name
        LIMIT $${all.length}`,
      all,
    );
  }

  /** Total de CVE cuando la página pedida queda fuera del rango (sin filas de las que leerlo). */
  private async countGroups(
    from: string,
    where: string[],
    params: unknown[],
  ): Promise<number> {
    const [row]: { n: number }[] = await this.db.query(
      `SELECT count(DISTINCT f.vulnerability_id)::int AS n
         FROM ${from} WHERE ${where.join(' AND ')}`,
      params,
    );
    return row?.n ?? 0;
  }

  /**
   * De quién son los findings de un asset: un contenedor no tiene propios, son los de su imagen
   * (relación `instance_of`), que se guardan una sola vez para todos sus contenedores. Con el
   * estado del escaneo si es un contenedor o una imagen, y el resumen del SBOM.
   */
  private async findingsOwner(assetId: string): Promise<{
    ownerId: string | null;
    image: ContainerImageSummary | null;
    sbom: SbomSummary | null;
  }> {
    const asset = await this.findAsset(assetId);
    let ownerId: string | null = assetId;
    if (asset.type === 'container') {
      const rel = await this.db
        .getRepository(AssetRelation)
        .findOneBy({ parentId: assetId, type: 'instance_of' });
      ownerId = rel?.childId ?? null;
    }
    const image =
      ownerId && (asset.type === 'container' || asset.type === 'image')
        ? await this.db
            .getRepository(ContainerImage)
            .findOneBy({ assetId: ownerId })
        : null;
    return {
      ownerId,
      image: image ? toImageSummary(image) : null,
      sbom: ownerId ? await this.sboms.summary(ownerId) : null,
    };
  }

  /**
   * Búsqueda de findings en todo el inventario (base de la búsqueda de CVEs). Cada finding lleva
   * los assets afectados: para una imagen, sus contenedores (recorriendo `instance_of`, sin los
   * retirados); para cualquier otro asset, él mismo.
   */
  async search(query: FindingListQueryDto): Promise<Page<FindingSearchResult>> {
    const page = await this.list(query);
    const ownerIds = [...new Set(page.items.map((f) => f.assetId))];
    const rows: (AffectedRow & { owner_id: string })[] = ownerIds.length
      ? await this.db.query(
          `SELECT o.id AS owner_id, a.id, a.name, a.type, a.status, p.parent_id
             FROM assets o
             LEFT JOIN asset_relations i
               ON o.type = 'image' AND i.child_id = o.id AND i.type = 'instance_of'
             JOIN assets a ON a.id = CASE WHEN o.type = 'image' THEN i.parent_id ELSE o.id END
             LEFT JOIN asset_relations p ON p.child_id = a.id AND p.type = 'contains'
            WHERE o.id = ANY($1::uuid[]) AND (o.type <> 'image' OR a.status <> 'retired')
            ORDER BY a.name, a.id`,
          [ownerIds],
        )
      : [];
    const owners: AffectedRow[] = ownerIds.length
      ? await this.db.query(
          `SELECT o.id, o.name, o.type, o.status, p.parent_id
             FROM assets o
             LEFT JOIN asset_relations p ON p.child_id = o.id AND p.type = 'contains'
            WHERE o.id = ANY($1::uuid[])`,
          [ownerIds],
        )
      : [];
    const ownerById = new Map(owners.map((o) => [o.id, toAffected(o)]));
    const affected = new Map<string, AffectedAsset[]>();
    for (const r of rows) {
      const list = affected.get(r.owner_id) ?? [];
      list.push(toAffected(r));
      affected.set(r.owner_id, list);
    }
    return {
      items: page.items.map((f) => ({
        ...f,
        owner: ownerById.get(f.assetId)!,
        affected: affected.get(f.assetId) ?? [],
      })),
      total: page.total,
    };
  }

  /** Findings de todo el inventario o de un asset, de más a menos graves. */
  private async list(
    query: FindingListQueryDto,
    assetId?: string,
  ): Promise<Page<FindingContract>> {
    const { where, params } = findingWhere(
      assetId
        ? { ...query, includeScanDisabled: true, includeNoise: true }
        : query,
      assetId
        ? { where: ['f.asset_id = $1'], params: [assetId] }
        : { where: [], params: [] },
    );
    const page = pageParams(params, query);
    const rows: (FindingRow & { total: number })[] = await this.db.query(
      `SELECT f.*, count(*) OVER ()::int AS total
         FROM findings f
        ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
        ORDER BY ${
          query.sort === 'severity'
            ? `array_position(${SEVERITY_RANK}, f.severity::text), f.priority DESC NULLS LAST`
            : `f.priority DESC NULLS LAST, array_position(${SEVERITY_RANK}, f.severity::text)`
        }, f.vulnerability_id, f.id
        ${page.sql}`,
      page.params,
    );
    const total =
      rows[0]?.total ??
      (
        (await this.db.query(
          `SELECT count(*)::int AS n FROM findings f
            ${where.length ? `WHERE ${where.join(' AND ')}` : ''}`,
          params,
        )) as { n: number }[]
      )[0]!.n;
    return { items: rows.map(toFinding), total };
  }

  /** Nombres públicos que llegan a alguno de estos assets (el contenedor y su imagen). */
  private async exposureOf(ids: string[]): Promise<PublicExposure | null> {
    const [row]: { n: number | null; sample: string | null }[] = await this.db.query(
      `SELECT max(e.n) AS n, min(e.names[1]) AS sample
         FROM (${EXPOSED_ASSETS_SQL}) e WHERE e.asset_id = ANY($1::uuid[])`,
      [ids],
    );
    return row?.n ? { publicDomains: row.n, sample: row.sample } : null;
  }

  private async findAsset(id: string): Promise<Asset> {
    const asset = await this.db.getRepository(Asset).findOneBy({ id });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    return asset;
  }
}

function dockerOf(asset: Asset): DockerContainerFacts | undefined {
  return asset.type === 'container'
    ? (asset.facts.docker as DockerContainerFacts | undefined)
    : undefined;
}

interface FindingRow extends AcceptanceRow {
  id: string;
  asset_id: string;
  vulnerability_id: string;
  package_name: string;
  installed_version: string;
  fixed_version: string | null;
  severity: FindingContract['severity'];
  title: string | null;
  fix_status: string | null;
  pkg_path: string | null;
  primary_url: string | null;
  status: FindingContract['status'];
  first_seen_at: Date;
  last_seen_at: Date;
  fixed_at: Date | null;
  cvss_score: number | null;
  priority: number | null;
  priority_reasons: PriorityReason[] | null;
  noise_reason: NoiseReason | null;
}

function toFinding(f: FindingRow): FindingContract {
  return {
    id: f.id,
    assetId: f.asset_id,
    vulnerabilityId: f.vulnerability_id,
    packageName: f.package_name,
    installedVersion: f.installed_version,
    fixedVersion: f.fixed_version,
    severity: f.severity,
    title: f.title,
    fixStatus: f.fix_status,
    pkgPath: f.pkg_path,
    primaryUrl: f.primary_url,
    status: f.status,
    firstSeenAt: f.first_seen_at.toISOString(),
    lastSeenAt: f.last_seen_at.toISOString(),
    fixedAt: f.fixed_at?.toISOString() ?? null,
    cvss: f.cvss_score,
    priority: priorityInfo(f.priority, f.priority_reasons),
    noiseReason: f.noise_reason,
    acceptance: acceptanceOf(f),
  };
}

/** Severidad máxima, título, referencia y parche de un grupo de findings del mismo CVE. */
const GROUP_COLUMNS = `
  ${PAGE_RANK} AS rank,
  (array_agg(f.title ORDER BY f.title) FILTER (WHERE f.title IS NOT NULL))[1] AS title,
  (array_agg(f.primary_url ORDER BY f.primary_url) FILTER (WHERE f.primary_url IS NOT NULL))[1] AS primary_url,
  bool_or(f.fixed_version IS NOT NULL) AS fixable,
  ${GROUP_PRIORITY} AS priority,
  (array_agg(f.priority_reasons ORDER BY ${GROUP_FIRST}, f.id))[1] AS reasons,
  CASE WHEN bool_and(f.noise_reason IS NOT NULL)
       THEN (array_agg(f.noise_reason ORDER BY f.priority DESC NULLS LAST, f.id))[1] END
    AS noise_reason,
  max(f.cvss_score) AS cvss,
  bool_or(vi.in_kev) AS kev,
  max(vi.epss) AS epss`;

/** KEV y EPSS del CVE (alias `vi`, para GROUP_COLUMNS). */
const INTEL_JOIN = `LEFT JOIN vulnerability_intel vi ON vi.vulnerability_id = f.vulnerability_id`;

function toGroup(r: VulnerabilityGroupRow) {
  return {
    vulnerabilityId: r.vulnerability_id,
    severity: SEVERITY_BY_RANK[r.rank - 1]!,
    title: r.title,
    primaryUrl: r.primary_url,
    fixable: r.fixable,
    priority: priorityInfo(r.priority, r.reasons),
    noiseReason: r.noise_reason,
    cvss: r.cvss,
    kev: r.kev === true,
    epss: r.epss,
  };
}

/** LIMIT/OFFSET como los dos últimos parámetros. */
function pageParams(
  params: unknown[],
  query: { limit?: number; offset?: number },
): { sql: string; params: unknown[] } {
  const all = [...params, query.limit ?? DEFAULT_LIMIT, query.offset ?? 0];
  return {
    sql: `LIMIT $${all.length - 1} OFFSET $${all.length}`,
    params: all,
  };
}

export interface VulnerabilitiesByAssetRow {
  id: string;
  name: string;
  type: string;
  projects: string[];
  cves: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  fixable: number;
  findings: {
    id: string;
    severity: string;
    package: string;
    installed: string;
    fixed: string | null;
    status: string;
  }[];
  containers: string[];
}

interface AffectedRow {
  id: string;
  name: string;
  type: AffectedAsset['type'];
  status: AffectedAsset['status'];
  parent_id: string | null;
}

function toAffected(r: AffectedRow): AffectedAsset {
  return {
    id: r.id,
    name: r.name,
    type: r.type,
    status: r.status,
    parentId: r.parent_id,
  };
}

function toImageSummary(i: ContainerImage): ContainerImageSummary {
  return {
    assetId: i.assetId,
    imageId: i.imageId,
    repoDigests: i.repoDigests,
    repoTags: i.repoTags,
    platform: i.platform,
    scanStatus: i.scanStatus,
    scanReason: i.scanReason,
    scannedAt: i.scannedAt?.toISOString() ?? null,
    scanSource: i.scanSource,
    trivyVersion: i.trivyVersion,
    dbUpdatedAt: i.dbUpdatedAt?.toISOString() ?? null,
    vulnerabilityCount: i.vulnerabilityCount,
  };
}
