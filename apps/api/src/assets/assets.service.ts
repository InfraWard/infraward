import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import {
  Asset,
  AssetRelation,
  Enrollment,
  Snapshot,
  buildTree,
  CONTAINS_LOCK,
  findAncestorRows,
  findSubtreeIds,
  findSubtreeRows,
  isSelfOrAncestor,
  recomputePolicies,
} from '@infraward/domain';
import { SecretsService } from '@infraward/secrets';
import {
  ENROLL_SSH_USER,
  TREE_HIDDEN_ASSET_TYPES,
  type Asset as AssetContract,
  type AssetRelation as AssetRelationContract,
  type AssetRelations,
  type AssetSummary,
  type AssetTreeSummaryNode,
  type CredentialRevocation,
  type DockerHostResources,
  type DockerResource,
  type DeleteAssetResponse,
  type Page,
  type Snapshot as SnapshotContract,
  type SnapshotSummary,
  filterTree,
  matchesInventoryQuery,
  parseSearchQuery,
} from '@infraward/shared-types';
import { DataSource, In, type EntityManager } from 'typeorm';
import {
  PG_CHECK_VIOLATION,
  PG_UNIQUE_VIOLATION,
  pgErrorCode,
} from '../database/pg-errors.js';
import { unenrollCommand } from '../enrollment/commands.js';
import { secretBaseRef } from '../enrollment/ssh-keys.js';
import { SshCaTrustService } from '../secrets/ssh-ca-trust.service.js';
import type {
  AssetListQueryDto,
  CreateAssetDto,
  CreateAssetRelationDto,
  PageQueryDto,
  UpdateAssetDto,
} from './assets.dto.js';
import {
  toAsset,
  toAssetSummary,
  toRelation,
  toRelationWithPeer,
  toTreeSummary,
  toSnapshot,
} from './assets.mapper.js';
import {
  openFindingsBySeverity,
  type OpenFindingCounts,
} from './open-findings.js';
import {
  TREE_EXTRAS_SELECT,
  treeExtras,
  type TreeExtrasRow,
} from './tree-extras.js';

type TreeAssetRow = TreeExtrasRow &
  Pick<
    Asset,
    | 'id'
    | 'name'
    | 'type'
    | 'status'
    | 'roles'
    | 'tags'
    | 'displayName'
    | 'discoveredName'
    | 'effectiveProjects'
  >;

const DEFAULT_LIMIT = 50;

@Injectable()
export class AssetsService {
  private readonly logger = new Logger(AssetsService.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly sshCa: SshCaTrustService,
    private readonly audit: AuditService,
  ) {}

  // --- Assets ---

  async list(query: AssetListQueryDto): Promise<Page<AssetContract>> {
    const qb = this.db.getRepository(Asset).createQueryBuilder('a');
    if (query.type) qb.andWhere('a.type = :type', { type: query.type });
    if (query.status)
      qb.andWhere('a.status = :status', { status: query.status });
    // `@>` (y no `= ANY`) para que lo resuelvan los índices GIN.
    if (query.tag)
      qb.andWhere('a.tags @> ARRAY[:tag]::text[]', { tag: query.tag });
    if (query.role)
      qb.andWhere('a.roles @> ARRAY[:role]::text[]', { role: query.role });
    if (query.projectId)
      qb.andWhere('a.effective_projects @> ARRAY[:projectId]::uuid[]', {
        projectId: query.projectId,
      });
    if (query.q)
      qb.andWhere(
        `(a.name ILIKE :q ESCAPE '\\' OR a.discovered_name ILIKE :q ESCAPE '\\')`,
        { q: `%${query.q.replace(/[\\%_]/g, '\\$&')}%` },
      );
    if (query.facts)
      qb.andWhere('a.facts @> :facts::jsonb', {
        facts: JSON.stringify(parseFactsFilter(query.facts)),
      });

    const [assets, total] = await qb
      .orderBy('a.name', 'ASC')
      .addOrderBy('a.id', 'ASC')
      .skip(query.offset ?? 0)
      .take(query.limit ?? DEFAULT_LIMIT)
      .getManyAndCount();
    return { items: assets.map((a) => toAsset(a)), total };
  }

  async get(id: string): Promise<AssetContract> {
    const asset = await this.findAsset(this.db.manager, id);
    const repo = this.db.getRepository(Asset);
    const select = { id: true, name: true, type: true, status: true } as const;
    const [duplicateOf, duplicates] = await Promise.all([
      asset.duplicateOfId
        ? repo.findOne({ where: { id: asset.duplicateOfId }, select })
        : null,
      repo.find({
        where: { duplicateOfId: asset.id },
        select,
        order: { name: 'ASC' },
      }),
    ]);
    return toAsset(
      asset,
      {
        duplicateOf: duplicateOf ? toAssetSummary(duplicateOf) : null,
        duplicates: duplicates.map(toAssetSummary),
      },
      { notes: true },
    );
  }

  async create(
    dto: CreateAssetDto,
    actor?: AuditActor,
  ): Promise<AssetContract> {
    const repo = this.db.getRepository(Asset);
    const asset = await this.save(() =>
      repo.save(
        repo.create({
          type: dto.type,
          // El nombre del alta hace de «descubierto»: renombrar pone displayName.
          discoveredName: dto.name,
          status: dto.status,
          naturalKey: dto.naturalKey ?? null,
          roles: dto.roles ?? [],
          tags: dto.tags ?? [],
          facts: dto.facts ?? {},
        }),
      ),
    );
    if (actor)
      await this.audit.record(actor, 'asset.created', {
        target: { type: asset.type, id: asset.id, label: asset.name },
        details: { via: 'manual', status: asset.status },
      });
    // Sus etiquetas pueden tener regla (§10).
    return toAsset(await this.recomputed(asset.id), undefined, { notes: true });
  }

  async update(
    id: string,
    dto: UpdateAssetDto,
    actor?: AuditActor,
  ): Promise<AssetContract> {
    const repo = this.db.getRepository(Asset);
    const asset = await this.findAsset(this.db.manager, id);
    const before = {
      name: asset.name,
      displayName: asset.displayName,
      status: asset.status,
      tags: [...asset.tags],
      notes: asset.notes,
    };
    const changed: string[] = [];
    for (const key of ['status', 'naturalKey', 'roles', 'facts'] as const) {
      if (dto[key] === undefined) continue;
      if (JSON.stringify(asset[key]) !== JSON.stringify(dto[key])) changed.push(key);
      Object.assign(asset, { [key]: dto[key] });
    }
    if (dto.displayName !== undefined) asset.displayName = dto.displayName;
    if (dto.tags !== undefined) asset.tags = [...new Set(dto.tags)];
    if (dto.notes !== undefined) asset.notes = dto.notes?.trim() ? dto.notes : null;
    // Un cambio de estado a mano no es de la reconciliación: contadores a cero (§10).
    if (dto.status !== undefined)
      Object.assign(asset, {
        missingRuns: 0,
        missingSince: null,
        missingScopeId: null,
        retiredAuto: false,
      });
    await this.save(() => repo.save(asset));
    const saved = await this.findAsset(this.db.manager, id);
    if (actor) {
      const target = { type: saved.type, id: saved.id, label: saved.name };
      if (changed.length > 0)
        await this.audit.record(actor, 'asset.updated', {
          target,
          // Solo los nombres de los campos (y el estado, que no es un dato sensible).
          details: {
            fields: changed,
            ...(changed.includes('status')
              ? { statusFrom: before.status, statusTo: saved.status }
              : {}),
          },
        });
      if (before.displayName !== saved.displayName)
        await this.audit.record(actor, 'asset.renamed', {
          target,
          details: {
            nameFrom: before.name,
            nameTo: saved.name,
            discoveredName: saved.discoveredName,
            restored: saved.displayName === null,
          },
        });
      const added = saved.tags.filter((t) => !before.tags.includes(t));
      const removed = before.tags.filter((t) => !saved.tags.includes(t));
      if (added.length || removed.length)
        await this.audit.record(actor, 'asset.tags_changed', {
          target,
          details: { added, removed },
        });
      // Las notas pueden llevar cualquier cosa: solo su longitud.
      if (before.notes !== saved.notes)
        await this.audit.record(actor, 'asset.notes_changed', {
          target,
          details: {
            lengthFrom: before.notes?.length ?? 0,
            lengthTo: saved.notes?.length ?? 0,
          },
        });
    }
    // Etiquetas y estado cambian la política efectiva (reglas por etiqueta, imágenes).
    return toAsset(await this.recomputed(id), undefined, { notes: true });
  }

  /** Recalcula la política efectiva del inventario (§10) y devuelve el asset al día. */
  private async recomputed(id: string): Promise<Asset> {
    return this.db.transaction(async (m) => {
      await recomputePolicies(m);
      return this.findAsset(m, id);
    });
  }

  /**
   * Retira (lógico) o purga (físico) el asset y todo su subárbol `contains`: nunca quedan
   * hijos huérfanos convertidos en raíz. Las relaciones y snapshots se borran en cascada.
   * Los enrolamientos abiertos se cancelan y, tras el commit, se borran las claves del
   * proveedor de secretos y se devuelve el comando para quitar el acceso de cada servidor.
   */
  async remove(
    id: string,
    purge: boolean,
    actor?: AuditActor,
  ): Promise<DeleteAssetResponse> {
    const { response, withCredentials } = await this.db.transaction(
      async (manager) => {
        const root = await this.findAsset(manager, id);
        const { affectedIds, withCredentials } = await this.removeSubtreesIn(
          manager,
          [id],
          purge,
        );
        await recomputePolicies(manager);
        if (actor)
          await this.audit.record(actor, purge ? 'asset.purged' : 'asset.retired', {
            target: { type: root.type, id: root.id, label: root.name },
            details: { affected: affectedIds.length },
            manager,
          });
        const mode: DeleteAssetResponse['mode'] = purge ? 'purged' : 'retired';
        return { response: { mode, affectedIds }, withCredentials };
      },
    );
    return {
      ...response,
      revocations: await this.revokeAll(withCredentials, purge),
    };
  }

  /**
   * Retira o purga los subárboles `contains` de `rootIds` en la transacción `manager`, sin
   * recalcular la política ni auditar (lo hace quien llama: la baja de uno o la de un lote).
   * Devuelve los afectados y los que tienen credenciales que revocar tras el commit
   * (`revokeAll`).
   */
  async removeSubtreesIn(
    manager: EntityManager,
    rootIds: readonly string[],
    purge: boolean,
  ): Promise<{ affectedIds: string[]; withCredentials: Asset[] }> {
    const affected = new Set<string>();
    for (const rootId of rootIds)
      for (const id of await findSubtreeIds(manager, rootId)) affected.add(id);
    const affectedIds = [...affected];
    if (affectedIds.length === 0) return { affectedIds, withCredentials: [] };
    const withCredentials = (
      await manager.findBy(Asset, { id: In(affectedIds) })
    ).filter(
      (a) =>
        a.credentials.sshPrivateKey ||
        a.credentials.apiToken ||
        (a.sshAuth === 'ca_certificate' && a.connection),
    );
    await manager.update(
      Enrollment,
      {
        assetId: In(affectedIds),
        status: In(['pending', 'confirmed', 'failed']),
      },
      { status: 'cancelled', tokenHash: null },
    );
    if (purge) {
      await manager.delete(Asset, { id: In(affectedIds) });
    } else {
      // Baja a mano: no vuelve sola aunque reaparezca (§10).
      await manager.update(
        Asset,
        { id: In(affectedIds) },
        { status: 'retired', retiredAuto: false },
      );
    }
    return { affectedIds, withCredentials };
  }

  /** Tras el commit de una baja: borra las claves y prepara los comandos para los servidores. */
  async revokeAll(
    assets: readonly Asset[],
    purged: boolean,
  ): Promise<CredentialRevocation[]> {
    const revocations: CredentialRevocation[] = [];
    for (const asset of assets)
      revocations.push(await this.revokeCredentials(asset, purged));
    return revocations;
  }

  /**
   * Borra la clave privada del proveedor. Si falla, en un asset retirado se conserva la
   * referencia para reintentar con otro DELETE; en uno purgado queda huérfana y se avisa.
   */
  private async revokeCredentials(
    asset: Asset,
    purged: boolean,
  ): Promise<CredentialRevocation> {
    // Conector de dominios: su token (no hay servidor al que quitarle el acceso).
    if (asset.credentials.apiToken)
      return {
        assetId: asset.id,
        secretRemoved: await this.removeSecret(asset, asset.credentials.apiToken, purged),
        command: '',
      };
    const command = unenrollCommand(
      asset.id,
      asset.connection?.user ?? ENROLL_SSH_USER,
      asset.sshAuth,
    );
    const ref = asset.credentials.sshPrivateKey;
    // Modo CA: no hay clave permanente que borrar; solo el comando para el servidor.
    if (!ref) return { assetId: asset.id, secretRemoved: true, command };
    const secretRemoved = await this.removeSecret(asset, ref, purged);
    return { assetId: asset.id, secretRemoved, command };
  }

  /** Borra la ruta del secreto y, si el asset sigue (retirado), su referencia. */
  private async removeSecret(
    asset: Asset,
    ref: string,
    purged: boolean,
  ): Promise<boolean> {
    try {
      await this.secrets.remove(secretBaseRef(ref));
      if (!purged) {
        await this.db
          .getRepository(Asset)
          .update({ id: asset.id }, { credentials: {} });
      }
      return true;
    } catch (error) {
      // La referencia no es secreta; el error de SecretsService nunca lleva valores.
      this.logger.warn(
        `No se pudo borrar ${secretBaseRef(ref)} del asset ${asset.id}: ${(error as Error).message}`,
      );
      return false;
    }
  }

  // --- Árbol ---

  /** Bosque completo: cada raíz (asset sin padre `contains`) con sus descendientes. */
  async forest(includeRetired = false): Promise<AssetTreeSummaryNode[]> {
    const rows = await findSubtreeRows(this.db.manager, 'roots', {
      excludeStatuses: includeRetired ? [] : ['retired'],
      excludeTypes: TREE_HIDDEN_ASSET_TYPES,
    });
    return this.assembleTree(rows);
  }

  /**
   * El bosque filtrado por la búsqueda del árbol (`?q=`, DESIGN §15): lo que cumple y sus
   * antepasados. Lo que el parser no entiende se ignora (nunca da error).
   */
  async searchForest(
    q: string,
    includeRetired = false,
  ): Promise<AssetTreeSummaryNode[]> {
    const forest = await this.forest(includeRetired);
    const parsed = parseSearchQuery(q, 'inventory');
    if (!parsed.terms.length) return forest;
    const projects = await this.db.query<{ id: string; name: string }[]>(
      'SELECT id, name FROM projects',
    );
    return filterTree(forest, (node) =>
      matchesInventoryQuery(node, parsed, { projects }),
    ).nodes;
  }

  async subtree(
    id: string,
    includeRetired = false,
  ): Promise<AssetTreeSummaryNode> {
    await this.findAsset(this.db.manager, id);
    const rows = await findSubtreeRows(this.db.manager, [id], {
      excludeStatuses: includeRetired ? [] : ['retired'],
      excludeTypes: TREE_HIDDEN_ASSET_TYPES,
    });
    const [root] = await this.assembleTree(rows);
    if (!root) throw new NotFoundException('Asset no encontrado');
    return root;
  }

  /**
   * Monta el árbol resumido: de los facts y la conexión solo lee las rutas que dan la dirección y
   * el estado de ejecución (nunca los facts completos ni las credenciales), más los findings abiertos.
   */
  private async assembleTree(
    rows: { id: string; parentId: string | null }[],
  ): Promise<AssetTreeSummaryNode[]> {
    const ids = rows.map((r) => r.id);
    const [assets, findings] = ids.length
      ? await Promise.all([
          this.db.query<TreeAssetRow[]>(
            `SELECT a.id, a.name, a.type, a.status, a.roles, a.tags,
                    a.display_name AS "displayName", a.discovered_name AS "discoveredName",
                    a.effective_projects AS "effectiveProjects", ${TREE_EXTRAS_SELECT}
               FROM assets a
              WHERE a.id = ANY($1::uuid[])`,
            [ids],
          ),
          openFindingsBySeverity(this.db.manager, ids),
        ])
      : [[], new Map<string, OpenFindingCounts>()];
    // Las CA vigentes solo hacen falta si hay algún asset en modo CA.
    const caFingerprints = assets.some((a) => a.ssh_auth === 'ca_certificate')
      ? await this.sshCa.currentFingerprints()
      : [];
    const byId = new Map(
      assets.map((a) => [
        a.id,
        toTreeSummary(a, treeExtras(a, caFingerprints), findings.get(a.id)),
      ]),
    );
    return buildTree(
      rows.flatMap((r) => {
        const node = byId.get(r.id);
        // Puede faltar si se borró entre las dos consultas.
        return node ? [{ node, parentId: r.parentId }] : [];
      }),
    );
  }

  /** Antepasados `contains` del asset, de la raíz al padre (para las migas de la ficha). */
  async ancestors(id: string): Promise<AssetSummary[]> {
    await this.findAsset(this.db.manager, id);
    const rows = await findAncestorRows(this.db.manager, id);
    if (rows.length === 0) return [];
    const assets = await this.db.getRepository(Asset).find({
      select: { id: true, name: true, type: true, status: true },
      where: { id: In(rows.map((r) => r.id)) },
    });
    const byId = new Map(assets.map((a) => [a.id, toAssetSummary(a)]));
    return rows
      .toSorted((a, b) => b.depth - a.depth)
      .flatMap((r) => byId.get(r.id) ?? []);
  }

  // --- Relaciones ---

  /**
   * Volúmenes y redes (hijos `contains`) e imágenes (`stores`) de un host Docker, con cuántos
   * contenedores activos los usan: los que no usa ninguno salen «sin uso». No retirados.
   */
  async dockerResources(id: string): Promise<DockerHostResources> {
    await this.findAsset(this.db.manager, id);
    const rows: (AssetSummary & { containers: number })[] = await this.db
      .query(
        `SELECT a.id, a.name, a.type, a.status,
                (SELECT count(DISTINCT u.parent_id)::int
                   FROM asset_relations u
                   JOIN assets c ON c.id = u.parent_id AND c.type = 'container' AND c.status = 'active'
                  WHERE u.child_id = a.id AND u.type IN ('mounts', 'attached_to', 'instance_of')
                ) AS containers
           FROM asset_relations r
           JOIN assets a ON a.id = r.child_id
          WHERE r.parent_id = $1 AND a.status <> 'retired'
            AND ((r.type = 'contains' AND a.type IN ('volume', 'network'))
                 OR (r.type = 'stores' AND a.type = 'image'))
          ORDER BY a.name, a.id`,
        [id],
      );
    const of = (type: string): DockerResource[] =>
      rows
        .filter((r) => r.type === type)
        .map(({ id: rid, name, type: t, status, containers }) => ({
          id: rid,
          name,
          type: t,
          status,
          containers,
          inUse: containers > 0,
        }));
    return {
      volumes: of('volume'),
      networks: of('network'),
      images: of('image'),
    };
  }

  async relations(id: string): Promise<AssetRelations> {
    await this.findAsset(this.db.manager, id);
    const repo = this.db.getRepository(AssetRelation);
    const order = { createdAt: 'ASC' } as const;
    // Del otro extremo solo el resumen: nunca facts ni credenciales.
    const peer = { id: true, name: true, type: true, status: true } as const;
    const base = {
      id: true,
      parentId: true,
      childId: true,
      type: true,
      createdAt: true,
    } as const;
    const [outgoing, incoming] = await Promise.all([
      repo.find({
        select: { ...base, child: peer },
        relations: { child: true },
        where: { parentId: id },
        order,
      }),
      repo.find({
        select: { ...base, parent: peer },
        relations: { parent: true },
        where: { childId: id },
        order,
      }),
    ]);
    return {
      outgoing: outgoing.map((r) => toRelationWithPeer(r, r.child!)),
      incoming: incoming.map((r) => toRelationWithPeer(r, r.parent!)),
    };
  }

  createRelation(dto: CreateAssetRelationDto): Promise<AssetRelationContract> {
    if (dto.parentId === dto.childId)
      throw new ConflictException(
        'Un asset no puede relacionarse consigo mismo',
      );

    return this.db.transaction(async (manager) => {
      if (dto.type === 'contains') {
        await manager.query('SELECT pg_advisory_xact_lock($1)', [
          CONTAINS_LOCK,
        ]);
      }
      await this.findAsset(manager, dto.parentId);
      await this.findAsset(manager, dto.childId);

      if (dto.type === 'contains') {
        const hasParent = await manager.existsBy(AssetRelation, {
          childId: dto.childId,
          type: 'contains',
        });
        if (hasParent)
          throw new ConflictException('El asset hijo ya tiene un padre');
        if (await isSelfOrAncestor(manager, dto.childId, dto.parentId))
          throw new ConflictException('La relación crearía un ciclo');
      }

      const repo = manager.getRepository(AssetRelation);
      const relation = await this.save(() =>
        repo.save(
          repo.create({
            parentId: dto.parentId,
            childId: dto.childId,
            type: dto.type,
          }),
        ),
      );
      // La política se hereda por `contains` y las imágenes por quien las usa (§10).
      await recomputePolicies(manager);
      return toRelation(relation);
    });
  }

  async removeRelation(id: string): Promise<void> {
    await this.db.transaction(async (m) => {
      const { affected } = await m.getRepository(AssetRelation).delete({ id });
      if (!affected) throw new NotFoundException('Relación no encontrada');
      await recomputePolicies(m);
    });
  }

  // --- Snapshots ---

  async snapshots(
    assetId: string,
    page: PageQueryDto,
  ): Promise<Page<SnapshotSummary>> {
    await this.findAsset(this.db.manager, assetId);
    // Solo el resumen del diff (la lista de cambios puede ser larga): la ficha la pide aparte.
    const [rows, [{ total }]]: [
      {
        id: string;
        asset_id: string;
        collected_at: Date;
        roles: string[];
        job_id: string | null;
        source: SnapshotSummary['source'];
        previous_id: string | null;
        summary: SnapshotSummary['changeSummary'];
      }[],
      { total: number }[],
    ] = await Promise.all([
      this.db.query(
        `SELECT id, asset_id, collected_at, roles, job_id, source, previous_id,
                diff->'summary' AS summary
           FROM snapshots WHERE asset_id = $1
          ORDER BY collected_at DESC, id ASC
          LIMIT $2 OFFSET $3`,
        [assetId, page.limit ?? DEFAULT_LIMIT, page.offset ?? 0],
      ),
      this.db.query(
        `SELECT count(*)::int AS total FROM snapshots WHERE asset_id = $1`,
        [assetId],
      ),
    ]);
    const items = rows.map((r) => ({
      id: r.id,
      assetId: r.asset_id,
      collectedAt: r.collected_at.toISOString(),
      roles: r.roles,
      jobId: r.job_id,
      source: r.source,
      previousId: r.previous_id,
      changeSummary: r.summary,
    }));
    return { items, total };
  }

  async snapshot(id: string): Promise<SnapshotContract> {
    const snapshot = await this.db.getRepository(Snapshot).findOneBy({ id });
    if (!snapshot) throw new NotFoundException('Snapshot no encontrado');
    return toSnapshot(snapshot);
  }

  // --- Utilidades ---

  private async findAsset(manager: EntityManager, id: string): Promise<Asset> {
    const asset = await manager.findOneBy(Asset, { id });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    return asset;
  }

  /** Traduce las violaciones de restricciones de la BD a 409. */
  private async save<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      const code = pgErrorCode(error);
      if (code === PG_UNIQUE_VIOLATION)
        throw new ConflictException(conflictMessage(error));
      if (code === PG_CHECK_VIOLATION)
        throw new ConflictException('La operación viola una restricción');
      throw error;
    }
  }
}

function conflictMessage(error: unknown): string {
  const constraint = (error as { driverError?: { constraint?: string } })
    .driverError?.constraint;
  switch (constraint) {
    case 'UQ_assets_type_natural_key':
      return 'Ya existe un asset de ese tipo con esa naturalKey';
    case 'UQ_asset_relations_contains_child':
      return 'El asset hijo ya tiene un padre';
    case 'UQ_asset_relations_parent_child_type':
      return 'La relación ya existe';
    default:
      return 'El recurso ya existe';
  }
}

/** El filtro `facts` de la query string: un objeto JSON. */
function parseFactsFilter(raw: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new BadRequestException('facts debe ser un objeto JSON');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new BadRequestException('facts debe ser un objeto JSON');
  return value as Record<string, unknown>;
}
