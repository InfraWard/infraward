import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  Asset,
  decideAlongPath,
  findAncestorRows,
  Project,
  ProjectMembership,
  recomputePolicies,
  scanEnabledSql,
  TagStyle,
  type MembershipInput,
} from '@infraward/domain';
import {
  SEVERITIES,
  type AssetProjects,
  type AssetType,
  type Project as ProjectContract,
  type ProjectDetail,
  type ProjectMembershipMode,
  type ProjectStats,
  type ProjectWithStats,
  type Severity,
  type TagInfo,
} from '@infraward/shared-types';
import { DataSource, In, type EntityManager } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import { toAssetSummary } from '../assets/assets.mapper.js';
import { isUniqueViolation } from '../database/pg-errors.js';
import type { CreateProjectDto, UpdateProjectDto } from './projects.dto.js';

/**
 * Proyectos (DESIGN §5): CRUD, filas de pertenencia (`include`/`exclude`, se heredan hacia abajo)
 * y resumen. Cada cambio de pertenencia recalcula en la misma transacción los proyectos
 * efectivos y la política (`recomputePolicies`), que es lo que leen los filtros.
 */
@Injectable()
export class ProjectsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly audit: AuditService,
  ) {}

  async list(): Promise<ProjectWithStats[]> {
    const projects = await this.db
      .getRepository(Project)
      .createQueryBuilder('p')
      .orderBy('lower(p.name)', 'ASC')
      .getMany();
    const stats = await this.stats(projects.map((p) => p.id));
    return projects.map((p) => ({
      ...toProject(p),
      stats: stats.get(p.id) ?? emptyStats(),
    }));
  }

  async get(id: string): Promise<ProjectDetail> {
    const project = await this.findProject(this.db.manager, id);
    const [stats, members] = await Promise.all([
      this.stats([id]),
      this.db.getRepository(ProjectMembership).find({
        where: { projectId: id },
        relations: { asset: true },
      }),
    ]);
    return {
      ...toProject(project),
      stats: stats.get(id) ?? emptyStats(),
      members: members
        .filter((m) => m.asset)
        .sort(
          (a, b) =>
            a.mode.localeCompare(b.mode) ||
            a.asset!.name.localeCompare(b.asset!.name),
        )
        .map((m) => ({
          asset: toAssetSummary(m.asset!),
          mode: m.mode,
          createdAt: m.createdAt.toISOString(),
        })),
    };
  }

  async create(
    dto: CreateProjectDto,
    actor?: AuditActor,
  ): Promise<ProjectContract> {
    const saved = await this.uniqueName(() =>
      this.db.transaction(async (m) => {
        const project = await m.save(
          m.create(Project, {
            name: dto.name,
            description: blankToNull(dto.description),
            color: dto.color?.toLowerCase() ?? null,
          }),
        );
        if (actor)
          await this.audit.record(actor, 'project.created', {
            target: { type: 'project', id: project.id, label: project.name },
            details: { color: project.color },
            manager: m,
          });
        return project;
      }),
    );
    return toProject(saved);
  }

  async update(
    id: string,
    dto: UpdateProjectDto,
    actor?: AuditActor,
  ): Promise<ProjectContract> {
    const saved = await this.uniqueName(() =>
      this.db.transaction(async (m) => {
        const project = await this.findProject(m, id);
        const before = { ...project };
        if (dto.name !== undefined) project.name = dto.name;
        if (dto.description !== undefined)
          project.description = blankToNull(dto.description);
        if (dto.color !== undefined)
          project.color = dto.color?.toLowerCase() ?? null;
        const changed = (['name', 'description', 'color'] as const).filter(
          (f) => before[f] !== project[f],
        );
        if (!changed.length) return project;
        const saved = await m.save(project);
        if (actor)
          await this.audit.record(actor, 'project.updated', {
            target: { type: 'project', id, label: saved.name },
            details: {
              fields: [...changed],
              ...(changed.includes('name') ? { nameFrom: before.name } : {}),
              ...(changed.includes('color')
                ? { colorFrom: before.color, colorTo: saved.color }
                : {}),
            },
            manager: m,
          });
        return saved;
      }),
    );
    return toProject(saved);
  }

  /** Borra el proyecto, sus filas y su regla de política (en cascada) y recalcula. */
  async remove(id: string, actor?: AuditActor): Promise<void> {
    await this.db.transaction(async (m) => {
      const project = await this.findProject(m, id);
      const members = await m.countBy(ProjectMembership, { projectId: id });
      await m.delete(Project, { id });
      await recomputePolicies(m);
      if (actor)
        await this.audit.record(actor, 'project.deleted', {
          target: { type: 'project', id, label: project.name },
          details: { members },
          manager: m,
        });
    });
  }

  /** Crea o cambia la fila directa de un asset (`include` o la excepción `exclude`). */
  async setMember(
    projectId: string,
    assetId: string,
    mode: ProjectMembershipMode,
    actor?: AuditActor,
  ): Promise<ProjectDetail> {
    await this.db.transaction(async (m) => {
      const project = await this.findProject(m, projectId);
      const asset = await this.findAsset(m, assetId);
      const existing = await m.findOneBy(ProjectMembership, {
        projectId,
        assetId,
      });
      if (existing?.mode === mode) return;
      await m.save(
        m.create(ProjectMembership, { projectId, assetId, mode }),
      );
      await recomputePolicies(m);
      if (actor)
        await this.audit.record(actor, 'project.member_set', {
          target: { type: asset.type, id: asset.id, label: asset.name },
          details: {
            projectId,
            project: project.name,
            mode,
            modeFrom: existing?.mode ?? null,
          },
          manager: m,
        });
    });
    return this.get(projectId);
  }

  async removeMember(
    projectId: string,
    assetId: string,
    actor?: AuditActor,
  ): Promise<ProjectDetail> {
    await this.db.transaction(async (m) => {
      const project = await this.findProject(m, projectId);
      const asset = await this.findAsset(m, assetId);
      const existing = await m.findOneBy(ProjectMembership, {
        projectId,
        assetId,
      });
      if (!existing) return;
      await m.delete(ProjectMembership, { projectId, assetId });
      await recomputePolicies(m);
      if (actor)
        await this.audit.record(actor, 'project.member_removed', {
          target: { type: asset.type, id: asset.id, label: asset.name },
          details: { projectId, project: project.name, mode: existing.mode },
          manager: m,
        });
    });
    return this.get(projectId);
  }

  /**
   * Fila directa de un asset en la transacción `m` (`inherit` la quita), sin recalcular ni
   * auditar: para las operaciones en lote (QoL-6). Devuelve el modo anterior, o undefined si no
   * cambió nada.
   */
  async applyMemberIn(
    m: EntityManager,
    projectId: string,
    assetId: string,
    mode: ProjectMembershipMode | 'inherit',
  ): Promise<ProjectMembershipMode | null | undefined> {
    const existing = await m.findOneBy(ProjectMembership, {
      projectId,
      assetId,
    });
    if (mode === 'inherit') {
      if (!existing) return undefined;
      await m.delete(ProjectMembership, { projectId, assetId });
      return existing.mode;
    }
    if (existing?.mode === mode) return undefined;
    await m.save(m.create(ProjectMembership, { projectId, assetId, mode }));
    return existing?.mode ?? null;
  }

  /** Proyectos de un asset con el motivo (fila propia, heredado de un antepasado o imagen). */
  async assetProjects(assetId: string): Promise<AssetProjects> {
    const m = this.db.manager;
    const asset = await this.findAsset(m, assetId);
    const own = await m.findBy(ProjectMembership, { assetId });
    const ids = [
      ...new Set([...asset.effectiveProjects, ...own.map((r) => r.projectId)]),
    ];
    const projects = new Map(
      (ids.length ? await m.findBy(Project, { id: In(ids) }) : []).map((p) => [
        p.id,
        p,
      ]),
    );
    let decided = new Map<string, { assetId: string }>();
    if (asset.type !== 'image') {
      const path = [
        asset.id,
        ...(await findAncestorRows(m, asset.id)).map((r) => r.id),
      ];
      const rows: MembershipInput[] = await m
        .getRepository(ProjectMembership)
        .find({ where: { assetId: In(path) } });
      const byAsset = new Map<string, MembershipInput[]>();
      for (const r of rows)
        byAsset.set(r.assetId, [...(byAsset.get(r.assetId) ?? []), r]);
      decided = decideAlongPath(path, byAsset);
    }
    const fromIds = [...decided.values()]
      .map((d) => d.assetId)
      .filter((id) => id !== asset.id);
    const fromAssets = new Map(
      (fromIds.length ? await m.findBy(Asset, { id: In(fromIds) }) : []).map(
        (a) => [a.id, a],
      ),
    );
    const ownModes = new Map(own.map((r) => [r.projectId, r.mode]));
    return {
      projects: asset.effectiveProjects
        .flatMap((id) => {
          const project = projects.get(id);
          if (!project) return [];
          const by = decided.get(id)?.assetId;
          const from = by && by !== asset.id ? fromAssets.get(by) : undefined;
          return [
            {
              ...toProject(project),
              source:
                ownModes.get(id) === 'include'
                  ? ({ kind: 'direct' } as const)
                  : from
                    ? ({ kind: 'inherited', from: toAssetSummary(from) } as const)
                    : ({ kind: 'holders' } as const),
            },
          ];
        })
        .sort((a, b) => a.name.localeCompare(b.name)),
      excluded: own
        .filter((r) => r.mode === 'exclude' && projects.has(r.projectId))
        .map((r) => toProject(projects.get(r.projectId)!))
        .sort((a, b) => a.name.localeCompare(b.name)),
    };
  }

  // --- Tags ---

  /** Tags en uso (en assets no retirados) y los que tienen color, para autocompletar. */
  async tags(): Promise<TagInfo[]> {
    const rows: { tag: string; assets: number; color: string | null }[] =
      await this.db.query(
        `SELECT COALESCE(u.tag, s.tag) AS tag, COALESCE(u.n, 0)::int AS assets, s.color
           FROM (SELECT t AS tag, count(*) AS n
                   FROM assets a, unnest(a.tags) AS t
                  WHERE a.status <> 'retired'
                  GROUP BY t) u
           FULL JOIN tag_styles s ON s.tag = u.tag
          ORDER BY lower(COALESCE(u.tag, s.tag))`,
      );
    return rows;
  }

  async setTagStyle(
    tag: string,
    color: string | null,
    actor?: AuditActor,
  ): Promise<TagInfo> {
    await this.db.transaction(async (m) => {
      const before = await m.findOneBy(TagStyle, { tag });
      const next = color?.toLowerCase() ?? null;
      if ((before?.color ?? null) === next) return;
      if (next) await m.save(m.create(TagStyle, { tag, color: next }));
      else await m.delete(TagStyle, { tag });
      if (actor)
        await this.audit.record(actor, 'tag.style_changed', {
          target: { type: 'tag', label: tag },
          details: { colorFrom: before?.color ?? null, colorTo: next },
          manager: m,
        });
    });
    return (
      (await this.tags()).find((t) => t.tag === tag) ?? {
        tag,
        assets: 0,
        color: null,
      }
    );
  }

  /**
   * Borra un tag: se quita de todos los assets (retirados incluidos) y se olvida su color, en una
   * transacción con el recálculo de la política. Las reglas por etiqueta (de política y de
   * acceso) se conservan: vuelven a valer si alguien pone otra vez el tag.
   */
  async deleteTag(tag: string, actor: AuditActor): Promise<{ assets: number }> {
    return this.db.transaction(async (m) => {
      const rows: { id: string }[] = await m.query(
        `WITH changed AS (
           UPDATE assets SET tags = array_remove(tags, $1) WHERE $1 = ANY(tags) RETURNING id
         )
         SELECT id FROM changed`,
        [tag],
      );
      const style = await m.findOneBy(TagStyle, { tag });
      if (rows.length === 0 && !style) throw new NotFoundException('El tag no existe');
      if (style) await m.delete(TagStyle, { tag });
      if (rows.length) await recomputePolicies(m);
      await this.audit.record(actor, 'tag.deleted', {
        target: { type: 'tag', label: tag },
        details: { assets: rows.length, ...(style && { color: style.color }) },
        manager: m,
      });
      return { assets: rows.length };
    });
  }

  // --- Resumen ---

  /**
   * Assets no retirados por tipo y findings abiertos (de dueños que escanean) de cada proyecto,
   * con lo heredado: una consulta por métrica para todos los proyectos a la vez.
   */
  private async stats(ids: string[]): Promise<Map<string, ProjectStats>> {
    const result = new Map<string, ProjectStats>(
      ids.map((id) => [id, emptyStats()]),
    );
    if (!ids.length) return result;
    const [types, findings, cves]: [
      { project_id: string; type: AssetType; n: number }[],
      { project_id: string; severity: Severity; n: number; fixable: number }[],
      { project_id: string; n: number }[],
    ] = await Promise.all([
      this.db.query(
        `SELECT p AS project_id, a.type, count(*)::int AS n
           FROM assets a, unnest(a.effective_projects) AS p
          WHERE a.status <> 'retired' AND p = ANY($1::uuid[])
          GROUP BY p, a.type`,
        [ids],
      ),
      this.db.query(
        `SELECT p AS project_id, f.severity, count(*)::int AS n,
                count(*) FILTER (WHERE f.fixed_version IS NOT NULL)::int AS fixable
           FROM findings f JOIN assets o ON o.id = f.asset_id,
                unnest(o.effective_projects) AS p
          WHERE f.status = 'open' AND o.status <> 'retired' AND ${scanEnabledSql('o')}
            AND p = ANY($1::uuid[])
          GROUP BY p, f.severity`,
        [ids],
      ),
      this.db.query(
        `SELECT p AS project_id, count(DISTINCT f.vulnerability_id)::int AS n
           FROM findings f JOIN assets o ON o.id = f.asset_id,
                unnest(o.effective_projects) AS p
          WHERE f.status = 'open' AND o.status <> 'retired' AND ${scanEnabledSql('o')}
            AND p = ANY($1::uuid[])
          GROUP BY p`,
        [ids],
      ),
    ]);
    for (const r of types) {
      const s = result.get(r.project_id)!;
      s.assetsByType[r.type] = r.n;
      s.assets += r.n;
    }
    for (const r of findings) {
      const s = result.get(r.project_id)!;
      s.openFindings[r.severity] = r.n;
      if (r.severity === 'CRITICAL' || r.severity === 'HIGH')
        s.fixableFindings[r.severity] = r.fixable;
    }
    for (const r of cves) result.get(r.project_id)!.openVulnerabilities = r.n;
    return result;
  }

  private async uniqueName<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      if (isUniqueViolation(error))
        throw new ConflictException('Ya hay un proyecto con ese nombre');
      throw error;
    }
  }

  private async findProject(m: EntityManager, id: string): Promise<Project> {
    const project = await m.findOneBy(Project, { id });
    if (!project) throw new NotFoundException('Proyecto no encontrado');
    return project;
  }

  private async findAsset(m: EntityManager, id: string): Promise<Asset> {
    const asset = await m.findOneBy(Asset, { id });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    return asset;
  }
}

function emptyStats(): ProjectStats {
  return {
    assetsByType: {},
    assets: 0,
    openFindings: Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<
      Severity,
      number
    >,
    fixableFindings: { CRITICAL: 0, HIGH: 0 },
    openVulnerabilities: 0,
  };
}

function blankToNull(text: string | null | undefined): string | null {
  return text?.trim() ? text.trim() : null;
}

export function toProject(project: Project): ProjectContract {
  return {
    id: project.id,
    name: project.name,
    description: project.description,
    color: project.color,
    createdAt: project.createdAt.toISOString(),
    updatedAt: project.updatedAt.toISOString(),
  };
}
