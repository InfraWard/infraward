import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Project } from '@infraward/domain';
import {
  DEFAULT_DASHBOARD,
  projectDashboardTemplate,
  validateDashboardLayout,
  type DashboardDocument,
  type DashboardLayout,
  type SaveDashboardRequest,
} from '@infraward/shared-types';
import { DataSource, type EntityManager } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import { Dashboard } from './dashboard.entity.js';

/** Panel personal (`ownerUserId`) o de un proyecto (`projectId`). */
type Owner = { ownerUserId: string } | { projectId: string };

const STALE =
  'El panel ha cambiado desde que lo abriste (otra pestaña u otra persona). Recarga y vuelve a aplicar tus cambios.';

/**
 * Paneles guardados (QoL-8, DESIGN §15): uno por usuario y uno por proyecto, con concurrencia
 * optimista por `version`. Sin fila, el por defecto; restablecer borra la fila.
 */
@Injectable()
export class DashboardsService {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly audit: AuditService,
  ) {}

  getMine(userId: string): Promise<DashboardDocument> {
    return this.get({ ownerUserId: userId }, DEFAULT_DASHBOARD);
  }

  async saveMine(
    userId: string,
    body: SaveDashboardRequest,
  ): Promise<DashboardDocument> {
    const layout = this.validate(body.layout);
    await this.db.transaction((m) =>
      this.save(m, { ownerUserId: userId }, layout, body.version, userId),
    );
    return this.getMine(userId);
  }

  async resetMine(userId: string): Promise<DashboardDocument> {
    await this.db.getRepository(Dashboard).delete({ ownerUserId: userId });
    return this.getMine(userId);
  }

  async getProject(projectId: string): Promise<DashboardDocument> {
    await this.findProject(this.db.manager, projectId);
    return this.get({ projectId }, projectDashboardTemplate(projectId));
  }

  async saveProject(
    projectId: string,
    body: SaveDashboardRequest,
    actor: AuditActor,
  ): Promise<DashboardDocument> {
    const layout = this.validate(body.layout, projectId);
    await this.db.transaction(async (m) => {
      const project = await this.findProject(m, projectId);
      const version = await this.save(
        m,
        { projectId },
        layout,
        body.version,
        actor.actorId,
      );
      await this.audit.record(actor, 'project.dashboard_updated', {
        target: { type: 'project', id: projectId, label: project.name },
        details: {
          widgets: layout.widgets.map((w) => w.type),
          version,
        },
        manager: m,
      });
    });
    return this.getProject(projectId);
  }

  async resetProject(
    projectId: string,
    actor: AuditActor,
  ): Promise<DashboardDocument> {
    await this.db.transaction(async (m) => {
      const project = await this.findProject(m, projectId);
      const { affected } = await m.delete(Dashboard, { projectId });
      if (affected)
        await this.audit.record(actor, 'project.dashboard_reset', {
          target: { type: 'project', id: projectId, label: project.name },
          manager: m,
        });
    });
    return this.getProject(projectId);
  }

  private async get(
    owner: Owner,
    fallback: DashboardLayout,
  ): Promise<DashboardDocument> {
    const row = await this.db.getRepository(Dashboard).findOne({
      where: owner,
      relations: { updatedBy: true },
    });
    if (!row)
      return {
        layout: fallback,
        isDefault: true,
        version: 0,
        updatedAt: null,
        updatedBy: null,
      };
    // Lo guardado se vuelve a normalizar: si el catálogo cambió, valen los valores por defecto.
    const checked = validateDashboardLayout(
      row.layout,
      'projectId' in owner ? owner.projectId : undefined,
    );
    return {
      layout: checked.ok ? checked.layout : fallback,
      isDefault: !checked.ok,
      version: row.version,
      updatedAt: row.updatedAt.toISOString(),
      updatedBy: row.updatedBy?.name ?? null,
    };
  }

  private validate(input: unknown, projectId?: string): DashboardLayout {
    const checked = validateDashboardLayout(input, projectId);
    if (!checked.ok) throw new BadRequestException(checked.error);
    return checked.layout;
  }

  /**
   * Guarda si `version` es la que hay (0 = aún no hay fila); si no, 409. Devuelve la nueva.
   */
  private async save(
    m: EntityManager,
    owner: Owner,
    layout: DashboardLayout,
    version: number,
    userId: string | null,
  ): Promise<number> {
    const [column, value] =
      'ownerUserId' in owner
        ? ['owner_user_id', owner.ownerUserId]
        : ['project_id', owner.projectId];
    if (version === 0) {
      const rows = (await m.query(
        `INSERT INTO dashboards (${column}, layout, version, updated_by_id)
         VALUES ($1, $2, 1, $3)
         ON CONFLICT (${column}) DO NOTHING
         RETURNING version`,
        [value, JSON.stringify(layout), userId],
      )) as { version: number }[];
      if (!rows.length) throw new ConflictException(STALE);
      return 1;
    }
    const [rows] = (await m.query(
      `UPDATE dashboards SET layout = $2, version = version + 1, updated_by_id = $3,
              updated_at = now()
        WHERE ${column} = $1 AND version = $4
        RETURNING version`,
      [value, JSON.stringify(layout), userId, version],
    )) as [{ version: number }[], number];
    if (!rows.length) throw new ConflictException(STALE);
    return rows[0]!.version;
  }

  private async findProject(m: EntityManager, id: string): Promise<Project> {
    const project = await m.findOne(Project, { where: { id } });
    if (!project) throw new NotFoundException('Proyecto no encontrado');
    return project;
  }
}
