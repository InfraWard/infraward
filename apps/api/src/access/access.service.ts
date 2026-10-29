import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Asset, findAncestorRows, Project } from '@infraward/domain';
import {
  accessRuleApplies,
  canAccess,
  hasPermission,
  USER_ROLES,
  type AccessAssetContext,
  type AccessPermission,
  type AccessPolicyRule,
  type AssetAccess,
  type AssetAccessEntry,
} from '@infraward/shared-types';
import { DataSource, In, type EntityManager } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import type { AccessChecker } from '../auth/access-checker.js';
import type { AuthenticatedUser } from '../auth/authenticated-user.js';
import { isUniqueViolation } from '../database/pg-errors.js';
import { User } from '../users/user.entity.js';
import { AccessPolicy } from './access-policy.entity.js';
import type { CreateAccessPolicyDto } from './access.dto.js';

/** Quién y dónde: lo que necesita la resolución de una regla. */
type RuleRow = Pick<
  AccessPolicy,
  'permission' | 'subjectType' | 'userId' | 'role' | 'scope' | 'assetId' | 'tag' | 'projectId'
>;

/**
 * Políticas de acceso interactivo (sesión 22, DESIGN §11): conceden `terminal.open` a una persona
 * o a un rol en un asset (y lo que contiene), una etiqueta o un proyecto. La resolución es la
 * misma función pura que explica la ficha (`canAccess` / `accessRuleApplies` de shared-types).
 */
@Injectable()
export class AccessService implements AccessChecker {
  private readonly listeners = new Set<() => void>();

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly audit: AuditService,
  ) {}

  /** Avisa de un cambio de reglas (la terminal vuelve a comprobar las sesiones abiertas). */
  onChange(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** ¿Puede `user` usar `permission` en el asset? Su rol o alguna de sus reglas. */
  async can(
    user: Pick<AuthenticatedUser, 'id' | 'role'>,
    permission: AccessPermission,
    assetId: string,
    m: EntityManager = this.db.manager,
  ): Promise<boolean> {
    if (hasPermission(user.role, permission)) return true;
    const rules = await this.rulesFor(m, user, permission);
    if (rules.length === 0) return false;
    const context = await this.context(m, assetId);
    return !!context && canAccess(user, permission, rules, context);
  }

  /** ¿Tiene esta persona alguna regla de `permission`? (sin ninguna, nada que mirar). */
  async hasAnyRule(
    user: Pick<AuthenticatedUser, 'id' | 'role'>,
    permission: AccessPermission,
  ): Promise<boolean> {
    return (await this.rulesFor(this.db.manager, user, permission)).length > 0;
  }

  async list(filter: { assetId?: string; userId?: string } = {}): Promise<AccessPolicyRule[]> {
    const rows = await this.db.getRepository(AccessPolicy).find({
      where: {
        ...(filter.userId && { userId: filter.userId }),
        ...(filter.assetId && { assetId: filter.assetId }),
      },
      relations: { user: true, asset: true, project: true, createdBy: true },
      order: { createdAt: 'ASC' },
    });
    return rows.map(toRule);
  }

  /** Concede el permiso (users.manage + reautenticación, en el controlador). */
  async create(dto: CreateAccessPolicyDto, actor: AuditActor): Promise<AccessPolicyRule> {
    const values = await this.validate(dto);
    let saved: AccessPolicy;
    try {
      saved = await this.db.transaction(async (m) => {
        const row = await m.save(
          m.create(AccessPolicy, { ...values, createdById: actor.actorId }),
        );
        await this.audit.record(actor, 'access.granted', {
          ...this.auditTarget(row, values.label),
          details: auditDetails(row, values.subjectLabel),
          manager: m,
        });
        return row;
      });
    } catch (error) {
      if (isUniqueViolation(error)) throw new ConflictException('Esa regla ya existe');
      throw error;
    }
    const row = await this.db.getRepository(AccessPolicy).findOneOrFail({
      where: { id: saved.id },
      relations: { user: true, asset: true, project: true, createdBy: true },
    });
    return toRule(row);
  }

  /** Retira el permiso: las terminales que dependían de él se cortan (vía `onChange`). */
  async remove(id: string, actor: AuditActor): Promise<void> {
    const row = await this.db.getRepository(AccessPolicy).findOne({
      where: { id },
      relations: { user: true, asset: true, project: true },
    });
    if (!row) throw new NotFoundException();
    await this.db.transaction(async (m) => {
      await m.delete(AccessPolicy, { id });
      await this.audit.record(actor, 'access.revoked', {
        ...this.auditTarget(row, row.asset?.name ?? row.project?.name ?? row.tag),
        details: auditDetails(row, row.user?.email ?? row.role),
        manager: m,
      });
    });
    this.changed();
  }

  /** Quién puede abrir terminal en el asset y por qué regla (la ficha). */
  async assetAccess(assetId: string): Promise<AssetAccess> {
    const context = await this.context(this.db.manager, assetId);
    if (!context) throw new NotFoundException('El asset no existe');
    const rules = await this.list({});
    const ancestors = context.ancestorIds.length
      ? await this.db.getRepository(Asset).find({
          select: { id: true, name: true, displayName: true },
          where: { id: In([...context.ancestorIds]) },
        })
      : [];
    const names = new Map(ancestors.map((a) => [a.id, a.displayName ?? a.name]));
    const entries: AssetAccessEntry[] = [];
    for (const rule of rules) {
      const source = accessRuleApplies(rule, context);
      if (!source) continue;
      entries.push({
        rule,
        source,
        sourceName:
          source.kind === 'inherited'
            ? (names.get(source.assetId) ?? null)
            : source.kind === 'project'
              ? rule.projectName
              : null,
      });
    }
    return {
      roles: USER_ROLES.filter((r) => hasPermission(r, 'terminal.open')),
      entries,
    };
  }

  /** Etiquetas, proyectos efectivos y antepasados `contains` del asset (null si no existe). */
  async context(m: EntityManager, assetId: string): Promise<AccessAssetContext | null> {
    const asset = await m.findOne(Asset, {
      select: { id: true, tags: true, effectiveProjects: true },
      where: { id: assetId },
    });
    if (!asset) return null;
    const ancestors = await findAncestorRows(m, assetId);
    return {
      assetId,
      ancestorIds: ancestors.map((a) => a.id),
      tags: asset.tags ?? [],
      projectIds: asset.effectiveProjects ?? [],
    };
  }

  private rulesFor(
    m: EntityManager,
    user: Pick<AuthenticatedUser, 'id' | 'role'>,
    permission: AccessPermission,
  ): Promise<RuleRow[]> {
    return m.find(AccessPolicy, {
      select: {
        permission: true,
        subjectType: true,
        userId: true,
        role: true,
        scope: true,
        assetId: true,
        tag: true,
        projectId: true,
      },
      where: [
        { permission, subjectType: 'user', userId: user.id },
        { permission, subjectType: 'role', role: user.role },
      ],
    });
  }

  /** Sujeto y objetivo existen y la regla tiene sentido. */
  private async validate(dto: CreateAccessPolicyDto) {
    const m = this.db.manager;
    let subjectLabel: string;
    if (dto.subjectType === 'user') {
      const user = await m.findOneBy(User, { id: dto.userId! });
      if (!user) throw new NotFoundException('El usuario no existe');
      if (hasPermission(user.role, dto.permission))
        throw new BadRequestException('Su rol ya tiene ese permiso en todos los assets');
      subjectLabel = user.email;
    } else {
      if (hasPermission(dto.role!, dto.permission))
        throw new BadRequestException('Ese rol ya tiene el permiso en todos los assets');
      subjectLabel = dto.role!;
    }
    let label: string;
    if (dto.scope === 'asset') {
      const asset = await m.findOneBy(Asset, { id: dto.assetId! });
      if (!asset) throw new NotFoundException('El asset no existe');
      label = asset.displayName ?? asset.name;
    } else if (dto.scope === 'project') {
      const project = await m.findOneBy(Project, { id: dto.projectId! });
      if (!project) throw new NotFoundException('El proyecto no existe');
      label = project.name;
    } else label = dto.tag!;
    return {
      permission: dto.permission,
      subjectType: dto.subjectType,
      userId: dto.subjectType === 'user' ? dto.userId! : null,
      role: dto.subjectType === 'role' ? dto.role! : null,
      scope: dto.scope,
      assetId: dto.scope === 'asset' ? dto.assetId! : null,
      tag: dto.scope === 'tag' ? dto.tag! : null,
      projectId: dto.scope === 'project' ? dto.projectId! : null,
      label,
      subjectLabel,
    };
  }

  private auditTarget(row: RuleRow & { id: string }, label: string | null) {
    return {
      target:
        row.scope === 'asset'
          ? { type: 'asset', id: row.assetId, label }
          : row.scope === 'project'
            ? { type: 'project', id: row.projectId, label }
            : { type: 'access_policy', id: row.id, label },
    };
  }

  private changed(): void {
    for (const listener of this.listeners) {
      try {
        listener();
      } catch {
        // Un oyente que falla no impide avisar a los demás.
      }
    }
  }
}

function auditDetails(row: RuleRow & { id: string }, subject: string | null) {
  return {
    ruleId: row.id,
    permission: row.permission,
    subjectType: row.subjectType,
    subject,
    scope: row.scope,
    ...(row.tag && { tag: row.tag }),
  };
}

function toRule(row: AccessPolicy): AccessPolicyRule {
  return {
    id: row.id,
    permission: row.permission,
    subject:
      row.subjectType === 'user'
        ? {
            type: 'user',
            userId: row.userId!,
            email: row.user?.email ?? null,
            name: row.user?.name ?? null,
          }
        : { type: 'role', role: row.role! },
    scope: row.scope,
    assetId: row.assetId,
    assetName: row.asset ? (row.asset.displayName ?? row.asset.name) : null,
    tag: row.tag,
    projectId: row.projectId,
    projectName: row.project?.name ?? null,
    createdAt: row.createdAt.toISOString(),
    createdBy: row.createdBy ? { id: row.createdBy.id, email: row.createdBy.email } : null,
  };
}
