import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { AppSetting, Asset, Notification } from '@infraward/domain';
import {
  SecretError,
  SecretNotFoundError,
  vaultEntryPath,
  vaultRefPath,
  vaultSecretRef,
  type VaultStore,
} from '@infraward/secrets';
import {
  NOTIFICATION_MAX_ITEMS,
  VAULT_ENTRY_KIND_LABELS,
  VAULT_NOT_CONFIGURED,
  VAULT_REVEAL_SECONDS,
  vaultRotationState,
  type AssetType,
  type CreateVaultEntryRequest,
  type ReplaceVaultSecretRequest,
  type RevealVaultSecretRequest,
  type RevealVaultSecretResponse,
  type UpdateVaultEntryRequest,
  type VaultEntry as VaultEntryDto,
  type VaultEntryList,
  type VaultSettings,
  type VaultStatus,
  type VaultVersion,
  type VaultVersionOrigin,
} from '@infraward/shared-types';
import { DataSource, type EntityManager } from 'typeorm';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import type { AuthenticatedUser } from '../auth/authenticated-user.js';
import { VaultEntry, VaultEntryVersion } from './vault-entry.entity.js';
import {
  normalizeVaultSettings,
  VAULT_SETTINGS_KEY,
  vaultRotationOverdue,
  vaultSettings,
} from './vault-settings.js';
import { VAULT_STORE } from './vault.tokens.js';

const DAY = 86_400_000;

/** Fila del listado (metadatos con los nombres de asset y usuarios; nunca el secreto). */
interface EntryRow {
  id: string;
  asset_id: string | null;
  asset_name: string | null;
  asset_type: AssetType | null;
  asset_roles: string[] | null;
  kind: VaultEntryDto['kind'];
  name: string;
  username: string | null;
  url: string | null;
  notes: string | null;
  has_secret: boolean;
  current_version: number | null;
  last_rotated_at: Date | null;
  rotation_days: number | null;
  created_at: Date;
  created_by: string | null;
  updated_at: Date;
  updated_by: string | null;
  deleted_at: Date | null;
  deleted_by: string | null;
}

const ENTRY_SELECT = `
  SELECT e.id, e.asset_id, a.name AS asset_name, a.type AS asset_type, a.roles AS asset_roles,
         e.kind, e.name, e.username, e.url, e.notes, (e.secret_ref IS NOT NULL) AS has_secret,
         e.current_version, e.last_rotated_at, e.rotation_days,
         e.created_at, cu.email AS created_by, e.updated_at, uu.email AS updated_by,
         e.deleted_at, du.email AS deleted_by
    FROM vault_entries e
    LEFT JOIN assets a ON a.id = e.asset_id
    LEFT JOIN users cu ON cu.id = e.created_by_id
    LEFT JOIN users uu ON uu.id = e.updated_by_id
    LEFT JOIN users du ON du.id = e.deleted_by_id`;

/**
 * Caja fuerte de credenciales (QoL-7, DESIGN §19). El valor de un secreto solo pasa por aquí al
 * guardarlo (hacia el almacén) y al revelarlo (hacia el admin que lo pidió, con step-up): nunca
 * va a la BD de la app, la auditoría, las notificaciones, los logs ni otra respuesta.
 */
@Injectable()
export class VaultService {
  private readonly logger = new Logger(VaultService.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    @Inject(VAULT_STORE) private readonly store: VaultStore | null,
    private readonly audit: AuditService,
  ) {}

  async status(): Promise<VaultStatus> {
    if (!this.store) return { provider: 'none', healthy: false, maxVersions: 0 };
    return {
      provider: this.store.provider === 'vault-openbao' ? 'openbao' : 'local',
      healthy: await this.store.healthCheck(),
      maxVersions: this.store.maxVersions,
    };
  }

  async list(query: {
    assetId?: string;
    deleted?: boolean;
    q?: string;
  }): Promise<VaultEntryList> {
    const settings = await vaultSettings(this.db.manager);
    const params: unknown[] = [];
    const where = [query.deleted ? 'e.deleted_at IS NOT NULL' : 'e.deleted_at IS NULL'];
    if (query.assetId) {
      params.push(query.assetId);
      where.push(`e.asset_id = $${params.length}`);
    }
    const q = query.q?.trim();
    if (q) {
      params.push(`%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
      const p = `$${params.length}`;
      where.push(
        `(e.name ILIKE ${p} OR e.username ILIKE ${p} OR e.url ILIKE ${p}
          OR a.name ILIKE ${p} OR a.discovered_name ILIKE ${p})`,
      );
    }
    const rows = (await this.db.query(
      `${ENTRY_SELECT} WHERE ${where.join(' AND ')}
        ORDER BY a.name NULLS LAST, e.name, e.id`,
      params,
    )) as EntryRow[];
    return {
      items: rows.map((r) => this.toDto(r, settings)),
      overdue: await vaultRotationOverdue(this.db.manager, null),
    };
  }

  async get(id: string): Promise<VaultEntryDto> {
    return this.toDto(await this.row(id), await vaultSettings(this.db.manager));
  }

  async create(
    body: CreateVaultEntryRequest,
    user: AuthenticatedUser,
    actor: AuditActor,
  ): Promise<VaultEntryDto> {
    const store = this.requireStore();
    const asset = body.assetId ? await this.asset(body.assetId) : null;
    const id = randomUUID();
    const path = vaultEntryPath(id);
    // Primero el almacén (fuera de la transacción) y luego la fila; si la fila falla, se
    // destruye lo guardado (compensación).
    const version = body.secret ? await this.put(store, path, body.secret) : null;
    try {
      await this.db.transaction(async (m) => {
        await m.insert(VaultEntry, {
          id,
          assetId: asset?.id ?? null,
          kind: body.kind,
          name: body.name,
          username: body.username ?? null,
          url: body.url ?? null,
          notes: body.notes ?? null,
          secretRef: version === null ? null : vaultSecretRef(store.provider, path),
          currentVersion: version,
          // Sin indicarla: con secreto cuenta como rotada ahora; null = sin fecha (una antigua).
          lastRotatedAt:
            body.lastRotatedAt !== undefined
              ? body.lastRotatedAt
                ? new Date(body.lastRotatedAt)
                : null
              : version === null
                ? null
                : new Date(),
          rotationDays: body.rotationDays ?? null,
          createdById: user.id,
          updatedById: user.id,
        });
        if (version !== null) await this.addVersion(m, id, version, 'created', user.id);
        await this.audit.record(actor, 'vault.created', {
          target: this.target(id, body.name),
          details: {
            entryId: id,
            kind: body.kind,
            assetId: asset?.id ?? null,
            assetName: asset?.name ?? null,
            hasValue: version !== null,
          },
          manager: m,
        });
      });
    } catch (error) {
      if (version !== null) await store.destroy(path).catch(() => undefined);
      throw error;
    }
    return this.get(id);
  }

  async update(
    id: string,
    body: UpdateVaultEntryRequest,
    user: AuthenticatedUser,
    actor: AuditActor,
  ): Promise<VaultEntryDto> {
    const entry = await this.entity(id);
    if (body.assetId) await this.asset(body.assetId);
    const changes: Record<string, unknown> = {};
    const changed: string[] = [];
    for (const key of [
      'kind',
      'name',
      'username',
      'url',
      'notes',
      'assetId',
      'rotationDays',
    ] as const) {
      if (body[key] === undefined || body[key] === entry[key]) continue;
      changes[key] = body[key];
      changed.push(key);
    }
    if (body.lastRotatedAt !== undefined) {
      const next = body.lastRotatedAt ? new Date(body.lastRotatedAt) : null;
      if (next?.getTime() !== entry.lastRotatedAt?.getTime()) {
        changes.lastRotatedAt = next;
        changed.push('lastRotatedAt');
      }
    }
    if (changed.length === 0) return this.get(id);
    await this.db.transaction(async (m) => {
      await m.update(VaultEntry, { id }, { ...changes, updatedById: user.id } as never);
      await this.audit.record(actor, 'vault.updated', {
        target: this.target(id, body.name ?? entry.name),
        // Solo qué campos: las notas y la URL pueden llevar datos que no deben ir aquí.
        details: { entryId: id, fields: changed },
        manager: m,
      });
    });
    return this.get(id);
  }

  async replaceSecret(
    id: string,
    body: ReplaceVaultSecretRequest,
    user: AuthenticatedUser,
    actor: AuditActor,
  ): Promise<VaultEntryDto> {
    const store = this.requireStore();
    const entry = await this.entity(id);
    const path = this.pathOf(entry, store);
    const version = await this.put(store, path, body.secret);
    await this.db.transaction(async (m) => {
      await m.query(
        `UPDATE vault_entries
            SET secret_ref = $2, current_version = GREATEST(COALESCE(current_version, 0), $3),
                last_rotated_at = CASE WHEN $4 THEN now() ELSE last_rotated_at END,
                updated_by_id = $5, updated_at = now()
          WHERE id = $1`,
        [id, vaultSecretRef(store.provider, path), version, body.rotated, user.id],
      );
      await this.addVersion(
        m,
        id,
        version,
        entry.secretRef ? 'replaced' : 'created',
        user.id,
      );
      await this.audit.record(actor, 'vault.secret_replaced', {
        target: this.target(id, entry.name),
        details: { entryId: id, version, rotated: body.rotated },
        manager: m,
      });
    });
    return this.get(id);
  }

  async markRotated(
    id: string,
    user: AuthenticatedUser,
    actor: AuditActor,
  ): Promise<VaultEntryDto> {
    const entry = await this.entity(id);
    await this.db.transaction(async (m) => {
      await m.update(
        VaultEntry,
        { id },
        { lastRotatedAt: new Date(), updatedById: user.id },
      );
      await this.audit.record(actor, 'vault.rotated', {
        target: this.target(id, entry.name),
        details: { entryId: id, previous: entry.lastRotatedAt?.toISOString() ?? null },
        manager: m,
      });
    });
    return this.get(id);
  }

  /** Borrado lógico: se recupera hasta que pase el plazo de los ajustes. */
  async remove(
    id: string,
    user: AuthenticatedUser,
    actor: AuditActor,
  ): Promise<VaultEntryDto> {
    const entry = await this.entity(id);
    const { deleteRetentionDays } = await vaultSettings(this.db.manager);
    await this.db.transaction(async (m) => {
      await m.update(
        VaultEntry,
        { id },
        { deletedAt: new Date(), deletedById: user.id, updatedById: user.id },
      );
      await this.audit.record(actor, 'vault.deleted', {
        target: this.target(id, entry.name),
        details: { entryId: id, retentionDays: deleteRetentionDays },
        manager: m,
      });
    });
    return this.get(id);
  }

  async restore(
    id: string,
    user: AuthenticatedUser,
    actor: AuditActor,
  ): Promise<VaultEntryDto> {
    const entry = await this.entity(id, { deleted: true });
    await this.db.transaction(async (m) => {
      await m.update(
        VaultEntry,
        { id },
        { deletedAt: null, deletedById: null, updatedById: user.id },
      );
      await this.audit.record(actor, 'vault.restored', {
        target: this.target(id, entry.name),
        details: { entryId: id },
        manager: m,
      });
    });
    return this.get(id);
  }

  /** Historial (quién y cuándo) con lo que el almacén aún conserva. Nunca los valores. */
  async versions(id: string): Promise<VaultVersion[]> {
    const entry = await this.entity(id, { deleted: 'any' });
    const stored = new Set<number>();
    if (entry.secretRef && this.store) {
      const path = this.pathOf(entry, this.store);
      for (const v of await this.call(() => this.store!.versions(path))) {
        stored.add(v.version);
      }
    }
    const rows = (await this.db.query(
      `SELECT v.version, v.origin, v.restored_from, v.created_at, u.email AS created_by
         FROM vault_entry_versions v LEFT JOIN users u ON u.id = v.created_by_id
        WHERE v.entry_id = $1 ORDER BY v.version DESC`,
      [id],
    )) as {
      version: number;
      origin: VaultVersionOrigin;
      restored_from: number | null;
      created_at: Date;
      created_by: string | null;
    }[];
    return rows.map((r) => ({
      version: r.version,
      origin: r.origin,
      restoredFrom: r.restored_from,
      createdAt: r.created_at.toISOString(),
      createdBy: r.created_by,
      current: r.version === entry.currentVersion,
      available: stored.has(r.version),
    }));
  }

  /** Copia una versión anterior como la actual (una versión más). Solo admin con step-up. */
  async restoreVersion(
    id: string,
    version: number,
    user: AuthenticatedUser,
    actor: AuditActor,
  ): Promise<VaultEntryDto> {
    const store = this.requireStore();
    const entry = await this.entity(id);
    if (!entry.secretRef) throw new NotFoundException('La entrada no tiene secreto');
    if (version === entry.currentVersion) {
      throw new BadRequestException('Esa ya es la versión actual');
    }
    const path = this.pathOf(entry, store);
    let restored: number;
    try {
      const old = await this.call(() => store.get(path, version));
      restored = await this.put(store, path, old.value);
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw new NotFoundException('El almacén ya no conserva esa versión');
      }
      throw error;
    }
    await this.db.transaction(async (m) => {
      await m.query(
        `UPDATE vault_entries
            SET current_version = GREATEST(COALESCE(current_version, 0), $2),
                updated_by_id = $3, updated_at = now()
          WHERE id = $1`,
        [id, restored, user.id],
      );
      await this.addVersion(m, id, restored, 'restored', user.id, version);
      await this.audit.record(actor, 'vault.version_restored', {
        target: this.target(id, entry.name),
        details: { entryId: id, from: version, version: restored },
        manager: m,
      });
    });
    return this.get(id);
  }

  /**
   * La única salida del valor: solo admin, con reautenticación reciente (guard) y límite de
   * intentos. Audita el revelado (y los fallos) y, si está activado, avisa a los demás admins.
   */
  async reveal(
    id: string,
    body: RevealVaultSecretRequest,
    user: AuthenticatedUser,
    actor: AuditActor,
  ): Promise<RevealVaultSecretResponse> {
    const store = this.requireStore();
    const entry = await this.entity(id, { deleted: 'any' }).catch(async (e) => {
      await this.audit.tryRecord(actor, 'vault.revealed', {
        outcome: 'failure',
        target: { type: 'vault_entry', id },
        details: { entryId: id, reason: 'not_found', purpose: body.purpose },
      });
      throw e;
    });
    const fail = async (reason: string) =>
      this.audit.tryRecord(actor, 'vault.revealed', {
        outcome: 'failure',
        target: this.target(id, entry.name),
        details: { entryId: id, reason, purpose: body.purpose },
      });
    if (entry.deletedAt) {
      await fail('deleted');
      throw new ConflictException('La entrada está en la papelera: recupérala para revelarla');
    }
    if (!entry.secretRef) {
      await fail('no_secret');
      throw new NotFoundException('La entrada no tiene secreto');
    }
    let secret: { value: string; version: number };
    try {
      secret = await this.call(() => store.get(this.pathOf(entry, store)));
    } catch (error) {
      await fail(error instanceof SecretError ? error.code : 'error');
      throw error;
    }
    // El motivo es texto libre: si alguien pega la credencial en él, no se guarda.
    let reason = body.reason?.trim() || null;
    if (reason && secret.value.length >= 4 && reason.includes(secret.value)) {
      reason = '[omitido: contenía la credencial]';
    }
    const asset = entry.assetId
      ? await this.db.manager.findOne(Asset, {
          where: { id: entry.assetId },
          select: { id: true, name: true, type: true },
        })
      : null;
    const assetName = asset?.name ?? null;
    const settings = await vaultSettings(this.db.manager);
    await this.db.transaction(async (m) => {
      await this.audit.record(actor, 'vault.revealed', {
        target: this.target(id, entry.name),
        details: {
          entryId: id,
          kind: entry.kind,
          assetId: asset?.id ?? null,
          assetName,
          version: secret.version,
          purpose: body.purpose,
          reason,
        },
        manager: m,
      });
      if (settings.notifyOnReveal) {
        const who = user.name?.trim() || user.email;
        const kind = VAULT_ENTRY_KIND_LABELS[entry.kind].toLowerCase();
        await m.insert(Notification, {
          kind: 'vault_revealed',
          assetId: asset?.id ?? null,
          assetName,
          message:
            `${who} reveló «${entry.name}» (${kind})` +
            (assetName ? ` de ${assetName}` : '') +
            (reason ? ` · motivo: ${reason}` : ''),
          items: asset
            ? [{ id: asset.id, name: assetName!, type: asset.type }].slice(
                0,
                NOTIFICATION_MAX_ITEMS,
              )
            : [],
          total: asset ? 1 : 0,
          audienceRoles: ['admin'],
          excludeUserId: user.id,
        });
      }
    });
    return {
      value: secret.value,
      version: secret.version,
      expiresInSeconds: VAULT_REVEAL_SECONDS,
    };
  }

  settings(): Promise<VaultSettings> {
    return vaultSettings(this.db.manager);
  }

  async updateSettings(body: VaultSettings, actor: AuditActor): Promise<VaultSettings> {
    const next = normalizeVaultSettings(body);
    await this.db.transaction(async (m) => {
      const before = await vaultSettings(m);
      await m.upsert(AppSetting, { key: VAULT_SETTINGS_KEY, value: next }, ['key']);
      const changes = Object.fromEntries(
        (Object.keys(next) as (keyof VaultSettings)[])
          .filter((k) => before[k] !== next[k])
          .map((k) => [k, `${before[k]} → ${next[k]}`]),
      );
      await this.audit.record(actor, 'vault.settings_changed', {
        target: { type: 'settings', label: 'Caja fuerte' },
        details: changes,
        manager: m,
      });
    });
    return next;
  }

  /**
   * Destruye (almacén y BD) las entradas borradas hace más del plazo. La llama el intervalo de
   * `VaultPurgeService`; también se puede llamar a mano (tests). Devuelve cuántas.
   */
  async purgeExpired(now: Date = new Date()): Promise<number> {
    if (!this.store) return 0;
    const store = this.store;
    const { deleteRetentionDays } = await vaultSettings(this.db.manager);
    const cutoff = new Date(now.getTime() - deleteRetentionDays * DAY);
    const expired = await this.db.manager
      .getRepository(VaultEntry)
      .createQueryBuilder('e')
      .where('e.deleted_at IS NOT NULL AND e.deleted_at <= :cutoff', { cutoff })
      .getMany();
    let purged = 0;
    const system: AuditActor = { actorId: null, actorEmail: null, ip: null };
    for (const entry of expired) {
      try {
        if (entry.secretRef) await store.destroy(this.pathOf(entry, store));
        await this.db.transaction(async (m) => {
          const [, affected] = (await m.query(
            'DELETE FROM vault_entries WHERE id = $1 AND deleted_at IS NOT NULL AND deleted_at <= $2',
            [entry.id, cutoff],
          )) as [unknown, number];
          if (!affected) return;
          purged++;
          await this.audit.record(system, 'vault.purged', {
            target: this.target(entry.id, entry.name),
            details: { entryId: entry.id, retentionDays: deleteRetentionDays },
            manager: m,
          });
        });
      } catch (error) {
        this.logger.warn(
          `No se pudo destruir la entrada ${entry.id} de la caja fuerte: ${(error as Error).name}`,
        );
      }
    }
    return purged;
  }

  // --- auxiliares ---

  private requireStore(): VaultStore {
    if (!this.store) {
      throw new ConflictException({
        statusCode: 409,
        code: VAULT_NOT_CONFIGURED,
        message:
          'La caja fuerte no está configurada (VAULT_PROVIDER): mira Ajustes › Caja fuerte',
      });
    }
    return this.store;
  }

  /** Guarda en el almacén y traduce sus errores (sin mensajes del proveedor hacia fuera). */
  private put(store: VaultStore, path: string, value: string): Promise<number> {
    return this.call(() => store.put(path, value));
  }

  private async call<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      if (error instanceof SecretNotFoundError) {
        throw new NotFoundException('El almacén no tiene ese secreto');
      }
      if (error instanceof SecretError) {
        this.logger.warn(`Caja fuerte: ${error.code}`);
        throw new ServiceUnavailableException({
          statusCode: 503,
          code: error.code,
          message: 'El almacén de la caja fuerte no responde o rechazó la operación',
        });
      }
      throw error;
    }
  }

  /** Ruta de la entrada en el almacén actual (la referencia debe ser de este almacén). */
  private pathOf(entry: VaultEntry, store: VaultStore): string {
    if (!entry.secretRef) return vaultEntryPath(entry.id);
    try {
      return vaultRefPath(entry.secretRef, store.provider);
    } catch {
      throw new ConflictException(
        'El secreto de esta entrada está en otro almacén (cambió VAULT_PROVIDER)',
      );
    }
  }

  private async entity(
    id: string,
    options: { deleted?: boolean | 'any' } = {},
  ): Promise<VaultEntry> {
    const entry = await this.db.manager.findOneBy(VaultEntry, { id });
    const deleted = options.deleted ?? false;
    if (!entry || (deleted !== 'any' && Boolean(entry.deletedAt) !== deleted)) {
      throw new NotFoundException(
        deleted === true ? 'Entrada no encontrada en la papelera' : 'Entrada no encontrada',
      );
    }
    return entry;
  }

  private async row(id: string): Promise<EntryRow> {
    const [row] = (await this.db.query(`${ENTRY_SELECT} WHERE e.id = $1`, [id])) as EntryRow[];
    if (!row) throw new NotFoundException('Entrada no encontrada');
    return row;
  }

  private async asset(id: string): Promise<{ id: string; name: string }> {
    const asset = await this.db.manager.findOne(Asset, {
      where: { id },
      select: { id: true, name: true },
    });
    if (!asset) throw new BadRequestException('El asset no existe');
    return { id: asset.id, name: asset.name };
  }

  private addVersion(
    m: EntityManager,
    entryId: string,
    version: number,
    origin: VaultVersionOrigin,
    userId: string,
    restoredFrom: number | null = null,
  ) {
    return m.insert(VaultEntryVersion, {
      entryId,
      version,
      origin,
      restoredFrom,
      createdById: userId,
    });
  }

  private target(id: string, name: string) {
    return { type: 'vault_entry', id, label: name };
  }

  private toDto(r: EntryRow, settings: VaultSettings): VaultEntryDto {
    const days = r.rotation_days ?? settings.rotationWarnDays;
    const rotation = vaultRotationState(r.last_rotated_at, days);
    return {
      id: r.id,
      kind: r.kind,
      name: r.name,
      username: r.username,
      url: r.url,
      notes: r.notes,
      asset:
        r.asset_id && r.asset_name
          ? {
              id: r.asset_id,
              name: r.asset_name,
              type: r.asset_type ?? 'server',
              roles: r.asset_roles ?? [],
            }
          : null,
      hasSecret: r.has_secret,
      currentVersion: r.current_version,
      lastRotatedAt: r.last_rotated_at?.toISOString() ?? null,
      rotationDays: r.rotation_days,
      effectiveRotationDays: days,
      rotationState: rotation.state,
      rotationDueAt: rotation.dueAt?.toISOString() ?? null,
      createdAt: r.created_at.toISOString(),
      createdBy: r.created_by,
      updatedAt: r.updated_at.toISOString(),
      updatedBy: r.updated_by,
      deletedAt: r.deleted_at?.toISOString() ?? null,
      deletedBy: r.deleted_by,
      purgeAt: r.deleted_at
        ? new Date(r.deleted_at.getTime() + settings.deleteRetentionDays * DAY).toISOString()
        : null,
    };
  }
}
