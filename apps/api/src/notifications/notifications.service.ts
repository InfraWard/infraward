import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import type {
  NotificationPage,
  NotificationUnreadCount,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';

/**
 * Las que puede ver el usuario `$n` (y su rol `$n+1`): las de todos y las de su rol (un revelado
 * de la caja fuerte, solo admins), salvo las que provocó él mismo.
 */
function visibleTo(n: number): string {
  return `(audience_roles IS NULL OR $${n + 1}::text = ANY(audience_roles))
          AND exclude_user_id IS DISTINCT FROM $${n}::uuid`;
}

/** Notificaciones del mantenimiento del inventario (DESIGN §10), leídas por usuario. */
@Injectable()
export class NotificationsService {
  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async list(
    userId: string,
    limit = 20,
    offset = 0,
  ): Promise<NotificationPage> {
    const { seen, role } = await this.viewer(userId);
    const [rows, [counts]]: [
      {
        id: string;
        kind: NotificationPage['items'][number]['kind'];
        asset_id: string | null;
        asset_name: string | null;
        message: string;
        items: NotificationPage['items'][number]['items'];
        total: number;
        created_at: Date;
      }[],
      { total: number; unread: number }[],
    ] = await Promise.all([
      this.db.query(
        `SELECT id, kind, asset_id, asset_name, message, items, total, created_at
           FROM notifications WHERE ${visibleTo(3)}
          ORDER BY created_at DESC, id LIMIT $1 OFFSET $2`,
        [limit, offset, userId, role],
      ),
      this.db.query(
        `SELECT count(*)::int AS total,
                count(*) FILTER (WHERE $1::timestamptz IS NULL OR created_at > $1)::int AS unread
           FROM notifications WHERE ${visibleTo(2)}`,
        [seen, userId, role],
      ),
    ]);
    return {
      items: rows.map((r) => ({
        id: r.id,
        kind: r.kind,
        assetId: r.asset_id,
        assetName: r.asset_name,
        message: r.message,
        items: r.items,
        total: r.total,
        createdAt: r.created_at.toISOString(),
        unread: !seen || r.created_at > seen,
      })),
      total: counts.total,
      unread: counts.unread,
    };
  }

  async unreadCount(userId: string): Promise<NotificationUnreadCount> {
    const { seen, role } = await this.viewer(userId);
    const [row]: { unread: number }[] = await this.db.query(
      `SELECT count(*)::int AS unread FROM notifications
        WHERE ($1::timestamptz IS NULL OR created_at > $1) AND ${visibleTo(2)}`,
      [seen, userId, role],
    );
    return { unread: row.unread };
  }

  /** «Marcar como leídas»: las anteriores a ahora dejan de contar. */
  async markSeen(userId: string): Promise<NotificationUnreadCount> {
    const [rows]: [unknown[], number] = await this.db.query(
      `UPDATE users SET notifications_seen_at = now() WHERE id = $1 RETURNING id`,
      [userId],
    );
    if (!rows.length) throw new NotFoundException('Usuario no encontrado');
    return { unread: 0 };
  }

  /** Último «Marcar como leídas» y rol (de la BD, como en cada petición). */
  private async viewer(
    userId: string,
  ): Promise<{ seen: Date | null; role: string }> {
    const [row]: { seen: Date | null; role: string }[] = await this.db.query(
      `SELECT notifications_seen_at AS seen, role::text AS role FROM users WHERE id = $1`,
      [userId],
    );
    if (!row) throw new NotFoundException('Usuario no encontrado');
    return row;
  }
}
