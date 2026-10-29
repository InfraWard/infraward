import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { expiryWarningDays, Notification } from '@infraward/domain';
import {
  NOTIFICATION_MAX_ITEMS,
  type AssetType,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';

interface Expiring {
  id: string;
  name: string;
  type: AssetType;
  not_after: Date;
}

/** Umbrales que ya ha cruzado una caducidad (0 = caducado), de mayor a menor. */
export function crossedThresholds(
  notAfter: Date,
  days: readonly number[],
  now: Date,
): number[] {
  const left = (notAfter.getTime() - now.getTime()) / 86_400_000;
  const crossed = days.filter((d) => left < d);
  return left <= 0 ? [...crossed, 0] : crossed;
}

/** «caduca en 6 días», «caducó hace 2 días», «caduca hoy». */
export function expiryPhrase(notAfter: Date, now: Date): string {
  const days = Math.ceil((notAfter.getTime() - now.getTime()) / 86_400_000);
  if (notAfter <= now) {
    const ago = Math.floor((now.getTime() - notAfter.getTime()) / 86_400_000);
    return ago === 0 ? 'caducó hoy' : `caducó hace ${ago} ${ago === 1 ? 'día' : 'días'}`;
  }
  if (days <= 1) return 'caduca en menos de un día';
  return `caduca en ${days} días`;
}

/**
 * Avisos de caducidad de dominios (RDAP) y certificados (Plesk y 443), DESIGN §13: en cada tick,
 * lo que ha cruzado un umbral (`app_settings.expiry_warning_days`, p. ej. 30 y 7 días) o ya ha
 * caducado genera una notificación, una sola vez por asset, fecha y umbral (`expiry_alerts`).
 * Una renovación trae otra fecha y vuelve a avisar en cada umbral.
 */
@Injectable()
export class ExpiryAlerts {
  private readonly logger = new Logger(ExpiryAlerts.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  run(now: Date = new Date()): Promise<number> {
    return this.db.transaction(async (m) => {
      const days = await expiryWarningDays(m);
      const max = Math.max(...days);
      const rows: Expiring[] = await m.query(
        `SELECT id, name, type, not_after FROM (
           SELECT a.id, a.name, a.type,
                  (CASE a.type
                     WHEN 'certificate' THEN a.facts->'certificate'->>'notAfter'
                     ELSE a.facts->'registration'->>'expiresAt' END)::timestamptz AS not_after
             FROM assets a
            WHERE a.status = 'active' AND a.type IN ('certificate', 'domain')
              AND jsonb_typeof(CASE a.type
                     WHEN 'certificate' THEN a.facts->'certificate'->'notAfter'
                     ELSE a.facts->'registration'->'expiresAt' END) = 'string') x
          WHERE not_after < $1::timestamptz + make_interval(days => $2)`,
        [now.toISOString(), max],
      );
      const notified: { item: Expiring; threshold: number }[] = [];
      for (const row of rows) {
        const crossed = crossedThresholds(row.not_after, days, now);
        if (crossed.length === 0) continue;
        const inserted: { threshold_days: number }[] = await m.query(
          `INSERT INTO expiry_alerts (asset_id, not_after, threshold_days)
           SELECT $1, $2, t FROM unnest($3::int[]) AS t
           ON CONFLICT DO NOTHING
           RETURNING threshold_days`,
          [row.id, row.not_after, crossed],
        );
        if (inserted.length === 0) continue;
        notified.push({
          item: row,
          threshold: Math.min(...inserted.map((i) => i.threshold_days)),
        });
      }
      if (notified.length === 0) return 0;
      notified.sort((a, b) => a.item.not_after.getTime() - b.item.not_after.getTime());
      const parts = notified
        .slice(0, 5)
        .map(
          (n) =>
            `${n.item.name} (${n.item.type === 'domain' ? 'dominio' : 'certificado'}) ${expiryPhrase(n.item.not_after, now)}`,
        );
      const more = notified.length > 5 ? ` y ${notified.length - 5} más` : '';
      await m.insert(Notification, {
        kind: 'expiry_warning',
        assetId: notified.length === 1 ? notified[0].item.id : null,
        assetName: notified.length === 1 ? notified[0].item.name : null,
        message: `${notified.length === 1 ? 'Caducidad' : `${notified.length} caducidades`}: ${parts.join('; ')}${more}`,
        items: notified
          .slice(0, NOTIFICATION_MAX_ITEMS)
          .map((n) => ({ id: n.item.id, name: n.item.name, type: n.item.type })),
        total: notified.length,
      });
      this.logger.log(`Avisos de caducidad: ${notified.length}`);
      return notified.length;
    });
  }
}
