import { Injectable, Logger, Optional } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Notification } from '@infraward/domain';
import { NOTIFICATION_MAX_ITEMS } from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { PrioritizeTrigger } from '../intel/prioritize-trigger.js';

interface ExpiredRow {
  asset_id: string;
  asset_name: string;
  vulnerability_id: string;
  package_name: string;
}

/**
 * Caducidad de «Aceptar el riesgo» (DESIGN §9): los findings aceptados con la fecha ya pasada
 * vuelven a `open` (cuentan como nuevos y, si son críticos, en KEV y expuestos, se vuelve a avisar)
 * y deja una notificación por asset. Lo lanza el líder cada pocos minutos.
 */
@Injectable()
export class AcceptanceExpiry {
  private readonly logger = new Logger(AcceptanceExpiry.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    @Optional() private readonly prioritize?: PrioritizeTrigger,
  ) {}

  /** Reabre las aceptaciones caducadas; devuelve cuántos findings. */
  async run(): Promise<number> {
    const reopened = await this.db.transaction(async (m) => {
      const [rows]: [ExpiredRow[], number] = await m.query(
        `UPDATE findings f SET status = 'open', opened_at = now(), kev_alerted_at = NULL
           FROM assets a
          WHERE a.id = f.asset_id AND f.status = 'accepted'
            AND f.accept_expires_at IS NOT NULL AND f.accept_expires_at <= now()
         RETURNING f.asset_id, a.name AS asset_name, f.vulnerability_id, f.package_name`,
      );
      const byAsset = new Map<string, ExpiredRow[]>();
      for (const r of rows) {
        const list = byAsset.get(r.asset_id) ?? [];
        list.push(r);
        byAsset.set(r.asset_id, list);
      }
      for (const [assetId, list] of byAsset) {
        const cves = [...new Map(list.map((r) => [r.vulnerability_id, r])).values()];
        const names = cves.slice(0, 5).map((r) => r.vulnerability_id);
        const more = cves.length > 5 ? ` y ${cves.length - 5} más` : '';
        await m.insert(Notification, {
          kind: 'finding_acceptance_expired',
          assetId,
          assetName: list[0]!.asset_name,
          message: `${list[0]!.asset_name}: caducó el riesgo aceptado de ${cves.length === 1 ? '1 CVE' : `${cves.length} CVE`}, vuelve a estar abierto — ${names.join(', ')}${more}`,
          items: cves.slice(0, NOTIFICATION_MAX_ITEMS).map((r) => ({
            id: r.vulnerability_id,
            name: `${r.vulnerability_id} (${r.package_name})`,
            type: 'vulnerability' as const,
          })),
          total: cves.length,
        });
      }
      return rows.length;
    });
    if (reopened > 0) {
      this.logger.log(`Riesgo aceptado caducado: ${reopened} finding(s) reabierto(s)`);
      await this.prioritize?.request('aceptaciones caducadas');
    }
    return reopened;
  }
}
