import {
  NOTIFICATION_MAX_ITEMS,
  type NotificationItem,
  type NotificationKind,
} from '@infraward/shared-types';
import type { EntityManager } from 'typeorm';
import { Notification } from './notification.entity.js';

/** Notificaciones agrupadas por descubrimiento y padre (las de altas, bajas y reapariciones). */
export type GroupedNotificationKind = Exclude<
  NotificationKind,
  | 'reconcile_failed'
  | 'expiry_warning'
  | 'dns_dangling'
  | 'vulnerability_kev'
  | 'vault_revealed'
>;

const VERBS: Record<GroupedNotificationKind, [string, string]> = {
  asset_created: ['nuevo', 'nuevos'],
  asset_missing: ['desaparecido', 'desaparecidos'],
  asset_reactivated: ['ha reaparecido', 'han reaparecido'],
  asset_retired: ['retirado tras no verse', 'retirados tras no verse'],
};

/**
 * Mensaje de una notificación agrupada: «pve-pruebas: 1 nuevo — test (lxc)»,
 * «pve-pruebas: 3 desaparecidos — a, b, c». Solo nombres y tipos.
 */
export function groupedMessage(
  kind: GroupedNotificationKind,
  parentName: string | null,
  items: readonly NotificationItem[],
): string {
  const [one, many] = VERBS[kind];
  const head = `${items.length} ${items.length === 1 ? one : many}`;
  const names = items
    .slice(0, 5)
    .map((i) => `${i.name} (${i.type})`)
    .join(', ');
  const more = items.length > 5 ? ` y ${items.length - 5} más` : '';
  return `${parentName ? `${parentName}: ` : ''}${head} — ${names}${more}`;
}

/** Guarda una notificación agrupada (nada si no hay assets). */
export async function notifyAssets(
  m: EntityManager,
  kind: GroupedNotificationKind,
  parent: { id: string; name: string } | null,
  items: readonly NotificationItem[],
): Promise<void> {
  if (items.length === 0) return;
  await m.insert(Notification, {
    kind,
    assetId: parent?.id ?? null,
    assetName: parent?.name ?? null,
    message: groupedMessage(kind, parent?.name ?? null, items),
    items: items.slice(0, NOTIFICATION_MAX_ITEMS),
    total: items.length,
  });
}
