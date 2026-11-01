import { createHmac } from 'node:crypto';
import type { AlertChannel, Notification } from '@infraward/domain';
import type { AlertWebhookPayload } from '@infraward/shared-types';

/** Lo que sale de una notificación hacia fuera: lo mismo que enseña la campana. */
export type AlertSource = Pick<
  Notification,
  'id' | 'kind' | 'assetId' | 'assetName' | 'message' | 'items' | 'total' | 'createdAt'
> &
  Partial<Pick<Notification, 'audienceRoles'>>;

/** Enlace a la web: el CVE (si solo hay uno), el asset o la lista de vulnerabilidades. */
export function alertLink(n: AlertSource, publicUrl: string | undefined): string | null {
  if (!publicUrl) return null;
  const base = publicUrl.replace(/\/+$/, '');
  const cves = n.items.filter((i) => i.type === 'vulnerability');
  if (cves.length === 1) return `${base}/vulnerabilities/${encodeURIComponent(cves[0]!.id)}`;
  if (n.assetId) return `${base}/assets/${encodeURIComponent(n.assetId)}`;
  if (cves.length) return `${base}/vulnerabilities`;
  return base;
}

export function webhookPayload(
  n: AlertSource,
  publicUrl: string | undefined,
  event: AlertWebhookPayload['event'] = 'notification',
): AlertWebhookPayload {
  return {
    event,
    id: n.id,
    kind: event === 'test' ? 'test' : n.kind,
    message: n.message,
    asset: n.assetId || n.assetName ? { id: n.assetId, name: n.assetName } : null,
    items: n.items.map((i) => ({ id: i.id, name: i.name, type: i.type })),
    total: n.total,
    createdAt: n.createdAt.toISOString(),
    url: alertLink(n, publicUrl),
  };
}

/** Firma del webhook: `sha256=<hex>` de HMAC-SHA256(secreto, `<fecha>.<cuerpo>`). */
export function webhookSignature(secret: string, timestamp: number, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`;
}

/** ¿Le llega esta notificación a este canal? Filtro de tipos y de las solo para admins. */
export function channelAccepts(
  channel: Pick<AlertChannel, 'enabled' | 'kinds' | 'includeAdminOnly'>,
  n: Pick<AlertSource, 'kind' | 'audienceRoles'>,
): boolean {
  if (!channel.enabled) return false;
  if (channel.kinds && !channel.kinds.includes(n.kind)) return false;
  // Las restringidas a algunos roles (hoy: solo admins) solo salen por los canales que lo piden.
  if (n.audienceRoles?.length && !channel.includeAdminOnly) return false;
  return true;
}

/** Asunto y cuerpo (texto y HTML mínimo) del correo de una notificación. */
export function emailContent(
  n: AlertSource,
  publicUrl: string | undefined,
): { subject: string; text: string; html: string } {
  const link = alertLink(n, publicUrl);
  const subject = `[InfraWard] ${n.message}`.replace(/[\r\n]+/g, ' ').slice(0, 200);
  const lines = [n.message, ''];
  for (const item of n.items) lines.push(`- ${item.name}`);
  if (n.total > n.items.length) lines.push(`… y ${n.total - n.items.length} más`);
  if (link) lines.push('', link);
  const esc = (s: string) =>
    s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const html = [
    `<p>${esc(n.message)}</p>`,
    n.items.length
      ? `<ul>${n.items.map((i) => `<li>${esc(i.name)}</li>`).join('')}</ul>`
      : '',
    n.total > n.items.length ? `<p>… y ${n.total - n.items.length} más</p>` : '',
    link ? `<p><a href="${esc(link)}">Abrir en InfraWard</a></p>` : '',
  ].join('');
  return { subject, text: lines.join('\n'), html };
}
