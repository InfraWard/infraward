import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import {
  QUEUE_NAMES,
  type AlertChannel,
  type AlertsStatus,
  type AlertTestResult,
  type AlertWebhookPayload,
  type AuditPage,
} from '@infraward/shared-types';
import { getQueueToken } from '@nestjs/bullmq';
import type { Queue } from 'bullmq';
import { createHmac } from 'node:crypto';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { networkInterfaces } from 'node:os';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  prepareEnv,
} from './support/app.js';
import { seedInventory, type SeededInventory } from './support/inventory-seed.js';
import { startWorker, stopWorker, waitFor, type TestWorker } from './support/worker.js';

const EDITOR = { email: 'editor-alertas@infraward.test', password: 'contraseña-del-editor' };
const SIGNING = 'secreto-de-firma-del-webhook';
/** Token en la ruta, como los de Slack o Discord: nunca debe salir de la API ni quedar en claro. */
const PATH_TOKEN = 'T0KEN-centinela-de-la-ruta';

/** Una IPv4 de la máquina que no sea loopback (los webhooks a 127.0.0.1 no se admiten nunca). */
const lanIp = Object.values(networkInterfaces())
  .flat()
  .find((i) => i && i.family === 'IPv4' && !i.internal)?.address;

interface Received {
  headers: IncomingHttpHeaders;
  body: string;
  payload: AlertWebhookPayload;
}

/**
 * Alertas fuera de la app (DESIGN §10) con el worker real: canales (solo admins, con
 * reautenticación), la URL y el secreto de firma en el gestor de secretos, prueba del canal,
 * reparto de las notificaciones nuevas por webhook firmado, el filtro de las de solo admins y la
 * caducidad de un riesgo aceptado (que reabre el finding y avisa).
 */
describe.skipIf(!lanIp)('Alertas fuera de la app (e2e)', { timeout: 90_000 }, () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  let editor: string;
  let worker: TestWorker | undefined;
  let server: Server;
  let inv: SeededInventory;
  let expiredFinding: string;
  const received: Received[] = [];
  let hookUrl: string;

  beforeAll(async () => {
    await prepareEnv('e2e_alerts');
    app = await createTestApp();
    db = app.get(DataSource);
    await app.get(UsersService).create(EDITOR.email, EDITOR.password, 'editor');
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    editor = await loginToken(app, EDITOR.email, EDITOR.password);

    server = createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        received.push({ headers: req.headers, body, payload: JSON.parse(body) });
        res.writeHead(204).end();
      });
    });
    await new Promise<void>((r) => server.listen(0, '0.0.0.0', r));
    hookUrl = `http://${lanIp}:${(server.address() as AddressInfo).port}/hooks/${PATH_TOKEN}`;

    // Un riesgo aceptado ya caducado: el líder lo reabre al arrancar.
    inv = await seedInventory(db);
    // Un UPDATE … RETURNING devuelve [filas, recuento].
    const [[row]]: [{ id: string }[], number] = await db.query(
      `UPDATE findings SET status = 'accepted', accepted_at = now() - interval '2 days',
              accepted_by = 'a@b.c', accept_reason = 'temporal',
              accept_expires_at = now() - interval '1 minute'
        WHERE asset_id = $1 AND vulnerability_id = 'CVE-2026-0003' RETURNING id`,
      [inv.images.pg],
    );
    expiredFinding = row!.id;

    worker = await startWorker({
      ALERTS_WEBHOOK_ALLOW_HTTP: 'true',
      ALERTS_WEBHOOK_ALLOW_PRIVATE: 'true',
      ALERTS_PUBLIC_URL: 'https://infraward.example',
    });
  });

  afterAll(async () => {
    await stopWorker(worker);
    for (const name of [QUEUE_NAMES.system, QUEUE_NAMES.alerts])
      await app?.get<Queue>(getQueueToken(name)).obliterate({ force: true });
    await app?.close();
    await new Promise<void>((r) => server?.close(() => r()));
  });

  const call = (method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, payload?: object, token = admin) =>
    app.inject({ method, url, payload, headers: authHeaders(token) });

  it('al caducar un riesgo aceptado, el finding vuelve a abierto y deja una notificación', async () => {
    await waitFor(
      async () => {
        const [f]: { status: string }[] = await db.query(
          `SELECT status FROM findings WHERE id = $1`,
          [expiredFinding],
        );
        return f!.status === 'open';
      },
      20_000,
      () => `el finding sigue aceptado:\n${worker?.output.join('')}`,
    );
    const [n]: { message: string; items: { id: string }[] }[] = await db.query(
      `SELECT message, items FROM notifications WHERE kind = 'finding_acceptance_expired'`,
    );
    expect(n!.message).toContain('pg:latest');
    expect(n!.items.map((i) => i.id)).toEqual(['CVE-2026-0003']);
  });

  it('el worker publica su estado (sin SMTP, webhooks http y privados permitidos)', async () => {
    await waitFor(
      async () => (await call('GET', '/alerts/status')).json<AlertsStatus>().allowHttp === true,
      20_000,
      () => 'el worker no publicó el estado de las alertas',
    );
    expect((await call('GET', '/alerts/status')).json()).toEqual({
      smtpConfigured: false,
      allowPrivate: true,
      allowHttp: true,
    });
  });

  it('solo admins, y crear pide reautenticación reciente', async () => {
    expect((await call('GET', '/alerts/channels', undefined, editor)).statusCode).toBe(403);
    await db.query(
      `UPDATE user_sessions SET reauthenticated_at = now() - interval '1 hour'
        WHERE csrf_token = $1`,
      [admin.split(' ')[1]],
    );
    const stale = await call('POST', '/alerts/channels', { name: 'x', type: 'webhook', url: hookUrl });
    expect(stale.statusCode).toBe(403);
    expect(stale.json()).toMatchObject({ code: 'recent_auth_required', action: 'alerts.channel_change' });
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
  });

  it('valida el destino', async () => {
    const loopback = await call('POST', '/alerts/channels', {
      name: 'local',
      type: 'webhook',
      url: 'http://127.0.0.1:9/x',
    });
    expect(loopback.statusCode).toBe(400);
    const ftp = await call('POST', '/alerts/channels', { name: 'f', type: 'webhook', url: 'ftp://x/y' });
    expect(ftp.statusCode).toBe(400);
    const mail = await call('POST', '/alerts/channels', { name: 'm', type: 'email' });
    expect(mail.statusCode).toBe(400);
  });

  let channel: AlertChannel;

  it('crea un webhook: la URL y el secreto van al gestor de secretos, nunca de vuelta', async () => {
    const res = await call('POST', '/alerts/channels', {
      name: 'n8n de casa',
      type: 'webhook',
      url: hookUrl,
      secret: SIGNING,
      kinds: ['asset_created', 'vault_revealed', 'finding_acceptance_expired'],
    });
    expect(res.statusCode).toBe(201);
    channel = res.json<AlertChannel>();
    expect(channel).toMatchObject({
      name: 'n8n de casa',
      type: 'webhook',
      enabled: true,
      host: new URL(hookUrl).host,
      hasSecret: true,
      secretProvider: 'local',
      includeAdminOnly: false,
    });
    expect(res.body).not.toContain(PATH_TOKEN);
    expect(res.body).not.toContain(SIGNING);
    const [row]: { raw: string }[] = await db.query(
      `SELECT row_to_json(c)::text AS raw FROM alert_channels c WHERE id = $1`,
      [channel.id],
    );
    expect(row!.raw).not.toContain(PATH_TOKEN);
    expect(row!.raw).not.toContain(SIGNING);
    const [secrets]: { raw: string }[] = await db.query(
      `SELECT string_agg(row_to_json(s)::text, '') AS raw FROM local_secrets s`,
    );
    expect(secrets!.raw).not.toContain(PATH_TOKEN);
    expect(secrets!.raw).not.toContain(SIGNING);
    const list = await call('GET', '/alerts/channels');
    expect(list.body).not.toContain(PATH_TOKEN);
  });

  const verify = (r: Received) => {
    const ts = r.headers['x-infraward-timestamp'] as string;
    const expected = createHmac('sha256', SIGNING).update(`${ts}.${r.body}`).digest('hex');
    expect(r.headers['x-infraward-signature']).toBe(`sha256=${expected}`);
  };

  it('la prueba del canal llega firmada', async () => {
    const res = await call('POST', `/alerts/channels/${channel.id}/test`);
    expect(res.json<AlertTestResult>()).toEqual({ ok: true, error: null });
    const test = received.find((r) => r.payload.event === 'test')!;
    expect(test.headers['x-infraward-event']).toBe('test');
    verify(test);
    const audit = (await call('GET', '/audit?action=alerts.channel_tested')).json<AuditPage>();
    expect(audit.items[0]).toMatchObject({ outcome: 'success', details: { host: channel.host } });
    expect(JSON.stringify(audit)).not.toContain(PATH_TOKEN);
  });

  it('reparte las notificaciones nuevas que admite el filtro (sin las de solo admins)', async () => {
    const insert = (kind: string, message: string, audience: string[] | null = null) =>
      db.query(
        `INSERT INTO notifications (kind, asset_id, asset_name, message, items, total, audience_roles)
         VALUES ($1, $2, 'pve-lab', $3, $4, 1, $5)`,
        [kind, inv.node, message, JSON.stringify([{ id: inv.ct, name: 'ct-docker', type: 'lxc' }]), audience],
      );
    await insert('asset_created', 'pve-lab: 1 nuevo — ct-docker (lxc)');
    await insert('asset_missing', 'fuera del filtro');
    await insert('vault_revealed', 'solo admins', ['admin']);
    await waitFor(
      () => received.some((r) => r.payload.kind === 'asset_created'),
      30_000,
      () => `no llegó la alerta:\n${worker?.output.join('').slice(-3000)}`,
    );
    const hit = received.find((r) => r.payload.kind === 'asset_created')!;
    verify(hit);
    expect(hit.headers['x-infraward-event']).toBe('asset_created');
    expect(hit.payload).toMatchObject({
      event: 'notification',
      message: 'pve-lab: 1 nuevo — ct-docker (lxc)',
      asset: { id: inv.node, name: 'pve-lab' },
      items: [{ id: inv.ct, name: 'ct-docker', type: 'lxc' }],
      url: `https://infraward.example/assets/${inv.node}`,
    });
    // Ninguna notificación queda sin repartir, pero ni la de fuera del filtro ni la de solo
    // admins salen por este canal.
    await waitFor(
      async () =>
        ((await db.query(
          `SELECT count(*)::int AS n FROM notifications WHERE dispatched_at IS NULL`,
        )) as { n: number }[])[0]!.n === 0,
      20_000,
      () => 'quedan notificaciones sin repartir',
    );
    await new Promise((r) => setTimeout(r, 1500));
    expect(received.map((r) => r.payload.kind)).not.toContain('asset_missing');
    expect(received.map((r) => r.payload.kind)).not.toContain('vault_revealed');
    // La de la caducidad (creada al arrancar el worker, antes del primer reparto) también sale.
    const expired = received.find((r) => r.payload.kind === 'finding_acceptance_expired')!;
    expect(expired.payload.url).toBe('https://infraward.example/vulnerabilities/CVE-2026-0003');
    const [ch]: { last_success_at: Date | null }[] = await db.query(
      `SELECT last_success_at FROM alert_channels WHERE id = $1`,
      [channel.id],
    );
    expect(ch!.last_success_at).not.toBeNull();
  });

  it('cambiar y borrar: el secreto de firma se quita y el canal se borra con sus secretos', async () => {
    const res = await call('PATCH', `/alerts/channels/${channel.id}`, {
      secret: null,
      includeAdminOnly: true,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json<AlertChannel>()).toMatchObject({ hasSecret: false, includeAdminOnly: true });
    const del = await call('DELETE', `/alerts/channels/${channel.id}`);
    expect(del.statusCode).toBe(204);
    expect((await call('GET', '/alerts/channels')).json()).toEqual([]);
    const [left]: { n: number }[] = await db.query(
      `SELECT count(*)::int AS n FROM local_secrets WHERE path LIKE $1`,
      [`alerts/${channel.id}/%`],
    );
    expect(left!.n).toBe(0);
    const audit = (await call('GET', '/audit?action=alerts.channel_deleted')).json<AuditPage>();
    expect(audit.items[0]).toMatchObject({ targetLabel: 'n8n de casa' });
  });

  it('correo sin SMTP en el worker: la prueba lo dice', async () => {
    const res = await call('POST', '/alerts/channels', {
      name: 'guardia',
      type: 'email',
      recipients: ['Guardia@Example.com'],
    });
    expect(res.statusCode).toBe(201);
    const mail = res.json<AlertChannel>();
    expect(mail.recipients).toEqual(['guardia@example.com']);
    const test = await call('POST', `/alerts/channels/${mail.id}/test`);
    expect(test.json<AlertTestResult>()).toMatchObject({ ok: false, error: expect.stringContaining('SMTP') });
  });
});
