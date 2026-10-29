import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import {
  createSecretProviders,
  LocalVaultStore,
  MasterKey,
  SecretsService,
  TypeOrmVaultRowStore,
  vaultEntryPath,
} from '@infraward/secrets';
import type {
  AuditPage,
  CreatedApiTokenResponse,
  NotificationPage,
  RevealVaultSecretResponse,
  VaultEntry,
  VaultEntryList,
  VaultVersion,
} from '@infraward/shared-types';
import type { ModuleRef } from '@nestjs/core';
import { Redis } from 'ioredis';
import { DataSource } from 'typeorm';
import { UsersService } from '../src/users/users.service.js';
import { VaultService } from '../src/vault/vault.service.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  loginToken,
  nextTotpCode,
  prepareEnv,
  redisDb,
  redisUrl,
  vaultKeyFile,
} from './support/app.js';
import { seedInventory, type SeededInventory } from './support/inventory-seed.js';

const ADMIN2 = { email: 'admin2-vault@infraward.test', password: 'contraseña-del-segundo-admin' };
const EDITOR = { email: 'editora-vault@infraward.test', password: 'contraseña-de-la-editora' };
const VIEWER = { email: 'lector-vault@infraward.test', password: 'contraseña-del-lector-vault' };

/** Centinelas: las contraseñas guardadas, que solo pueden salir en la respuesta de «Revelar». */
const ROOT_PW = `root-centinela-${randomBytes(6).toString('hex')}`;
const WEB_PW = `panel-centinela-${randomBytes(6).toString('hex')}`;
const ROTATED_PW = `rotada-centinela-${randomBytes(6).toString('hex')}`;
const SECRETS = [ROOT_PW, WEB_PW, ROTATED_PW];

const WORKER_DIST = resolve(import.meta.dirname, '../../worker/dist');

/**
 * Caja fuerte de credenciales (QoL-7, DESIGN §19): admin y editor gestionan (sin ver valores);
 * solo un admin revela, con reautenticación reciente; todo auditado, con aviso a los demás
 * admins; versiones, papelera y purga; y el worker no puede leerla.
 */
describe('Caja fuerte de credenciales (e2e)', () => {
  let app: NestFastifyApplication;
  let db: DataSource;
  let admin: string;
  let admin2: string;
  let editor: string;
  let viewer: string;
  let inv: SeededInventory;
  let consoleEntry: VaultEntry;
  let webEntry: VaultEntry;
  const output: string[] = [];
  /** Todas las respuestas menos las de «Revelar» (que son las únicas que llevan el valor). */
  const responses: string[] = [];

  beforeAll(async () => {
    await prepareEnv('e2e_vault', {
      VAULT_PROVIDER: 'local',
      VAULT_LOCAL_MASTER_KEY_FILE: vaultKeyFile(),
      VAULT_MAX_VERSIONS: '3',
    });
    for (const stream of [process.stdout, process.stderr]) {
      const write = stream.write.bind(stream) as (...args: unknown[]) => boolean;
      vi.spyOn(stream, 'write').mockImplementation((...args: unknown[]) => {
        output.push(String(args[0]));
        return write(...args);
      });
    }
    app = await createTestApp();
    db = app.get(DataSource);
    const users = app.get(UsersService);
    await users.create(ADMIN2.email, ADMIN2.password, 'admin');
    await users.create(EDITOR.email, EDITOR.password, 'editor');
    await users.create(VIEWER.email, VIEWER.password, 'viewer');
    admin = await loginToken(app, ADMIN.email, ADMIN.password);
    admin2 = await loginToken(app, ADMIN2.email, ADMIN2.password);
    editor = await loginToken(app, EDITOR.email, EDITOR.password);
    viewer = await loginToken(app, VIEWER.email, VIEWER.password);
    inv = await seedInventory(db);
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await app?.close();
  });

  async function call(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    url: string,
    options: { session?: string | null; bearer?: string; payload?: object } = {},
  ) {
    const session = options.session === undefined ? admin : options.session;
    const res = await app.inject({
      method,
      url,
      headers: {
        ...(session ? authHeaders(session) : {}),
        ...(options.bearer ? { authorization: `Bearer ${options.bearer}` } : {}),
      },
      payload: options.payload,
    });
    if (!url.endsWith('/reveal')) responses.push(res.body);
    return res;
  }

  /** Mueve la última reautenticación de la sesión `minutes` minutos atrás. */
  async function ageReauth(token: string, minutes: number) {
    await db.query(
      `UPDATE user_sessions SET reauthenticated_at = now() - make_interval(mins => $2)
        WHERE csrf_token = $1`,
      [token.split(' ')[1], minutes],
    );
  }

  async function reauth(token: string, email: string, action: string) {
    const res = await call('POST', '/auth/reauth', {
      session: token,
      payload: { code: await nextTotpCode(email), action },
    });
    expect(res.statusCode).toBe(200);
  }

  async function lastEvent(action: string) {
    const res = await call('GET', `/audit?action=${action}&limit=1`);
    expect(res.statusCode).toBe(200);
    return res.json<AuditPage>().items[0];
  }

  it('estado del almacén: local y sano', async () => {
    const res = await call('GET', '/vault/status', { session: editor });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ provider: 'local', healthy: true, maxVersions: 3 });
    expect(res.headers['cache-control']).toBeUndefined();
  });

  it('el editor guarda la contraseña de consola del servidor y la de su panel web, sin ver los valores', async () => {
    const created = await call('POST', '/vault/entries', {
      session: editor,
      payload: {
        kind: 'console',
        name: 'root (consola)',
        username: 'root',
        assetId: inv.node,
        secret: ROOT_PW,
      },
    });
    expect(created.statusCode).toBe(201);
    expect(created.headers['cache-control']).toBe('no-store');
    consoleEntry = created.json<VaultEntry>();
    expect(consoleEntry).toMatchObject({
      kind: 'console',
      username: 'root',
      asset: { id: inv.node, name: 'pve-lab' },
      hasSecret: true,
      currentVersion: 1,
      rotationState: 'ok',
      effectiveRotationDays: 180,
    });
    expect(created.body).not.toContain(ROOT_PW);
    expect(created.body).not.toContain('secret://');

    const web = await call('POST', '/vault/entries', {
      session: editor,
      payload: {
        kind: 'web',
        name: 'Proxmox (web)',
        username: 'root@pam',
        url: 'https://10.9.9.1:8006',
        assetId: inv.node,
        secret: WEB_PW,
        rotationDays: 30,
        lastRotatedAt: new Date(Date.now() - 40 * 86_400_000).toISOString(),
      },
    });
    expect(web.statusCode).toBe(201);
    webEntry = web.json<VaultEntry>();
    expect(webEntry).toMatchObject({ rotationState: 'overdue', effectiveRotationDays: 30 });

    // En la BD: solo la referencia al almacén de la caja fuerte (no al de la app) y texto cifrado.
    const [row]: { secret_ref: string }[] = await db.query(
      'SELECT secret_ref FROM vault_entries WHERE id = $1',
      [consoleEntry.id],
    );
    expect(row!.secret_ref).toBe(
      `secret://vault-local/entries/${consoleEntry.id}#password`,
    );
    const cipher = JSON.stringify(await db.query('SELECT * FROM vault_local_secrets'));
    for (const s of SECRETS) expect(cipher).not.toContain(s);
    expect(await db.query('SELECT 1 FROM local_secrets WHERE path LIKE $1', ['%entries%'])).toEqual(
      [],
    );
  });

  it('listado por asset y búsqueda: solo metadatos, con el vencido contado', async () => {
    const list = await call('GET', `/vault/entries?assetId=${inv.node}`, { session: editor });
    expect(list.statusCode).toBe(200);
    const body = list.json<VaultEntryList>();
    expect(body.items.map((e) => e.name)).toEqual(['Proxmox (web)', 'root (consola)']);
    expect(body.overdue).toBe(1);
    const found = await call('GET', '/vault/entries?q=8006', { session: editor });
    expect(found.json<VaultEntryList>().items.map((e) => e.id)).toEqual([webEntry.id]);
    for (const r of [list.body, found.body]) {
      expect(r).not.toContain('secret://');
      for (const s of SECRETS) expect(r).not.toContain(s);
    }
  });

  it('permisos: el lector no ve nada; el editor no revela; un token de API no entra', async () => {
    expect((await call('GET', '/vault/entries', { session: viewer })).statusCode).toBe(403);
    expect((await call('GET', '/vault/status', { session: viewer })).statusCode).toBe(403);
    const denied = await call('POST', `/vault/entries/${consoleEntry.id}/reveal`, {
      session: editor,
      payload: { purpose: 'show' },
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.body).not.toContain(ROOT_PW);

    const token = await call('POST', '/auth/tokens', {
      payload: {
        name: 'Script vault',
        scope: 'role',
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      },
    });
    expect(token.statusCode).toBe(201);
    const bearer = token.json<CreatedApiTokenResponse>().secret;
    for (const [method, url] of [
      ['GET', '/vault/entries'],
      ['POST', `/vault/entries/${consoleEntry.id}/reveal`],
    ] as const) {
      const res = await call(method, url, {
        session: null,
        bearer,
        payload: method === 'POST' ? { purpose: 'show' } : undefined,
      });
      expect(res.statusCode).toBe(403);
      expect(res.body).not.toContain(ROOT_PW);
    }
  });

  it('revelar exige reautenticación reciente; con el código TOTP, devuelve el valor y lo audita', async () => {
    await ageReauth(admin, 11);
    const denied = await call('POST', `/vault/entries/${consoleEntry.id}/reveal`, {
      payload: { purpose: 'show', reason: 'Consola de emergencia' },
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.json()).toMatchObject({ code: 'recent_auth_required', action: 'vault.reveal' });

    await reauth(admin, ADMIN.email, 'vault.reveal');
    const res = await call('POST', `/vault/entries/${consoleEntry.id}/reveal`, {
      payload: { purpose: 'show', reason: 'Consola de emergencia' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.json<RevealVaultSecretResponse>()).toEqual({
      value: ROOT_PW,
      version: 1,
      expiresInSeconds: 30,
    });

    const event = await lastEvent('vault.revealed');
    expect(event).toMatchObject({
      outcome: 'success',
      actorEmail: ADMIN.email,
      targetLabel: 'root (consola)',
      details: expect.objectContaining({
        entryId: consoleEntry.id,
        assetName: 'pve-lab',
        purpose: 'show',
        reason: 'Consola de emergencia',
        version: 1,
      }),
    });
    const required = await lastEvent('auth.reauth_required');
    expect(required?.details).toMatchObject({ action: 'vault.reveal' });
  });

  it('un motivo con la credencial pegada no se guarda', async () => {
    const res = await call('POST', `/vault/entries/${consoleEntry.id}/reveal`, {
      payload: { purpose: 'copy', reason: `me la apunto: ${ROOT_PW}` },
    });
    expect(res.statusCode).toBe(200);
    expect((await lastEvent('vault.revealed'))?.details).toMatchObject({
      reason: '[omitido: contenía la credencial]',
      purpose: 'copy',
    });
  });

  it('avisa a los demás admins (no a quien reveló ni a los que no son admins)', async () => {
    const page = (token: string) =>
      call('GET', '/notifications', { session: token }).then((r) => r.json<NotificationPage>());
    const other = (await page(admin2)).items.filter((n) => n.kind === 'vault_revealed');
    expect(other).toHaveLength(2);
    expect(other[0]).toMatchObject({
      assetId: inv.node,
      message: expect.stringMatching(/reveló «root \(consola\)» \(consola\) de pve-lab/),
    });
    expect((await page(admin)).items.some((n) => n.kind === 'vault_revealed')).toBe(false);
    expect((await page(editor)).items.some((n) => n.kind === 'vault_revealed')).toBe(false);
    expect((await page(viewer)).items.some((n) => n.kind === 'vault_revealed')).toBe(false);
    const unread = await call('GET', '/notifications/unread-count', { session: editor });
    const before = unread.json<{ unread: number }>().unread;
    expect(before).toBe((await page(editor)).unread);
  });

  it('versiones: sustituir crea otra (sin leer la anterior) y solo un admin con step-up restaura', async () => {
    const replaced = await call('PUT', `/vault/entries/${consoleEntry.id}/secret`, {
      session: editor,
      payload: { secret: ROTATED_PW, rotated: true },
    });
    expect(replaced.statusCode).toBe(200);
    expect(replaced.json<VaultEntry>()).toMatchObject({ currentVersion: 2 });

    const versions = (
      await call('GET', `/vault/entries/${consoleEntry.id}/versions`, { session: editor })
    ).json<VaultVersion[]>();
    expect(versions.map((v) => [v.version, v.origin, v.current, v.available])).toEqual([
      [2, 'replaced', true, true],
      [1, 'created', false, true],
    ]);
    expect(versions[0]!.createdBy).toBe(EDITOR.email);

    const byEditor = await call('POST', `/vault/entries/${consoleEntry.id}/versions/1/restore`, {
      session: editor,
    });
    expect(byEditor.statusCode).toBe(403);
    await ageReauth(admin, 11);
    const stale = await call('POST', `/vault/entries/${consoleEntry.id}/versions/1/restore`);
    expect(stale.json()).toMatchObject({ action: 'vault.version_restore' });
    await reauth(admin, ADMIN.email, 'vault.version_restore');
    const restored = await call('POST', `/vault/entries/${consoleEntry.id}/versions/1/restore`);
    expect(restored.statusCode).toBe(200);
    expect(restored.json<VaultEntry>().currentVersion).toBe(3);
    const reveal = await call('POST', `/vault/entries/${consoleEntry.id}/reveal`, {
      payload: { purpose: 'show' },
    });
    expect(reveal.json<RevealVaultSecretResponse>()).toMatchObject({ value: ROOT_PW, version: 3 });
    expect((await lastEvent('vault.version_restored'))?.details).toMatchObject({
      from: 1,
      version: 3,
    });

    // Con VAULT_MAX_VERSIONS=3, una más poda la 1: el historial la marca como no disponible.
    await call('PUT', `/vault/entries/${consoleEntry.id}/secret`, {
      session: editor,
      payload: { secret: ROTATED_PW, rotated: false },
    });
    const after = (
      await call('GET', `/vault/entries/${consoleEntry.id}/versions`)
    ).json<VaultVersion[]>();
    expect(after.find((v) => v.version === 1)?.available).toBe(false);
    const gone = await call('POST', `/vault/entries/${consoleEntry.id}/versions/1/restore`);
    expect(gone.statusCode).toBe(404);
  });

  it('papelera: borrar, no revelar, recuperar; y pasado el plazo se destruye', async () => {
    const del = await call('DELETE', `/vault/entries/${webEntry.id}`, { session: editor });
    expect(del.statusCode).toBe(200);
    expect(del.json<VaultEntry>().purgeAt).not.toBeNull();
    const live = (await call('GET', '/vault/entries')).json<VaultEntryList>();
    expect(live.items.map((e) => e.id)).not.toContain(webEntry.id);
    const trash = (await call('GET', '/vault/entries?deleted=true')).json<VaultEntryList>();
    expect(trash.items.map((e) => e.id)).toEqual([webEntry.id]);
    const blocked = await call('POST', `/vault/entries/${webEntry.id}/reveal`, {
      payload: { purpose: 'show' },
    });
    expect(blocked.statusCode).toBe(409);
    expect(blocked.body).not.toContain(WEB_PW);

    const back = await call('POST', `/vault/entries/${webEntry.id}/restore`, { session: editor });
    expect(back.statusCode).toBe(200);
    expect(back.json<VaultEntry>().deletedAt).toBeNull();

    await call('DELETE', `/vault/entries/${webEntry.id}`, { session: editor });
    const vault = app.get(VaultService);
    expect(await vault.purgeExpired(new Date())).toBe(0);
    expect(await vault.purgeExpired(new Date(Date.now() + 31 * 86_400_000))).toBe(1);
    expect(
      await db.query('SELECT 1 FROM vault_local_secrets WHERE path = $1', [
        vaultEntryPath(webEntry.id),
      ]),
    ).toEqual([]);
    expect((await call('GET', `/vault/entries/${webEntry.id}`)).statusCode).toBe(404);
    expect((await lastEvent('vault.purged'))?.targetLabel).toBe('Proxmox (web)');
  });

  it('ajustes: cambiarlos exige admin con step-up y queda auditado; sin aviso, no se notifica', async () => {
    const current = await call('GET', '/vault/settings', { session: editor });
    expect(current.json()).toEqual({
      rotationWarnDays: 180,
      notifyOnReveal: true,
      deleteRetentionDays: 30,
    });
    const next = { rotationWarnDays: 90, notifyOnReveal: false, deleteRetentionDays: 7 };
    expect(
      (await call('PUT', '/vault/settings', { session: editor, payload: next })).statusCode,
    ).toBe(403);
    await ageReauth(admin, 11);
    const stale = await call('PUT', '/vault/settings', { payload: next });
    expect(stale.json()).toMatchObject({ action: 'vault.settings_change' });
    await reauth(admin, ADMIN.email, 'vault.settings_change');
    const saved = await call('PUT', '/vault/settings', { payload: next });
    expect(saved.statusCode).toBe(200);
    expect(saved.json()).toEqual(next);
    expect((await lastEvent('vault.settings_changed'))?.details).toMatchObject({
      notifyOnReveal: 'true → false',
    });

    const before = (await call('GET', '/notifications', { session: admin2 })).json<NotificationPage>();
    await call('POST', `/vault/entries/${consoleEntry.id}/reveal`, { payload: { purpose: 'show' } });
    const after = (await call('GET', '/notifications', { session: admin2 })).json<NotificationPage>();
    expect(after.total).toBe(before.total);
  });

  it('el worker no puede leerla: ni con su configuración, ni con su clave, ni en su código', async () => {
    const ref = `secret://vault-local/${vaultEntryPath(consoleEntry.id)}#password`;
    // El SecretsService del worker se monta con estas variables (SECRETS_*): aunque alguien le
    // pusiera las VAULT_*, no las lee.
    const providers = createSecretProviders(
      {
        enabled: ['local'],
        local: { file: process.env.SECRETS_LOCAL_MASTER_KEY_FILE },
      },
      { get: () => db } as unknown as ModuleRef,
    );
    const workerSecrets = new SecretsService(providers, 0);
    await expect(workerSecrets.resolve(ref)).rejects.toMatchObject({
      code: 'provider_not_configured',
    });
    // La misma ruta en su proveedor local (otra tabla): no existe.
    await expect(
      workerSecrets.resolve(`secret://local/${vaultEntryPath(consoleEntry.id)}#password`),
    ).rejects.toMatchObject({ code: 'not_found' });
    // Y con su clave maestra el texto cifrado de la caja fuerte no se descifra.
    const workerKey = new MasterKey(
      Buffer.from(
        readFileSync(process.env.SECRETS_LOCAL_MASTER_KEY_FILE!, 'utf8').trim(),
        'base64',
      ),
    );
    const withWorkerKey = new LocalVaultStore(new TypeOrmVaultRowStore(() => db), workerKey, 3);
    await expect(withWorkerKey.get(vaultEntryPath(consoleEntry.id))).rejects.toMatchObject({
      code: 'key_mismatch',
    });
    // Ni la API de comprobar referencias (la del SecretsService compartido) la resuelve.
    const check = await call('POST', '/secrets/check', { payload: { ref } });
    expect(check.json()).toMatchObject({ resolves: false, error: 'provider_not_configured' });
    // El worker compilado no conoce la caja fuerte: ni sus variables, ni su tabla, ni su almacén.
    // Salvo la lista de variables que el gateway RECHAZA (no arranca si le llega una VAULT_*).
    const files = readdirSync(WORKER_DIST, { recursive: true, encoding: 'utf8' }).filter(
      (f) => f.endsWith('.js') && f !== join('gateway', 'gateway.env.js'),
    );
    expect(files.length).toBeGreaterThan(20);
    for (const f of files) {
      const code = readFileSync(join(WORKER_DIST, f), 'utf8');
      expect(code, f).not.toMatch(/VAULT_|vault_local_secrets|vault_entries|VaultStore/);
    }
  });

  it('purgar el asset deja la entrada suelta (la contraseña no se pierde)', async () => {
    const [{ id }]: { id: string }[] = await db.query(
      `INSERT INTO assets (type, discovered_name, status) VALUES ('server', 'idrac-host', 'active')
       RETURNING id`,
    );
    const ipmi = await call('POST', '/vault/entries', {
      session: editor,
      payload: { kind: 'ipmi', name: 'iDRAC', assetId: id },
    });
    expect(ipmi.statusCode).toBe(201);
    expect(ipmi.json<VaultEntry>().hasSecret).toBe(false);
    await db.query('DELETE FROM assets WHERE id = $1', [id]);
    const after = await call('GET', `/vault/entries/${ipmi.json<VaultEntry>().id}`);
    expect(after.json<VaultEntry>().asset).toBeNull();
    // Un asset que no existe: 400.
    const missing = await call('POST', '/vault/entries', {
      session: editor,
      payload: { kind: 'ipmi', name: 'iDRAC', assetId: id },
    });
    expect(missing.statusCode).toBe(400);
  });

  it('0 fugas: los valores solo salen en «Revelar» (ni BD, auditoría, notificaciones, Redis, logs, respuestas ni exportaciones)', async () => {
    for (const url of [
      `/assets/${inv.node}`,
      '/assets/tree',
      '/assets/export?format=json',
      '/dashboard',
      '/audit?limit=200',
    ]) {
      const res = await call('GET', url);
      expect(res.statusCode, url).toBe(200);
      expect(res.body, url).not.toContain('vault-local');
    }
    const dump = JSON.stringify(
      await db.query(`SELECT row_to_json(t) AS r FROM (SELECT * FROM vault_entries) t
        UNION ALL SELECT row_to_json(v) FROM vault_entry_versions v
        UNION ALL SELECT row_to_json(l) FROM vault_local_secrets l
        UNION ALL SELECT row_to_json(s) FROM local_secrets s
        UNION ALL SELECT row_to_json(a) FROM audit_events a
        UNION ALL SELECT row_to_json(n) FROM notifications n
        UNION ALL SELECT row_to_json(x) FROM app_settings x
        UNION ALL SELECT row_to_json(u) FROM user_sessions u`),
    );
    const redis = new Redis({
      host: redisUrl().hostname,
      port: Number(redisUrl().port || 6379),
      db: Number(redisDb()),
    });
    const values: string[] = [];
    for (const key of await redis.keys('*')) {
      const type = await redis.type(key);
      if (type === 'string') values.push((await redis.get(key)) ?? '');
      if (type === 'hash') values.push(JSON.stringify(await redis.hgetall(key)));
      if (type === 'list') values.push(JSON.stringify(await redis.lrange(key, 0, -1)));
    }
    await redis.quit();
    const logs = output.join('');
    for (const secret of SECRETS) {
      expect(dump).not.toContain(secret);
      expect(values.join('\n')).not.toContain(secret);
      expect(logs).not.toContain(secret);
      expect(responses.join('\n')).not.toContain(secret);
    }
  });
});
