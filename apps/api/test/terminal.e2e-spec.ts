import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { loadOpenBaoConfig, OpenBaoSecretProvider } from '@infraward/secrets';
import {
  createTestAppRole,
  createTestTerminalAppRole,
  startOpenBaoTestServer,
  type OpenBaoTestServer,
  type TestAppRole,
} from '@infraward/secrets/testing/openbao';
import {
  ADMIN_ACCESS_VERSION,
  SSH_CA_CONFIG_VERSION,
  SUDOERS_VERSION,
  type CreateTerminalSessionResponse,
  type TemporaryPasswordResponse,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { embeddedCommand, keyComment } from '../src/enrollment/commands.js';
import { EnrollScriptTemplate } from '../src/enrollment/script-template.js';
import { startSshd, type TestSshd } from './integration/support/sshd.js';
import {
  ADMIN,
  authHeaders,
  createTestApp,
  enableTotp,
  login,
  loginToken,
  prepareEnv,
  sessionToken,
} from './support/app.js';
import { freePort, startGateway } from './support/gateway.js';
import { TestTerminal } from './support/terminal-client.js';
import { startWorker, stopWorker, waitFor, type TestWorker } from './support/worker.js';

/** `pct` falso: `enter <vmid>` abre una shell; `exec <vmid> -- <cmd…>` ejecuta el comando. */
const FAKE_PCT = `#!/bin/sh
case "$1" in
  enter) [ "$2" = 101 ] || exit 2; echo "PCT_ENTER $2"; exec /bin/bash --norc -i ;;
  exec) vmid=$2; shift 3; echo "PCT_EXEC $vmid" >&2; exec "$@" ;;
esac
exit 2
`;
/**
 * systemd falso para «Habilitar Podman» (la imagen no tiene systemd): `loginctl enable-linger` crea
 * el bus del usuario y `systemctl --user enable --now podman.socket`, su socket de Podman.
 */
const UNIX_SOCKET = `python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])'`;
const FAKE_LOGINCTL = `#!/bin/sh
[ "$1" = enable-linger ] || exit 2
n=$(id -u "$2") || exit 1
sleep 2
install -d -m 700 -o "$2" "/run/user/$n" && rm -f "/run/user/$n/bus" && ${UNIX_SOCKET} "/run/user/$n/bus" || exit 1
echo "FAKE_LINGER $2"
`;
const FAKE_SYSTEMCTL = `#!/bin/sh
[ "$*" = '--user enable --now podman.socket' ] || exit 2
mkdir -p "$XDG_RUNTIME_DIR/podman" && rm -f "$XDG_RUNTIME_DIR/podman/podman.sock" && ${UNIX_SOCKET} "$XDG_RUNTIME_DIR/podman/podman.sock" || exit 1
echo "FAKE_SOCKET $(id -un)"
`;
/** `docker` falso: contenedores en marcha que solo tienen /bin/sh (no bash). */
const FAKE_DOCKER = `#!/bin/sh
case "$1" in
  inspect) echo true ;;
  exec)
    shift
    if [ "$1" = -it ]; then
      shift
      [ -t 0 ] || { echo "the input device is not a TTY" >&2; exit 1; }
      id=$1; shift
      echo "DOCKER_EXEC $id $1"
      exec "$@"
    fi
    shift
    [ "$1" = /bin/sh ] && exit 0
    exit 1 ;;
esac
`;

const ED25519_FP = /^\d+ (SHA256:[A-Za-z0-9+/]{43}) .*\(ED25519\)$/m;

/**
 * Terminal de extremo a extremo (sesión 21): API real (escuchando), el modo `gateway` del worker
 * compilado, OpenBao real (rol y AppRole de la terminal) y un sshd real con el acceso de
 * administración instalado por el script de alta. `pct` y `docker` son falsos en el servidor.
 */
describe('Terminal a través del gateway (e2e)', () => {
  let sshd: TestSshd;
  let bao: OpenBaoTestServer;
  let appRole: TestAppRole;
  let app: NestFastifyApplication;
  let db: DataSource;
  let gateway: TestWorker | undefined;
  let gatewayUrl: string;
  let gatewayEnv: Record<string, string>;
  let apiUrl: string;
  let adminToken: string;
  let secret: string;
  const responses: string[] = [];
  /** Salida de los gateways ya parados (el de la prueba de parada se relanza). */
  const gatewayLogs: string[] = [];
  const ids: Record<'server' | 'ct' | 'container' | 'ctContainer' | 'noAdmin' | 'domain', string> = {
    server: '',
    ct: '',
    container: '',
    ctContainer: '',
    noAdmin: '',
    domain: '',
  };

  async function ticket(
    token: string,
    assetId: string,
    action?: object,
  ): Promise<{ status: number; body: CreateTerminalSessionResponse & { code?: string } }> {
    const res = await app.inject({
      method: 'POST',
      url: '/terminal/sessions',
      headers: authHeaders(token),
      payload: action ? { assetId, action } : { assetId },
    });
    responses.push(JSON.stringify(res.headers), res.body);
    return { status: res.statusCode, body: res.json() };
  }

  /** Abre una terminal con la cookie de la sesión que pidió el ticket (como el navegador). */
  async function open(
    assetId: string,
    size?: { cols: number; rows: number },
    token = adminToken,
  ) {
    const { status, body } = await ticket(token, assetId);
    expect(status, JSON.stringify(body)).toBe(201);
    const terminal = await TestTerminal.open(body.gatewayUrl, body.ticket, size, {
      cookie: authHeaders(token).cookie!,
    });
    return { terminal, sessionId: body.sessionId, ticket: body.ticket };
  }

  /**
   * Como admin con la sesión recién reautenticada (conceder y desactivar piden step-up). Se marca
   * en la sesión en lugar de volver a entrar: cada login con TOTP gasta un paso de 30 s.
   */
  async function asAdmin(method: 'POST' | 'DELETE', url: string, payload?: object) {
    await db.query(`UPDATE user_sessions SET reauthenticated_at = now() WHERE csrf_token = $1`, [
      adminToken.split(' ')[1],
    ]);
    return app.inject({ method, url, headers: authHeaders(adminToken), payload });
  }

  async function row(sessionId: string) {
    const [r]: Record<string, unknown>[] = await db.query(
      'SELECT * FROM terminal_sessions WHERE id = $1',
      [sessionId],
    );
    return r!;
  }

  /**
   * Acciones auditadas de una sesión (y de una regla), en orden, cuando ya está la última que se
   * espera. La API marca la sesión `closed` y escribe la auditoría justo después, en otra
   * sentencia: ver `closed` en la fila no garantiza que ya esté `terminal.session_closed`.
   */
  async function auditedActions(
    sessionId: string,
    last: string,
    ruleId: string | null = null,
  ): Promise<string[]> {
    let actions: string[] = [];
    await waitFor(
      async () => {
        const rows: { action: string }[] = await db.query(
          `SELECT action FROM audit_events
            WHERE details->>'sessionId' = $1 OR details->>'ruleId' = $2
            ORDER BY occurred_at, id`,
          [sessionId, ruleId],
        );
        actions = rows.map((r) => r.action);
        return actions.includes(last);
      },
      10_000,
      () => `auditoría sin ${last}: ${JSON.stringify(actions)}`,
    );
    return actions;
  }

  async function insertAsset(
    type: string,
    name: string,
    extra: { facts?: object; connection?: object; roles?: string[]; adminAccess?: object | null } = {},
  ): Promise<string> {
    const [r]: { id: string }[] = await db.query(
      `INSERT INTO assets (type, discovered_name, status, facts, connection, roles, ssh_auth, host_key_fingerprint, admin_access)
       VALUES ($1, $2, 'active', $3, $4, $5, 'ca_certificate', $6, $7) RETURNING id`,
      [
        type,
        name,
        extra.facts ?? {},
        extra.connection ?? null,
        extra.roles ?? [],
        extra.connection ? hostFingerprint : null,
        extra.adminAccess ?? null,
      ],
    );
    return r!.id;
  }
  let hostFingerprint = '';

  /** Editor nuevo con su contraseña y, si se pide, TOTP (recién reautenticado). */
  async function editorToken(
    email = 'editora@infraward.test',
    totp = false,
  ): Promise<{ token: string; id: string }> {
    const created = await app.inject({
      method: 'POST',
      url: '/users',
      headers: authHeaders(adminToken),
      payload: { email, name: 'Editora', role: 'editor' },
    });
    expect(created.statusCode).toBe(201);
    const { temporaryPassword: temporary, user } = created.json<TemporaryPasswordResponse>();
    const limited = sessionToken(await login(app, email, temporary));
    const changed = await app.inject({
      method: 'POST',
      url: '/auth/password',
      headers: authHeaders(limited),
      payload: { currentPassword: temporary, newPassword: 'otra-contraseña-larga' },
    });
    expect(changed.statusCode).toBe(200);
    const token = await loginToken(app, email, 'otra-contraseña-larga');
    if (totp) await enableTotp(app, email, token);
    return { token, id: user.id };
  }

  beforeAll(async () => {
    // La preparación construye la imagen del sshd dentro del dind del CI (apt-get) antes de nada:
    // se registra cada fase para que un paso lento o atascado se vea en el log del job. Con el
    // runner ocupado (los tests de integración construyen las mismas imágenes a la vez) pasa de
    // 5 min: el mismo margen que el `beforeAll` de esos tests.
    const t0 = Date.now();
    const phase = <T>(name: string, step: Promise<T>): Promise<T> => {
      console.log(`[terminal e2e] ${name}…`);
      return step.then((value) => {
        console.log(`[terminal e2e] ${name}: ${((Date.now() - t0) / 1000).toFixed(1)} s`);
        return value;
      });
    };
    [sshd, bao] = await Promise.all([
      phase('sshd', startSshd()),
      phase('openbao', startOpenBaoTestServer()),
    ]);
    appRole = await createTestAppRole(bao);
    const terminalRole = await createTestTerminalAppRole(bao, appRole);
    const provider = new OpenBaoSecretProvider(
      loadOpenBaoConfig({
        addr: bao.addr,
        roleId: appRole.roleId,
        secretId: appRole.secretId,
        kvMount: appRole.kvMount,
        approleMount: appRole.approleMount,
        kvPrefix: appRole.kvPrefix,
        sshMount: appRole.sshMount,
        sshRole: appRole.sshRole,
      }),
    );
    const caKeys = (await provider.sshCaPublicKeys()).map((k) => k.publicKey);
    await provider.close();

    // El servidor: script de alta en modo CA con el acceso de administración.
    const script = EnrollScriptTemplate.load().render({
      mode: 'embedded',
      apiUrl: '',
      token: '',
      authMode: 'ca_certificate',
      publicKey: '',
      keyComment: keyComment('00000000-0000-4000-8000-000000000021'),
      sudoersVersion: SUDOERS_VERSION,
      caKeys,
      caVersion: SSH_CA_CONFIG_VERSION,
      issuedAt: Math.floor(Date.now() / 1000),
      adminAccess: 'operator',
      adminAccessVersion: ADMIN_ACCESS_VERSION,
    });
    const enrolled = await phase('enroll', sshd.root(embeddedCommand(script)));
    expect(enrolled.code, enrolled.stderr).toBe(0);
    for (const [path, body] of [
      ['/usr/local/sbin/pct', FAKE_PCT],
      ['/usr/local/bin/docker', FAKE_DOCKER],
      ['/usr/local/bin/loginctl', FAKE_LOGINCTL],
      ['/usr/local/bin/systemctl', FAKE_SYSTEMCTL],
    ] as const) {
      const r = await sshd.root(
        `printf '%s' '${body.replaceAll("'", `'\\''`)}' > ${path} && chmod 755 ${path}`,
      );
      expect(r.code, r.stderr).toBe(0);
    }
    hostFingerprint = ED25519_FP.exec(
      execFileSync('ssh-keygen', ['-lf', '-'], {
        input: execFileSync('ssh-keyscan', ['-t', 'ed25519', '-p', String(sshd.port), sshd.host]),
      }).toString(),
    )![1]!;

    secret = randomBytes(32).toString('base64url');
    const secretFile = join(mkdtempSync(join(tmpdir(), 'infraward-e2e-gw-')), 'gateway.secret');
    writeFileSync(secretFile, `${secret}\n`, { mode: 0o600 });
    const gatewayPort = await freePort();
    gatewayUrl = `ws://127.0.0.1:${gatewayPort}`;
    await prepareEnv('e2e_terminal', {
      LOGIN_THROTTLE_LIMIT: '100',
      OPENBAO_ADDR: bao.addr,
      OPENBAO_KV_MOUNT: appRole.kvMount,
      OPENBAO_APPROLE_MOUNT: appRole.approleMount,
      OPENBAO_SSH_MOUNT: appRole.sshMount,
      OPENBAO_ROLE_ID: appRole.roleId,
      TERMINAL_OPENBAO_ROLE_ID: terminalRole.roleId,
      TERMINAL_OPENBAO_SECRET_ID: terminalRole.secretId,
      TERMINAL_OPENBAO_SECRET_ID_FILE: '',
      TERMINAL_OPENBAO_SSH_ROLE: terminalRole.sshRole,
      GATEWAY_API_SECRET_FILE: secretFile,
      GATEWAY_PUBLIC_URL: gatewayUrl,
      // Latido y barrido rápidos para probar el gateway que muere sin pararse.
      TERMINAL_HEARTBEAT_TIMEOUT: '6',
      TERMINAL_SWEEP_INTERVAL: '1',
    });
    app = await phase('api', createTestApp());
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    apiUrl = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
    db = app.get(DataSource);

    const adminAccess = {
      mode: 'operator',
      account: 'infraward-admin',
      version: 1,
      enabledAt: new Date().toISOString(),
    };
    const connection = { host: sshd.host, port: sshd.port, user: 'inventory' };
    ids.server = await insertAsset('server', 'srv-terminal', {
      connection,
      roles: ['proxmox-node', 'docker-host'],
      adminAccess,
    });
    ids.ct = await insertAsset('lxc', 'ct-101', {
      roles: ['docker-host'],
      facts: { proxmox: { vmid: 101, kind: 'lxc', node: 'pve', status: 'running' } },
    });
    ids.container = await insertAsset('container', 'web-solo-sh', {
      facts: { docker: { id: 'a'.repeat(64) } },
    });
    ids.ctContainer = await insertAsset('container', 'web-en-ct', {
      facts: { docker: { id: 'b'.repeat(64) } },
    });
    ids.noAdmin = await insertAsset('server', 'srv-sin-acceso', { connection });
    ids.domain = await insertAsset('domain', 'ejemplo.test');
    for (const [parent, child] of [
      [ids.server, ids.ct],
      [ids.server, ids.container],
      [ids.ct, ids.ctContainer],
    ])
      await db.query(
        `INSERT INTO asset_relations (parent_id, child_id, type) VALUES ($1, $2, 'contains')`,
        [parent, child],
      );

    gatewayEnv = {
      GATEWAY_PORT: String(gatewayPort),
      GATEWAY_HOST: '127.0.0.1',
      GATEWAY_API_URL: apiUrl,
      GATEWAY_API_SECRET_FILE: secretFile,
      GATEWAY_SHUTDOWN_GRACE: '3',
      GATEWAY_HEARTBEAT_INTERVAL: '1',
      WEB_ORIGIN: 'https://infraward.test',
      SSH_CONNECT_TIMEOUT: '10',
      WORKER_TMP_DIR: mkdtempSync(join(tmpdir(), 'iw-gw-')),
    };
    gateway = await phase('gateway', startGateway(gatewayEnv));
    adminToken = await loginToken(app, ADMIN.email, ADMIN.password);
  }, 600_000);

  afterAll(async () => {
    if (process.env.TERMINAL_E2E_DEBUG) console.log(sshd?.logs().split('\n').slice(-60).join('\n'));
    await stopWorker(gateway);
    await app?.close();
    await appRole?.cleanup();
    await Promise.all([sshd?.stop(), bao?.stop()]);
  });

  it('el gateway no arranca con variables del gestor de secretos', async () => {
    await expect(
      startGateway({ ...gatewayEnv, GATEWAY_PORT: '0', OPENBAO_ADDR: bao.addr }),
    ).rejects.toThrow(/no accede al gestor de secretos: quita OPENBAO_ADDR/);
  });

  it('shell en el servidor con la cuenta de administración, PTY, redimensionado y key_id en el log', async () => {
    const { terminal, sessionId } = await open(ids.server, { cols: 100, rows: 30 });
    await terminal.until((t) => !!t.message('ready'), 'ready');
    expect(terminal.message('ready')).toMatchObject({ account: 'infraward-admin', asset: 'srv-terminal' });
    terminal.type('stty size; id -un; tty; sudo -n true && echo SUDO_OK\r');
    await terminal.waitOutput('SUDO_OK');
    expect(terminal.output).toContain('30 100');
    expect(terminal.output).toContain('infraward-admin');
    expect(terminal.output).toMatch(/\/dev\/pts\/\d+/);
    terminal.resize(132, 40);
    await new Promise((r) => setTimeout(r, 300));
    terminal.type('stty size\r');
    await terminal.waitOutput('40 132');
    terminal.type('exit 3\r');
    const exit = await terminal.waitExit();
    expect(exit).toMatchObject({ reason: 'exit', code: 3 });

    // auth.log del servidor: la cuenta, el certificado y el key_id con la sesión y la persona.
    expect(
      await sshd.waitForLog(
        `ID infraward:session=${sessionId}:user=${ADMIN.email}:asset=${ids.server}`,
      ),
    ).toBe(true);
    const accepted = sshd.logs().split('\n').find((l) => l.includes(`session=${sessionId}`))!;
    expect(accepted).toMatch(/Accepted publickey for infraward-admin .* ED25519-CERT/);

    await waitFor(async () => (await row(sessionId)).state === 'closed', 10_000, () => 'cierre');
    const closed = await row(sessionId);
    expect(closed).toMatchObject({ close_reason: 'exit', exit_code: 3, gateway: 'gateway-1' });
    expect(closed.ticket_hash).toBeNull();
    expect(await auditedActions(sessionId, 'terminal.session_closed')).toEqual([
      'terminal.session_requested',
      'terminal.session_opened',
      'terminal.session_closed',
    ]);
  });

  it('CT: sudo pct enter <vmid>; contenedor: docker exec -it con la shell que tiene (sh)', async () => {
    const ct = await open(ids.ct);
    await ct.terminal.waitOutput('PCT_ENTER 101');
    ct.terminal.type('exit\r');
    await ct.terminal.waitExit();

    const container = await open(ids.container);
    await container.terminal.waitOutput(`DOCKER_EXEC ${'a'.repeat(64)} /bin/sh`);
    container.terminal.type('tty && exit 0\r');
    await container.terminal.waitOutput(/\/dev\/pts\/\d+/);
    expect((await container.terminal.waitExit()).code).toBe(0);

    // Contenedor dentro de un CT: pct exec del CT y, dentro, docker exec -it.
    const nested = await open(ids.ctContainer);
    await nested.terminal.waitOutput(`DOCKER_EXEC ${'b'.repeat(64)} /bin/sh`);
    expect(nested.terminal.output).toContain('PCT_EXEC 101');
    nested.terminal.type('exit\r');
    await nested.terminal.waitExit();
  });

  it('el ticket vale una vez; sin acceso de administración o en otro tipo de asset, 409', async () => {
    const { terminal, ticket: used } = await open(ids.server);
    await terminal.until((t) => !!t.message('ready'), 'ready');
    const again = await TestTerminal.open(`${gatewayUrl}/terminal`, used);
    expect(await again.waitExit()).toMatchObject({ reason: 'denied' });
    terminal.type('exit\r');
    await terminal.waitExit();

    const noAdmin = await ticket(adminToken, ids.noAdmin);
    expect(noAdmin.status).toBe(409);
    expect(JSON.stringify(noAdmin.body)).toMatch(/no tiene el acceso interactivo/);
    expect((await ticket(adminToken, ids.domain)).status).toBe(409);
  });

  it('«Habilitar Podman»: terminal de solo lectura con el comando fijo, solo para usuarios detectados', async () => {
    const created = await sshd.root('useradd -m -u 1500 podalice && rm -f /etc/infraward/podman-users');
    expect(created.code, created.stderr).toBe(0);
    const user = (name: string, uid: number, enabled = false) => ({
      uid, name, enabled, socket: false, storage: true, linger: false, containers: 1,
    });
    await db.query(`UPDATE assets SET facts = $2 WHERE id = $1`, [
      ids.server,
      { detected: { podman: '5.4.2', podmanUsers: [user('podalice', 1500), user('ya', 1501, true)] } },
    ]);
    // Usuarios que no están detectados, nombres raros o acciones desconocidas: nunca llegan al servidor.
    const notDetected = await ticket(adminToken, ids.server, { kind: 'podman-enable', users: ['root'] });
    expect(notDetected.status).toBe(409);
    expect(
      (await ticket(adminToken, ids.server, { kind: 'podman-enable', users: ['a;id'] })).status,
    ).toBe(400);
    expect((await ticket(adminToken, ids.server, { kind: 'shell', users: ['podalice'] })).status).toBe(
      400,
    );
    expect(
      (await ticket(adminToken, ids.container, { kind: 'podman-enable', users: ['podalice'] })).status,
    ).toBe(409);

    const action = { kind: 'podman-enable', users: ['podalice'] };
    const { status, body } = await ticket(adminToken, ids.server, action);
    expect(status, JSON.stringify(body)).toBe(201);
    const terminal = await TestTerminal.open(body.gatewayUrl, body.ticket, undefined, {
      cookie: authHeaders(adminToken).cookie!,
    });
    await terminal.until((t) => !!t.message('ready'), 'ready');
    expect(terminal.message('ready')).toMatchObject({ readOnly: true, account: 'infraward-admin' });
    await terminal.waitOutput('+ loginctl enable-linger podalice');
    terminal.type('echo TECLEADO\r');
    await terminal.waitOutput('Listo: vuelve a recolectar');
    const exit = await terminal.waitExit();
    expect(exit, terminal.output).toMatchObject({ reason: 'exit', code: 0 });
    expect(terminal.output).toContain('FAKE_LINGER podalice');
    expect(terminal.output).toContain('FAKE_SOCKET podalice');
    expect(terminal.output).toContain('Socket: /run/user/1500/podman/podman.sock');
    expect(terminal.output).not.toContain('TECLEADO');
    const list = await sshd.root('cat /etc/infraward/podman-users; stat -c %a /etc/infraward/podman-users');
    expect(list.stdout).toMatch(/^podalice$/m);
    expect(list.stdout.trim().endsWith('644')).toBe(true);

    await waitFor(async () => (await row(body.sessionId)).state === 'closed', 10_000, () => 'cierre');
    expect((await row(body.sessionId)).action).toEqual(action);
    await auditedActions(body.sessionId, 'terminal.session_closed');
    const [requested]: { details: { action?: unknown; actionUsers?: unknown } }[] = await db.query(
      `SELECT details FROM audit_events WHERE action = 'terminal.session_requested' AND details->>'sessionId' = $1`,
      [body.sessionId],
    );
    expect(requested!.details).toMatchObject({ action: 'podman-enable', actionUsers: ['podalice'] });
    await db.query(`UPDATE assets SET facts = '{}' WHERE id = $1`, [ids.server]);
  });

  it('sin permiso (editor), sin reautenticación reciente o con un token de API: rechazado', async () => {
    const { token: editor } = await editorToken();
    // 403 sin pedir reautenticación (el permiso va antes) y sin botón en la ficha.
    const denied = await ticket(editor, ids.server);
    expect(denied.status).toBe(403);
    expect(denied.body.code).toBeUndefined();
    const status = await app.inject({
      method: 'GET',
      url: `/assets/${ids.server}/terminal`,
      headers: authHeaders(editor),
    });
    expect(status.json()).toMatchObject({ allowed: false, available: false, reason: null });

    const stale = await loginToken(app, ADMIN.email, ADMIN.password);
    await db.query(
      `UPDATE user_sessions SET reauthenticated_at = now() - interval '11 minutes' WHERE csrf_token = $1`,
      [stale.split(' ')[1]],
    );
    const old = await ticket(stale, ids.server);
    expect(old.status).toBe(403);
    expect(old.body).toMatchObject({ code: 'recent_auth_required', action: 'terminal.open' });

    const created = await app.inject({
      method: 'POST',
      url: '/auth/tokens',
      headers: authHeaders(adminToken),
      payload: { name: 'terminal', scope: 'role', expiresAt: new Date(Date.now() + 86_400_000).toISOString() },
    });
    expect(created.statusCode).toBe(201);
    const bearer = created.json<{ secret: string }>().secret;
    const viaToken = await app.inject({
      method: 'POST',
      url: '/terminal/sessions',
      headers: { authorization: `Bearer ${bearer}` },
      payload: { assetId: ids.server },
    });
    expect(viaToken.statusCode).toBe(403);
  });

  it('rutas internas: sin el secreto del gateway, 401', async () => {
    for (const authorization of [undefined, 'Gateway otro-secreto-que-no-es-el-bueno-de-verdad', `Bearer ${secret}`]) {
      const res = await fetch(`${apiUrl}/internal/gateway/sessions/redeem`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(authorization && { authorization }) },
        body: JSON.stringify({ ticket: 'x'.repeat(43), gateway: 'gateway-1', sessionCookieHash: null }),
      });
      expect(res.status).toBe(401);
    }
    const ok = await fetch(`${apiUrl}/internal/gateway/sessions/redeem`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Gateway ${secret}` },
      body: JSON.stringify({ ticket: 'x'.repeat(43), gateway: 'gateway-1', sessionCookieHash: null }),
    });
    expect(ok.status).toBe(404);
    const beat = await fetch(`${apiUrl}/internal/gateway/heartbeat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ gateway: 'gateway-1', sessions: [] }),
    });
    expect(beat.status).toBe(401);
  });

  it('reiniciar el worker de jobs no corta la terminal abierta', async () => {
    const workers: TestWorker[] = [await startWorker()];
    try {
      const { terminal } = await open(ids.server);
      await terminal.until((t) => !!t.message('ready'), 'ready');
      await stopWorker(workers[0]);
      workers.push(await startWorker());
      terminal.type('echo SIGUE_VIVA\r');
      await terminal.waitOutput('SIGUE_VIVA');
      await stopWorker(workers[1]);
      terminal.type('exit\r');
      expect((await terminal.waitExit()).reason).toBe('exit');
    } finally {
      for (const w of workers) await stopWorker(w);
    }
  });

  it('parada del gateway: aviso y cierre limpio al agotarse la gracia', async () => {
    const { terminal, sessionId } = await open(ids.server);
    await terminal.until((t) => !!t.message('ready'), 'ready');
    const exited = new Promise((done) => gateway!.child.once('exit', done));
    gateway!.child.kill('SIGTERM');
    await terminal.until((t) => !!t.message('notice'), 'el aviso');
    expect(terminal.message('notice')!.message).toMatch(/se va a reiniciar.*3 s/);
    expect(terminal.output).toContain('[InfraWard] El gateway se va a reiniciar');
    const exit = await terminal.waitExit(15_000);
    expect(exit.reason).toBe('gateway_shutdown');
    expect((await terminal.closed).code).toBe(1001);
    await exited;
    // Parada ordenada completa (Nest vuelve a lanzar la señal al terminar: sale por SIGTERM).
    expect(gateway!.output.join('')).toContain('Cerrando 1 terminales que siguen abiertas');
    expect(gateway!.child.signalCode ?? gateway!.child.exitCode).toMatch(/SIGTERM|^0$/);
    expect(await row(sessionId)).toMatchObject({ state: 'closed', close_reason: 'gateway_shutdown' });
    gatewayLogs.push(gateway!.output.join(''));
    gateway = await startGateway(gatewayEnv);
  });

  it('el WebSocket exige la cookie de la sesión que pidió el ticket y el Origin de la web', async () => {
    // Sin cookie: el ticket solo no basta.
    const bare = await ticket(adminToken, ids.server);
    const noCookie = await TestTerminal.open(bare.body.gatewayUrl, bare.body.ticket);
    expect(await noCookie.waitExit()).toMatchObject({
      reason: 'denied',
      message: expect.stringMatching(/solo se abre desde la sesión de InfraWard que la pidió/),
    });
    expect(await row(bare.body.sessionId)).toMatchObject({ state: 'rejected', close_reason: 'denied' });

    // Con la cookie de otra sesión (aunque sea de la misma persona), tampoco.
    const other = await loginToken(app, ADMIN.email, ADMIN.password);
    const mine = await ticket(adminToken, ids.server);
    const wrong = await TestTerminal.open(mine.body.gatewayUrl, mine.body.ticket, undefined, {
      cookie: authHeaders(other).cookie!,
    });
    expect((await wrong.waitExit()).reason).toBe('denied');

    // Otro origen: el upgrade se rechaza antes de mandar nada (ni se gasta el ticket).
    const fresh = await ticket(adminToken, ids.server);
    await expect(
      TestTerminal.open(fresh.body.gatewayUrl, fresh.body.ticket, undefined, {
        cookie: authHeaders(adminToken).cookie!,
        origin: 'https://otra-web.example',
      }),
    ).rejects.toThrow(/403/);
    expect((await row(fresh.body.sessionId)).state).toBe('pending');
    // El de la web sí.
    const web = await TestTerminal.open(fresh.body.gatewayUrl, fresh.body.ticket, undefined, {
      cookie: authHeaders(adminToken).cookie!,
      origin: 'https://infraward.test',
    });
    await web.until((t) => !!t.message('ready'), 'ready');
    web.type('exit\r');
    await web.waitExit();
  }, 150_000);

  it('regla por etiqueta: el editor abre terminal solo en esos assets; quitar la regla la corta', async () => {
    const { token: editor, id: editorId } = await editorToken('editor-etiqueta@infraward.test', true);
    await db.query(`UPDATE assets SET tags = '{web}' WHERE id = $1`, [ids.container]);
    // Conceder exige reautenticación reciente (step-up) y no admite reglas repetidas.
    await db.query(
      `UPDATE user_sessions SET reauthenticated_at = now() - interval '11 minutes' WHERE csrf_token = $1`,
      [adminToken.split(' ')[1]],
    );
    const rule = { permission: 'terminal.open', subjectType: 'user', userId: editorId, scope: 'tag', tag: 'web' };
    const notFresh = await app.inject({
      method: 'POST',
      url: '/access-policies',
      headers: authHeaders(adminToken),
      payload: rule,
    });
    expect(notFresh.json()).toMatchObject({ code: 'recent_auth_required', action: 'access.grant' });
    const granted = await asAdmin('POST', '/access-policies', rule);
    expect(granted.statusCode, granted.body).toBe(201);
    expect((await asAdmin('POST', '/access-policies', rule)).statusCode).toBe(409);

    // Solo en el contenedor con la etiqueta: ni en su servidor ni en el CT.
    expect((await ticket(editor, ids.server)).status).toBe(403);
    expect((await ticket(editor, ids.ct)).status).toBe(403);
    const status = await app.inject({
      method: 'GET',
      url: `/assets/${ids.container}/terminal`,
      headers: authHeaders(editor),
    });
    expect(status.json()).toMatchObject({ allowed: true, available: true, account: 'infraward-admin' });
    const { terminal, sessionId } = await open(ids.container, undefined, editor);
    await terminal.until((t) => !!t.message('ready'), 'ready');
    // El gateway solo manda `ready` cuando la API ha registrado la apertura (`/opened`): para
    // entonces la sesión está `active` y su apertura, ya en la auditoría.
    expect((await row(sessionId)).state).toBe('active');
    const opened: unknown[] = await db.query(
      `SELECT 1 FROM audit_events WHERE action = 'terminal.session_opened' AND details->>'sessionId' = $1`,
      [sessionId],
    );
    expect(opened).toHaveLength(1);

    // El admin retira la regla: la terminal se corta al momento, con el motivo dentro.
    const ruleId = granted.json<{ id: string }>().id;
    expect((await asAdmin('DELETE', `/access-policies/${ruleId}`)).statusCode).toBe(204);
    const exit = await terminal.waitExit(10_000);
    expect(exit).toMatchObject({ reason: 'revoked' });
    expect(exit.message).toMatch(/Ya no tienes permiso para abrir terminales en web-solo-sh/);
    expect(terminal.output).toContain('[InfraWard] Ya no tienes permiso');
    await waitFor(async () => (await row(sessionId)).state === 'closed', 10_000, () => 'cierre');
    expect(await row(sessionId)).toMatchObject({ close_reason: 'revoked' });
    expect(await auditedActions(sessionId, 'terminal.session_closed', ruleId)).toEqual([
      'access.granted',
      'terminal.session_requested',
      'terminal.session_opened',
      'access.revoked',
      'terminal.session_revoked',
      'terminal.session_closed',
    ]);
  }, 150_000);

  it('regla en un servidor (heredada por lo que contiene) y desactivar a la persona la corta', async () => {
    const { token: editor, id: editorId } = await editorToken('editor-nodo@infraward.test', true);
    const granted = await asAdmin('POST', '/access-policies', {
      permission: 'terminal.open',
      subjectType: 'user',
      userId: editorId,
      scope: 'asset',
      assetId: ids.server,
    });
    expect(granted.statusCode, granted.body).toBe(201);
    const access = await app.inject({
      method: 'GET',
      url: `/assets/${ids.ctContainer}/access`,
      headers: authHeaders(adminToken),
    });
    expect(access.json().entries).toEqual([
      expect.objectContaining({ source: { kind: 'inherited', assetId: ids.server }, sourceName: 'srv-terminal' }),
    ]);
    const { terminal, sessionId } = await open(ids.ctContainer, undefined, editor);
    await terminal.until((t) => !!t.message('ready'), 'ready');
    expect((await asAdmin('POST', `/users/${editorId}/deactivate`)).statusCode).toBe(200);
    const exit = await terminal.waitExit(10_000);
    expect(exit.reason).toBe('revoked');
    expect(exit.message).toMatch(/cuenta de InfraWard está desactivada|sesión de InfraWard desde la que se abrió/);
    await waitFor(async () => (await row(sessionId)).state === 'closed', 10_000, () => 'cierre');
  }, 150_000);

  it('cerrar la sesión web corta sus terminales al momento', async () => {
    const session = await loginToken(app, ADMIN.email, ADMIN.password);
    const { terminal, sessionId } = await open(ids.server, undefined, session);
    await terminal.until((t) => !!t.message('ready'), 'ready');
    const started = Date.now();
    const out = await app.inject({ method: 'POST', url: '/auth/logout', headers: authHeaders(session) });
    expect(out.statusCode).toBe(200);
    const exit = await terminal.waitExit(10_000);
    // Por el canal de Redis, sin esperar al latido.
    expect(Date.now() - started).toBeLessThan(3000);
    expect(exit).toMatchObject({
      reason: 'revoked',
      message: 'Se ha cerrado la sesión de InfraWard desde la que se abrió la terminal',
    });
    expect(terminal.message('notice')!.message).toMatch(/Se ha cerrado la sesión/);
    await waitFor(async () => (await row(sessionId)).state === 'closed', 10_000, () => 'cierre');
    expect(await row(sessionId)).toMatchObject({ close_reason: 'revoked' });
  }, 150_000);

  it('el latido mantiene la sesión; si el gateway muere sin pararse, el barrido la cierra', async () => {
    const { terminal, sessionId } = await open(ids.server);
    await terminal.until((t) => !!t.message('ready'), 'ready');
    // Con latido cada segundo y 6 s de margen, sigue viva pasado el margen.
    await new Promise((r) => setTimeout(r, 7000));
    expect((await row(sessionId)).state).toBe('active');
    expect(new Date((await row(sessionId)).heartbeat_at as string).getTime()).toBeGreaterThan(
      Date.now() - 3000,
    );
    const exited = new Promise((done) => gateway!.child.once('exit', done));
    gateway!.child.kill('SIGKILL');
    await exited;
    await waitFor(async () => (await row(sessionId)).state === 'closed', 20_000, () => 'barrido');
    expect(await row(sessionId)).toMatchObject({
      close_reason: 'gateway_lost',
      close_message: expect.stringMatching(/El gateway gateway-\d+ dejó de responder/),
    });
    // La auditoría se escribe justo después del cierre.
    await waitFor(
      async () =>
        (
          await db.query(
            `SELECT 1 FROM audit_events WHERE details->>'sessionId' = $1 AND action = 'terminal.session_closed' AND details->>'reason' = 'gateway_lost'`,
            [sessionId],
          )
        ).length === 1,
      5000,
      () => 'auditoría del barrido',
    );
    gatewayLogs.push(gateway!.output.join(''));
    gateway = await startGateway(gatewayEnv);
  });

  it('0 fugas: ni tickets, ni claves, ni certificados en la BD, la auditoría ni los logs', async () => {
    const tables = JSON.stringify(
      await db.query(
        `SELECT (SELECT json_agg(t) FROM terminal_sessions t) AS s, (SELECT json_agg(a) FROM audit_events a) AS a`,
      ),
    );
    const gatewayOutput = gatewayLogs.join('') + gateway!.output.join('');
    const logs = gatewayOutput + responses.filter((r) => !r.includes('"ticket"')).join('');
    // Ni la cookie de la sesión ni su hash salen del gateway (solo viaja a la API al canjear).
    const cookie = authHeaders(adminToken).cookie!.split('=')[1]!;
    const cookieHash = createHash('sha256').update(cookie).digest('hex');
    for (const text of [tables, logs]) {
      expect(text).not.toMatch(/-cert-v01@openssh\.com/);
      expect(text).not.toContain('PRIVATE KEY');
      expect(text).not.toContain(secret);
      expect(text).not.toContain(cookieHash);
    }
    expect(gatewayOutput).not.toContain(cookie);
    // Los tickets solo salen en la respuesta de POST /terminal/sessions, nunca en la BD.
    const tickets = responses
      .map((r) => /"ticket":"([A-Za-z0-9_-]+)"/.exec(r)?.[1])
      .filter((t): t is string => !!t);
    expect(tickets.length).toBeGreaterThan(3);
    for (const t of tickets) {
      expect(tables).not.toContain(t);
      expect(gatewayOutput).not.toContain(t);
    }
  });
});
