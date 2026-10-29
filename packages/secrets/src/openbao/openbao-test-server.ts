// Utilidades de test para OpenBao (subpath `@infraward/secrets/testing/openbao`; no van en index).
// El token root solo se usa aquí, para preparar el escenario; el proveedor entra por AppRole.
import { randomBytes } from 'node:crypto';

export const OPENBAO_TEST_IMAGE = 'quay.io/openbao/openbao:2.6.4';

export interface OpenBaoTestServer {
  addr: string;
  rootToken: string;
  stop(): Promise<void>;
}

export interface TestAppRole {
  kvMount: string;
  approleMount: string;
  roleId: string;
  secretId: string;
  /** Prefijo permitido por la política del rol dentro del KV. */
  kvPrefix: string;
  /** Motor SSH en modo CA (con un emisor ed25519 y el rol `inventory`, como bootstrap.sh). */
  sshMount: string;
  sshRole: string;
  /** Desmonta el KV y el AppRole creados. */
  cleanup(): Promise<void>;
}

/**
 * OpenBao para tests: OPENBAO_TEST_ADDR + OPENBAO_TEST_ROOT_TOKEN si están (p. ej. el service
 * de CI o el del compose), o un contenedor efímero en modo `-dev` con Testcontainers.
 */
export async function startOpenBaoTestServer(): Promise<OpenBaoTestServer> {
  const addr = process.env.OPENBAO_TEST_ADDR;
  const rootToken = process.env.OPENBAO_TEST_ROOT_TOKEN;
  if (addr && rootToken) {
    return { addr: addr.replace(/\/+$/, ''), rootToken, stop: async () => {} };
  }
  // Ryuk no funciona con Podman rootless; el contenedor se para en stop().
  process.env.TESTCONTAINERS_RYUK_DISABLED ??= 'true';
  const { GenericContainer, Wait } = await import('testcontainers');
  const token = `root-${randomBytes(12).toString('hex')}`;
  const container = await new GenericContainer(OPENBAO_TEST_IMAGE)
    .withCommand([
      'server',
      '-dev',
      `-dev-root-token-id=${token}`,
      '-dev-listen-address=0.0.0.0:8200',
    ])
    .withExposedPorts(8200)
    .withWaitStrategy(Wait.forHttp('/v1/sys/health', 8200).forStatusCode(200))
    .start();
  return {
    addr: `http://${container.getHost()}:${container.getMappedPort(8200)}`,
    rootToken: token,
    stop: async () => {
      await container.stop();
    },
  };
}

/** Petición con el token root. Lanza si el estado no es 2xx. */
export async function rootRequest(
  server: OpenBaoTestServer,
  method: string,
  path: string,
  body?: unknown,
): Promise<Record<string, unknown> | null> {
  const res = await fetch(`${server.addr}/v1/${path}`, {
    method,
    headers: {
      'X-Vault-Token': server.rootToken,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status >= 300) {
    throw new Error(`OpenBao ${method} ${path}: HTTP ${res.status}`);
  }
  return res.status === 204
    ? null
    : ((await res.json()) as Record<string, unknown>);
}

/**
 * Crea un KV v2 y un AppRole con nombres únicos, una política limitada a `<kv>/…/<prefijo>/*`
 * (como la de bootstrap.sh) y un secret_id.
 */
export async function createTestAppRole(
  server: OpenBaoTestServer,
  options: {
    tokenTtl?: string;
    tokenMaxTtl?: string;
    kvPrefix?: string;
    /** max_ttl del rol SSH (para probar certificados caducados con TTL corto). */
    certMaxTtl?: string;
  } = {},
): Promise<TestAppRole> {
  const id = randomBytes(4).toString('hex');
  const kvMount = `kv-${id}`;
  const approleMount = `approle-${id}`;
  const kvPrefix = options.kvPrefix ?? 'infraward';
  const policy = `infraward-${id}`;
  const sshMount = `ssh-${id}`;
  const sshRole = 'inventory';
  await rootRequest(server, 'POST', `sys/mounts/${kvMount}`, {
    type: 'kv',
    options: { version: '2' },
  });
  await rootRequest(server, 'POST', `sys/mounts/${sshMount}`, { type: 'ssh' });
  await addTestSshIssuer(server, sshMount, 'ca-1', true);
  await rootRequest(
    server,
    'POST',
    `${sshMount}/roles/${sshRole}`,
    sshRoleParams(sshRole, options.certMaxTtl ?? '30m'),
  );
  await rootRequest(server, 'POST', `sys/auth/${approleMount}`, {
    type: 'approle',
  });
  await rootRequest(server, 'PUT', `sys/policies/acl/${policy}`, {
    policy: `
path "${kvMount}/data/${kvPrefix}/*" { capabilities = ["create", "read", "update"] }
path "${kvMount}/metadata/${kvPrefix}/*" { capabilities = ["read", "delete"] }
path "${sshMount}/sign/${sshRole}" { capabilities = ["update"] }
path "${sshMount}/issuers" { capabilities = ["list"] }
`,
  });
  await rootRequest(server, 'POST', `auth/${approleMount}/role/app`, {
    token_policies: [policy],
    token_ttl: options.tokenTtl ?? '1h',
    token_max_ttl: options.tokenMaxTtl ?? '24h',
    secret_id_ttl: 0,
  });
  const role = await rootRequest(
    server,
    'GET',
    `auth/${approleMount}/role/app/role-id`,
  );
  const secret = await rootRequest(
    server,
    'POST',
    `auth/${approleMount}/role/app/secret-id`,
  );
  return {
    kvMount,
    approleMount,
    kvPrefix,
    sshMount,
    sshRole,
    roleId: (role!.data as { role_id: string }).role_id,
    secretId: (secret!.data as { secret_id: string }).secret_id,
    cleanup: async () => {
      await rootRequest(server, 'DELETE', `sys/mounts/${kvMount}`);
      await rootRequest(server, 'DELETE', `sys/mounts/${sshMount}`);
      await rootRequest(server, 'DELETE', `sys/auth/${approleMount}`);
      await rootRequest(server, 'DELETE', `sys/policies/acl/${policy}`);
    },
  };
}

/**
 * Parámetros del rol de firma, los mismos que pone deploy/openbao/bootstrap.sh: certificados de
 * usuario con un único principal permitido, key_id elegido por la app, sin extensiones (sin pty
 * ni reenvíos: equivale a `restrict`) y solo claves ed25519.
 */
export function sshRoleParams(
  principal: string,
  maxTtl = '30m',
): Record<string, unknown> {
  return {
    key_type: 'ca',
    allow_user_certificates: true,
    allow_host_certificates: false,
    allowed_users: principal,
    default_user: principal,
    allow_user_key_ids: true,
    ttl: '5m',
    max_ttl: maxTtl,
    allowed_extensions: '',
    default_extensions: {},
    allowed_critical_options: '',
    allowed_user_key_lengths: { 'ssh-ed25519': [0] },
    not_before_duration: '30s',
  };
}

/** Añade un emisor ed25519 generado dentro de OpenBao; devuelve su clave pública. */
export async function addTestSshIssuer(
  server: OpenBaoTestServer,
  mount: string,
  name: string,
  setDefault: boolean,
): Promise<string> {
  const res = await rootRequest(
    server,
    'POST',
    `${mount}/issuers/import/${name}`,
    {
      generate_signing_key: true,
      key_type: 'ssh-ed25519',
      set_default: setDefault,
    },
  );
  return String((res!.data as { public_key: string }).public_key).trim();
}

/** Firma con el token root (para probar certificados que la app no podría pedir). */
export async function rootSignSshKey(
  server: OpenBaoTestServer,
  mount: string,
  role: string,
  body: Record<string, unknown>,
): Promise<string> {
  const res = await rootRequest(server, 'POST', `${mount}/sign/${role}`, body);
  return String((res!.data as { signed_key: string }).signed_key).trim();
}

/** Datos de un token por su accessor (sin el token), o null si ya no existe. */
export async function lookupAccessor(
  server: OpenBaoTestServer,
  accessor: string,
): Promise<Record<string, unknown> | null> {
  try {
    const res = await rootRequest(
      server,
      'POST',
      'auth/token/lookup-accessor',
      {
        accessor,
      },
    );
    return (res?.data as Record<string, unknown>) ?? null;
  } catch {
    return null;
  }
}

/** Política de la caja fuerte, la misma que pone deploy/openbao/bootstrap.sh (`infraward-vault`). */
export function vaultPolicy(kvMount: string, prefix: string): string {
  return `
path "${kvMount}/data/${prefix}/*" { capabilities = ["create", "read", "update"] }
path "${kvMount}/metadata/${prefix}/*" { capabilities = ["create", "read", "update", "delete"] }
`;
}

export interface TestVaultAppRole {
  roleId: string;
  secretId: string;
  kvPrefix: string;
}

/**
 * Segunda AppRole, la de la caja fuerte (QoL-7), en el mismo KV y montaje de AppRole que `app`,
 * con su propia política limitada a `<kv>/…/<prefijo de la caja fuerte>/*`.
 */
export async function createTestVaultAppRole(
  server: OpenBaoTestServer,
  app: TestAppRole,
  kvPrefix = 'infraward-vault',
): Promise<TestVaultAppRole> {
  const policy = `vault-${randomBytes(4).toString('hex')}`;
  await rootRequest(server, 'PUT', `sys/policies/acl/${policy}`, {
    policy: vaultPolicy(app.kvMount, kvPrefix),
  });
  await rootRequest(server, 'POST', `auth/${app.approleMount}/role/vault`, {
    token_policies: [policy],
    token_ttl: '1h',
    token_max_ttl: '24h',
    secret_id_ttl: 0,
  });
  const role = await rootRequest(
    server,
    'GET',
    `auth/${app.approleMount}/role/vault/role-id`,
  );
  const secret = await rootRequest(
    server,
    'POST',
    `auth/${app.approleMount}/role/vault/secret-id`,
  );
  return {
    roleId: (role!.data as { role_id: string }).role_id,
    secretId: (secret!.data as { secret_id: string }).secret_id,
    kvPrefix,
  };
}

/**
 * Parámetros del rol de la terminal (sesión 21), los mismos que pone deploy/openbao/bootstrap.sh:
 * solo el principal de rol `infraward-operators`, key_id elegido por la API, solo la extensión
 * `permit-pty` (sin reenvíos ni agente), solo ed25519 y vida corta.
 */
export function terminalSshRoleParams(principal = 'infraward-operators'): Record<string, unknown> {
  return {
    key_type: 'ca',
    allow_user_certificates: true,
    allow_host_certificates: false,
    allowed_users: principal,
    default_user: principal,
    allow_user_key_ids: true,
    ttl: '2m',
    max_ttl: '5m',
    allowed_extensions: 'permit-pty',
    default_extensions: {},
    allowed_critical_options: '',
    allowed_user_key_lengths: { 'ssh-ed25519': [0] },
    not_before_duration: '30s',
  };
}

/** Política de la terminal, la misma que pone deploy/openbao/bootstrap.sh (`infraward-terminal`). */
export function terminalPolicy(sshMount: string, sshRole: string): string {
  return `
path "${sshMount}/sign/${sshRole}" { capabilities = ["update"] }
`;
}

export interface TestTerminalAppRole {
  roleId: string;
  secretId: string;
  sshRole: string;
}

/**
 * Tercera AppRole, la de la terminal (sesión 21): el rol `infraward-operator` en el mismo
 * montaje SSH que `app` y una política que solo permite firmar con él. La AppRole `app` no puede
 * firmar ese rol (lo comprueba la integración).
 */
export async function createTestTerminalAppRole(
  server: OpenBaoTestServer,
  app: TestAppRole,
  sshRole = 'infraward-operator',
): Promise<TestTerminalAppRole> {
  const policy = `terminal-${randomBytes(4).toString('hex')}`;
  await rootRequest(server, 'POST', `${app.sshMount}/roles/${sshRole}`, terminalSshRoleParams());
  await rootRequest(server, 'PUT', `sys/policies/acl/${policy}`, {
    policy: terminalPolicy(app.sshMount, sshRole),
  });
  await rootRequest(server, 'POST', `auth/${app.approleMount}/role/terminal`, {
    token_policies: [policy],
    token_ttl: '1h',
    token_max_ttl: '24h',
    secret_id_ttl: 0,
  });
  const role = await rootRequest(
    server,
    'GET',
    `auth/${app.approleMount}/role/terminal/role-id`,
  );
  const secret = await rootRequest(
    server,
    'POST',
    `auth/${app.approleMount}/role/terminal/secret-id`,
  );
  return {
    roleId: (role!.data as { role_id: string }).role_id,
    secretId: (secret!.data as { secret_id: string }).secret_id,
    sshRole,
  };
}
