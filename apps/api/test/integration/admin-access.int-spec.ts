import {
  createTerminalSigner,
  generateSshKeyPair,
  loadOpenBaoConfig,
  OpenBaoSecretProvider,
  type TerminalCertSigner,
} from '@infraward/secrets';
import {
  createTestAppRole,
  createTestTerminalAppRole,
  rootSignSshKey,
  startOpenBaoTestServer,
  type OpenBaoTestServer,
  type TestAppRole,
} from '@infraward/secrets/testing/openbao';
import {
  ADMIN_ACCESS_VERSION,
  SSH_CA_CONFIG_VERSION,
  SUDOERS_VERSION,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import { embeddedCommand, keyComment } from '../../src/enrollment/commands.js';
import { EnrollScriptTemplate } from '../../src/enrollment/script-template.js';
import { sshAs, startSshd, type SshdVariant, type TestSshd } from './support/sshd.js';

const ADMIN_FILES = [
  '/etc/ssh/sshd_config.d/01-infraward-admin.conf',
  '/etc/sudoers.d/infraward-admin',
  '/etc/ssh/infraward/principals/infraward-admin',
  '/etc/infraward/admin-access-version',
];

/**
 * Acceso interactivo de administración (sesión 21, DESIGN §7) contra sshd reales (Debian 13 con
 * sudo y Ubuntu 26.04 con sudo-rs) y un OpenBao real: el bloque del script de alta es
 * idempotente, no cambia la configuración de `inventory`, solo admite los certificados del rol de
 * la terminal con el principal `infraward-operators` y se retira con `none`.
 */
describe.each<SshdVariant>(['debian', 'sudo-rs'])('Acceso de administración en %s (integración)', (variant) => {
  let sshd: TestSshd;
  let bao: OpenBaoTestServer;
  let appRole: TestAppRole;
  let app: OpenBaoSecretProvider;
  let terminal: TerminalCertSigner;
  let caKeys: string[];
  const assetId = randomUUID();

  const script = (adminAccess: 'operator' | 'none' | 'keep') =>
    EnrollScriptTemplate.load().render({
      mode: 'embedded',
      apiUrl: '',
      token: '',
      authMode: 'ca_certificate',
      publicKey: '',
      keyComment: keyComment(assetId),
      sudoersVersion: SUDOERS_VERSION,
      caKeys,
      caVersion: SSH_CA_CONFIG_VERSION,
      issuedAt: Math.floor(Date.now() / 1000),
      adminAccess,
      adminAccessVersion: ADMIN_ACCESS_VERSION,
    });
  const run = async (adminAccess: 'operator' | 'none' | 'keep') => {
    const r = await sshd.root(embeddedCommand(script(adminAccess)));
    expect(r.code, r.stderr).toBe(0);
    return r;
  };
  const effective = async (user: string) =>
    (await sshd.root(`sshd -T -C user=${user},host=localhost,addr=127.0.0.1`)).stdout;
  const mtimes = async () =>
    (await sshd.root(`stat -c '%n %Y' ${ADMIN_FILES.join(' ')}`)).stdout;

  async function operatorCert(keyId: string) {
    const pair = generateSshKeyPair('terminal');
    const certificate = await terminal.sign({
      publicKey: pair.publicKey,
      principal: 'infraward-operators',
      keyId,
      ttlSeconds: 120,
    });
    return { pair, certificate };
  }

  beforeAll(async () => {
    [sshd, bao] = await Promise.all([startSshd(variant), startOpenBaoTestServer()]);
    appRole = await createTestAppRole(bao);
    const terminalRole = await createTestTerminalAppRole(bao, appRole);
    const base = {
      addr: bao.addr,
      kvMount: appRole.kvMount,
      approleMount: appRole.approleMount,
      kvPrefix: appRole.kvPrefix,
      sshMount: appRole.sshMount,
    };
    app = new OpenBaoSecretProvider(
      loadOpenBaoConfig({ ...base, roleId: appRole.roleId, secretId: appRole.secretId, sshRole: appRole.sshRole }),
    );
    terminal = createTerminalSigner({
      openbao: { ...base, roleId: terminalRole.roleId, secretId: terminalRole.secretId, sshRole: terminalRole.sshRole },
      appOpenbao: { roleId: appRole.roleId, sshRole: appRole.sshRole },
    })!;
    caKeys = (await app.sshCaPublicKeys()).map((k) => k.publicKey);
  });

  afterAll(async () => {
    await app?.close();
    await terminal?.close();
    await appRole?.cleanup();
    await Promise.all([sshd?.stop(), bao?.stop()]);
  });

  it('instala la cuenta con sudo, solo con certificados; inventory no cambia; idempotente', async () => {
    await run('keep');
    const inventoryBefore = await effective('inventory');
    const first = await run('operator');
    expect(first.stderr).toContain('Acceso interactivo de administración');
    expect((await sshd.root('id -un infraward-admin && getent shadow infraward-admin')).stdout).toMatch(
      /^infraward-admin\ninfraward-admin:\*:/,
    );
    expect(await effective('inventory')).toBe(inventoryBefore);
    const admin = await effective('infraward-admin');
    for (const line of [
      'trustedusercakeys /etc/ssh/infraward/trusted_user_ca_keys',
      'authorizedprincipalsfile /etc/ssh/infraward/principals/%u',
      'authorizedkeysfile none',
      'passwordauthentication no',
      'permittty yes',
      'disableforwarding yes',
    ])
      expect(admin.split('\n'), line).toContain(line);
    expect((await sshd.root('cat /etc/ssh/infraward/principals/infraward-admin /etc/infraward/admin-access-version')).stdout).toBe(
      `infraward-operators\n${ADMIN_ACCESS_VERSION}\n`,
    );
    // Otra vez: sin cambios (ni la fecha de los ficheros).
    const before = await mtimes();
    await new Promise((r) => setTimeout(r, 1100));
    const second = await run('operator');
    expect(second.stderr).toContain('ya al día (sin cambios)');
    expect(await mtimes()).toBe(before);
  });

  it('entra con el certificado de la terminal, con PTY y sudo; el key_id va al log de sshd', async () => {
    const keyId = `infraward:session=${randomUUID()}:user=ana@example.com:asset=${assetId}`;
    const { pair, certificate } = await operatorCert(keyId);
    const r = await sshAs(sshd, 'infraward-admin', pair.privateKey, 'id -un; sudo -n true && echo SUDO_OK', {
      certificate,
    });
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toBe('infraward-admin\nSUDO_OK\n');
    expect(await sshd.waitForLog(`ID ${keyId} `)).toBe(true);
    const line = sshd.logs().split('\n').find((l) => l.includes(`ID ${keyId} `))!;
    expect(line).toMatch(/Accepted publickey for infraward-admin .* ED25519-CERT/);
  });

  it('rechaza: una clave sin certificado, el certificado del inventario y el certificado en inventory', async () => {
    const pair = generateSshKeyPair('suelta');
    await sshd.root(
      `install -d -m 700 -o infraward-admin /home/infraward-admin/.ssh && echo '${pair.publicKey}' > /home/infraward-admin/.ssh/authorized_keys`,
    );
    expect((await sshAs(sshd, 'infraward-admin', pair.privateKey, 'true')).code).toBe(255);

    const inventoryCert = await app.signSshKey({
      publicKey: pair.publicKey,
      principal: 'inventory',
      keyId: 'infraward:asset=x:job=y',
      ttlSeconds: 120,
    });
    expect(
      (await sshAs(sshd, 'infraward-admin', pair.privateKey, 'true', { certificate: inventoryCert })).code,
    ).toBe(255);

    // El certificado de la terminal no sirve para entrar como inventory (otro principal).
    const { pair: p2, certificate } = await operatorCert('infraward:session=s:user=u:asset=a');
    expect((await sshAs(sshd, 'inventory', p2.privateKey, 'true', { certificate })).code).toBe(255);

    // Un certificado con otro principal (firmado con el token root, que la app no tiene).
    const other = await rootSignSshKey(bao, appRole.sshMount, appRole.sshRole, {
      public_key: p2.publicKey,
      valid_principals: 'inventory',
      key_id: 'otro',
      cert_type: 'user',
    });
    expect(
      (await sshAs(sshd, 'infraward-admin', p2.privateKey, 'true', { certificate: other })).code,
    ).toBe(255);
  });

  it('la AppRole de la app (la del worker) no puede firmar con el rol de la terminal', async () => {
    const workerAsTerminal = new OpenBaoSecretProvider(
      loadOpenBaoConfig({
        addr: bao.addr,
        roleId: appRole.roleId,
        secretId: appRole.secretId,
        kvMount: appRole.kvMount,
        approleMount: appRole.approleMount,
        kvPrefix: appRole.kvPrefix,
        sshMount: appRole.sshMount,
        sshRole: 'infraward-operator',
      }),
    );
    await expect(
      workerAsTerminal.signSshKey({
        publicKey: generateSshKeyPair('w').publicKey,
        principal: 'infraward-operators',
        keyId: 'infraward:robado',
        ttlSeconds: 120,
        extensions: ['permit-pty'],
      }),
    ).rejects.toThrow(/HTTP 403|denegad|permission/i);
    await workerAsTerminal.close();
  });

  it('con `none` lo retira todo (y la cuenta, que creó InfraWard)', async () => {
    const r = await run('none');
    expect(r.stderr).toContain('Acceso interactivo de administración retirado');
    expect((await sshd.root(`ls ${ADMIN_FILES.join(' ')} 2>&1; id infraward-admin 2>&1`)).stdout).not.toMatch(
      /^\/etc\//m,
    );
    expect((await sshd.root('id infraward-admin')).code).not.toBe(0);
    const { pair, certificate } = await operatorCert('infraward:session=s:user=u:asset=a');
    expect((await sshAs(sshd, 'infraward-admin', pair.privateKey, 'true', { certificate })).code).toBe(255);
    // inventory sigue funcionando con su certificado.
    const inv = generateSshKeyPair('inv');
    const invCert = await app.signSshKey({
      publicKey: inv.publicKey,
      principal: 'inventory',
      keyId: 'infraward:asset=x:job=z',
      ttlSeconds: 120,
    });
    expect(
      (await sshAs(sshd, 'inventory', inv.privateKey, 'id -un', { certificate: invCert })).stdout,
    ).toBe('inventory\n');
  });

  it('sin /run/sshd (Debian con activación por socket, tras un reinicio): lo crea y sigue', async () => {
    // Sin el directorio, `sshd -t` falla («Missing privilege separation directory»); el script lo
    // crea como haría ssh.service (root, 0755) en lugar de pararse.
    await sshd.root('rm -rf /run/sshd');
    expect((await sshd.root('sshd -t')).code).not.toBe(0);
    const r = await run('operator');
    expect(r.stderr).not.toContain('no es válida');
    expect((await sshd.root("stat -c '%U %a' /run/sshd")).stdout).toBe('root 755\n');
    const { pair, certificate } = await operatorCert('infraward:session=r:user=u:asset=a');
    expect(
      (await sshAs(sshd, 'infraward-admin', pair.privateKey, 'id -un', { certificate })).stdout,
    ).toBe('infraward-admin\n');
  });
});
