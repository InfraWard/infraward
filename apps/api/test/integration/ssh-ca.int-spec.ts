import {
  generateSshKeyPair,
  loadOpenBaoConfig,
  OpenBaoSecretProvider,
  sshPublicKeyFingerprint,
} from '@infraward/secrets';
import {
  addTestSshIssuer,
  createTestAppRole,
  rootRequest,
  rootSignSshKey,
  sshRoleParams,
  startOpenBaoTestServer,
  type OpenBaoTestServer,
  type TestAppRole,
} from '@infraward/secrets/testing/openbao';
import {
  SSH_CA_CONFIG_VERSION,
  SUDOERS_VERSION,
} from '@infraward/shared-types';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  embeddedCommand,
  keyComment,
  unenrollCommand,
} from '../../src/enrollment/commands.js';
import { EnrollScriptTemplate } from '../../src/enrollment/script-template.js';
import { sshAs, startSshd, type TestSshd } from './support/sshd.js';

/**
 * Modo CA contra servidores reales (DESIGN §6, §7): el script de alta configura sshd para
 * confiar en la CA SSH de OpenBao, el worker entra con certificados de vida corta firmados en el
 * momento, y se rechaza lo que no debe entrar (caducado, otro principal, clave suelta).
 */
describe('CA SSH de OpenBao contra un sshd real (integración)', () => {
  let sshd: TestSshd;
  let bao: OpenBaoTestServer;
  let role: TestAppRole;
  let provider: OpenBaoSecretProvider;
  const template = EnrollScriptTemplate.load();
  const AUTH = '/home/inventory/.ssh/authorized_keys';

  const newAsset = () => {
    const id = randomUUID();
    return { id, ...generateSshKeyPair(keyComment(id)) };
  };
  const ca = newAsset();
  const migrating = newAsset();
  const staticOnly = newAsset();

  async function caKeys(): Promise<string[]> {
    return (await provider.sshCaPublicKeys()).map((k) => k.publicKey);
  }

  async function enroll(
    asset: { id: string; publicKey: string },
    mode: 'static_key' | 'ca_certificate',
    keys: string[] = [],
  ) {
    const script = template.render({
      mode: 'embedded',
      apiUrl: '',
      token: '',
      authMode: mode,
      publicKey: mode === 'static_key' ? asset.publicKey : '',
      keyComment: keyComment(asset.id),
      sudoersVersion: SUDOERS_VERSION,
      caKeys: mode === 'ca_certificate' ? keys : [],
      caVersion: SSH_CA_CONFIG_VERSION,
      issuedAt: Math.floor(Date.now() / 1000),
    });
    return sshd.root(embeddedCommand(script));
  }

  /** Par efímero y su certificado de la CA (lo que hace el worker en cada job). */
  async function certified(keyId: string, ttlSeconds = 120) {
    const pair = generateSshKeyPair('infraward-efimera');
    const certificate = await provider.signSshKey({
      publicKey: pair.publicKey,
      principal: 'inventory',
      keyId,
      ttlSeconds,
    });
    return { ...pair, certificate };
  }

  const whoami = async (
    key: { privateKey: string },
    certificate?: string,
    user = 'inventory',
  ) =>
    (
      await sshAs(sshd, user, key.privateKey, 'id -un', { certificate })
    ).stdout.trim();

  beforeAll(async () => {
    [sshd, bao] = await Promise.all([startSshd(), startOpenBaoTestServer()]);
    role = await createTestAppRole(bao);
    provider = new OpenBaoSecretProvider(
      loadOpenBaoConfig({
        addr: bao.addr,
        roleId: role.roleId,
        secretId: role.secretId,
        kvMount: role.kvMount,
        approleMount: role.approleMount,
        kvPrefix: role.kvPrefix,
        sshMount: role.sshMount,
        sshRole: role.sshRole,
      }),
    );
  });

  afterAll(async () => {
    await provider?.close();
    await role?.cleanup();
    await Promise.all([sshd?.stop(), bao?.stop()]);
  });

  it('con el reloj del servidor atrasado, el script en modo CA se para sin tocar nada', async () => {
    const script = template.render({
      mode: 'embedded',
      apiUrl: '',
      token: '',
      authMode: 'ca_certificate',
      publicKey: '',
      keyComment: keyComment(ca.id),
      sudoersVersion: SUDOERS_VERSION,
      caKeys: await caKeys(),
      caVersion: SSH_CA_CONFIG_VERSION,
      // Generado «dentro de un día»: para el servidor, su reloj va un día atrasado.
      issuedAt: Math.floor(Date.now() / 1000) + 86_400,
    });
    const r = await sshd.root(embeddedCommand(script));
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain('el reloj del servidor va atrasado');
    expect((await sshd.root('id inventory')).code).not.toBe(0);
    expect(
      (await sshd.root('test -e /etc/ssh/sshd_config.d/00-infraward.conf'))
        .code,
    ).not.toBe(0);
  });

  it('el script en modo CA valida sshd, no instala ninguna clave estática y entra con un certificado', async () => {
    const r = await enroll(ca, 'ca_certificate', await caKeys());
    expect(r.code, r.stderr).toBe(0);
    expect((await sshd.root('sshd -t')).code).toBe(0);
    // Ninguna clave estática para este asset (ni authorized_keys siquiera).
    expect((await sshd.root(`test -e ${AUTH}`)).code).not.toBe(0);
    const effective = (
      await sshd.root('sshd -T -C user=inventory,host=localhost,addr=127.0.0.1')
    ).stdout;
    expect(effective).toContain(
      'trustedusercakeys /etc/ssh/infraward/trusted_user_ca_keys',
    );
    expect(effective).toContain(
      'authorizedprincipalsfile /etc/ssh/infraward/principals/%u',
    );
    // Otro usuario no hereda nada.
    expect(
      (await sshd.root('sshd -T -C user=root,host=localhost,addr=127.0.0.1'))
        .stdout,
    ).toContain('trustedusercakeys none');

    const keyId = `infraward:asset=${ca.id}:job=int-1`;
    const job = await certified(keyId);
    expect(await whoami(job, job.certificate)).toBe('inventory');
    // El key_id del job queda en el log de sshd (auth.log en un servidor).
    expect(await sshd.waitForLog(`ID ${keyId}`)).toBe(true);
  });

  it('se rechaza la clave efímera sin certificado, un certificado caducado y uno con otro principal', async () => {
    const job = await certified(`infraward:asset=${ca.id}:job=int-2`);
    // La clave sola no vale: no está en authorized_keys.
    expect(await whoami(job)).toBe('');

    // Caducado: firmado con 5 s de vida (con el token root; la app no baja de 30 s).
    const shortPair = generateSshKeyPair('efimera');
    const expired = await rootSignSshKey(bao, role.sshMount, role.sshRole, {
      public_key: shortPair.publicKey,
      valid_principals: 'inventory',
      key_id: 'caducado',
      ttl: '5s',
    });
    expect(await whoami(shortPair, expired)).toBe('inventory');
    await sleep(7_000);
    expect(await whoami(shortPair, expired)).toBe('');

    // Misma CA, otro principal (un rol de prueba que permite `root`).
    await rootRequest(
      bao,
      'POST',
      `${role.sshMount}/roles/otro`,
      sshRoleParams('root'),
    );
    const other = generateSshKeyPair('efimera');
    const rootCert = await rootSignSshKey(bao, role.sshMount, 'otro', {
      public_key: other.publicKey,
      valid_principals: 'root',
      key_id: 'otro-principal',
      ttl: '60s',
    });
    expect(await whoami(other, rootCert)).toBe('');
    expect(await whoami(other, rootCert, 'root')).toBe('');
    // Las líneas «Accepted» de las conexiones anteriores ya están (la del expirado espera).
    await sshd.waitForLog('ID caducado');
    // En el log de sshd: el caducado solo entró mientras era válido; el de otro principal, nunca.
    const accepted = (id: string) =>
      sshd
        .logs()
        .split('\n')
        .filter((l) => l.includes('Accepted') && l.includes(`ID ${id} `))
        .length;
    expect(accepted('caducado')).toBe(1);
    expect(accepted('otro-principal')).toBe(0);
  });

  it('un asset estático pasa a CA volviendo a ejecutar el script: su línea desaparece y la de otro sigue', async () => {
    expect((await enroll(staticOnly, 'static_key')).code).toBe(0);
    expect((await enroll(migrating, 'static_key')).code).toBe(0);
    expect(await whoami(migrating)).toBe('inventory');

    const r = await enroll(migrating, 'ca_certificate', await caKeys());
    expect(r.code, r.stderr).toBe(0);
    const lines = (await sshd.root(`cat ${AUTH}`)).stdout.trim().split('\n');
    expect(lines.some((l) => l.endsWith(keyComment(migrating.id)))).toBe(false);
    expect(lines.some((l) => l.endsWith(keyComment(staticOnly.id)))).toBe(true);
    // La clave estática migrada ya no entra; el certificado sí; el estático sigue a la vez.
    expect(await whoami(migrating)).toBe('');
    const job = await certified(`infraward:asset=${migrating.id}:job=int-3`);
    expect(await whoami(job, job.certificate)).toBe('inventory');
    expect(await whoami(staticOnly)).toBe('inventory');
  });

  it('el fichero de CAs admite la actual y la siguiente; se lee sin sudo y al quitar una deja de valer', async () => {
    const next = await addTestSshIssuer(bao, role.sshMount, 'ca-2', false);
    await rootRequest(bao, 'POST', `${role.sshMount}/roles/siguiente`, {
      ...sshRoleParams('inventory'),
      issuer_ref: 'ca-2',
    });
    const pair = generateSshKeyPair('efimera');
    const nextCert = await rootSignSshKey(bao, role.sshMount, 'siguiente', {
      public_key: pair.publicKey,
      valid_principals: 'inventory',
      key_id: 'ca-siguiente',
      ttl: '120s',
    });
    // Aún no se confía en ca-2.
    expect(await whoami(pair, nextCert)).toBe('');

    const both = await caKeys();
    expect(both).toHaveLength(2);
    expect((await enroll(ca, 'ca_certificate', both)).code).toBe(0);
    expect(await whoami(pair, nextCert)).toBe('inventory');

    // El worker lo lee como inventory, sin sudo, y saca las huellas.
    const job = await certified(`infraward:asset=${ca.id}:job=int-4`);
    const text = (
      await sshAs(
        sshd,
        'inventory',
        job.privateKey,
        'cat /etc/ssh/infraward/trusted_user_ca_keys',
        { certificate: job.certificate },
      )
    ).stdout;
    expect(text).toContain(
      `# infraward-ssh-ca-version: ${SSH_CA_CONFIG_VERSION}`,
    );
    const fingerprints = text
      .split('\n')
      .filter((l) => l.startsWith('ssh-'))
      .map((l) => sshPublicKeyFingerprint(l));
    expect(fingerprints.sort()).toEqual(
      (await provider.sshCaPublicKeys()).map((k) => k.fingerprint).sort(),
    );

    // Retirada: solo la siguiente. El certificado de la antigua deja de valer.
    expect((await enroll(ca, 'ca_certificate', [next])).code).toBe(0);
    const old = await certified(`infraward:asset=${ca.id}:job=int-5`);
    expect(await whoami(old, old.certificate)).toBe('');
    expect(await whoami(pair, nextCert)).toBe('inventory');
    // Se deja como estaba para los siguientes tests.
    expect((await enroll(ca, 'ca_certificate', await caKeys())).code).toBe(0);
  });

  it('si sshd -t falla, el script deja la configuración como estaba y no recarga', async () => {
    const before = (
      await sshd.root('cat /etc/ssh/sshd_config.d/00-infraward.conf')
    ).stdout;
    await sshd.root(
      `printf 'NoExisteEstaOpcion yes\\n' > /etc/ssh/sshd_config.d/99-roto.conf`,
    );
    try {
      const keys = await caKeys();
      const r = await enroll(ca, 'ca_certificate', keys.slice(0, 1));
      expect(r.code).not.toBe(0);
      expect(r.stderr).toContain(
        'la configuración de sshd no es válida; se ha dejado como estaba',
      );
      expect(
        (await sshd.root('cat /etc/ssh/sshd_config.d/00-infraward.conf'))
          .stdout,
      ).toBe(before);
    } finally {
      await sshd.root('rm -f /etc/ssh/sshd_config.d/99-roto.conf');
    }
    const job = await certified(`infraward:asset=${ca.id}:job=int-6`);
    expect(await whoami(job, job.certificate)).toBe('inventory');
  });

  it('la baja en modo CA quita la confianza en la CA; el asset estático sigue entrando', async () => {
    const r = await sshd.root(
      unenrollCommand(ca.id, 'inventory', 'ca_certificate'),
    );
    expect(r.code, r.stderr).toBe(0);
    expect(
      (await sshd.root('test -e /etc/ssh/sshd_config.d/00-infraward.conf'))
        .code,
    ).not.toBe(0);
    const job = await certified(`infraward:asset=${ca.id}:job=int-7`);
    expect(await whoami(job, job.certificate)).toBe('');
    expect(await whoami(staticOnly)).toBe('inventory');
    // El usuario y el sudoers siguen: les queda la clave del asset estático.
    expect((await sshd.root('id inventory')).code).toBe(0);
  });

  it('ssh-keygen confirma que el certificado del worker es de usuario, con un solo principal y sin extensiones', async () => {
    const job = await certified('infraward:asset=x:job=y', 60);
    const info = execFileSync('ssh-keygen', ['-Lf', '-'], {
      input: job.certificate,
    }).toString();
    expect(info).toContain('user certificate');
    expect(info).toMatch(/Principals: \n\s+inventory\n/);
    expect(info).toMatch(/Extensions: \(none\)/);
  });
});
