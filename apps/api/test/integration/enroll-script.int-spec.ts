import {
  SSH_CA_CONFIG_VERSION,
  SUDOERS_VERSION,
} from '@infraward/shared-types';
import { randomUUID } from 'node:crypto';
import {
  embeddedCommand,
  keyComment,
  unenrollCommand,
} from '../../src/enrollment/commands.js';
import { EnrollScriptTemplate } from '../../src/enrollment/script-template.js';
import { generateSshKeyPair } from '@infraward/secrets';
import { sshAs, startSshd, type TestSshd } from './support/sshd.js';

/**
 * El script de alta real contra un sshd real: cada asset solo toca SU línea de authorized_keys
 * (comentario `inventory@infraward:<asset-id>`), y la baja solo quita esa línea.
 */
describe('Script de alta contra un servidor SSH real (integración)', () => {
  let sshd: TestSshd;
  const template = EnrollScriptTemplate.load();
  const AUTH = '/home/inventory/.ssh/authorized_keys';
  const OWN_LINE =
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPropiaDelAdministrador0000000000000000 admin@portatil';

  const newAsset = () => {
    const id = randomUUID();
    return { id, ...generateSshKeyPair(keyComment(id)) };
  };
  const a = newAsset();
  const b = newAsset();

  /**
   * El comando embebido tal cual lo da la API (`echo … | base64 -d | gunzip | sudo bash`), con
   * argumentos del script si se dan (`sudo bash -s -- <args>`, como `--podman-users`).
   */
  async function enroll(asset: { publicKey: string; id: string }, args = '') {
    const script = template.render({
      mode: 'embedded',
      apiUrl: '',
      token: '',
      authMode: 'static_key',
      publicKey: asset.publicKey,
      keyComment: keyComment(asset.id),
      sudoersVersion: SUDOERS_VERSION,
      caKeys: [],
      caVersion: SSH_CA_CONFIG_VERSION,
      issuedAt: Math.floor(Date.now() / 1000),
    });
    const command = embeddedCommand(script);
    const r = await sshd.root(
      args ? command.replace(/sudo bash$/, `sudo bash -s -- ${args}`) : command,
    );
    if (!args.includes('root')) expect(r.code, r.stderr).toBe(0);
    return r;
  }
  const connects = async (asset: { privateKey: string }) =>
    (
      await sshAs(sshd, 'inventory', asset.privateKey, 'id -un')
    ).stdout.trim() === 'inventory';
  const authorizedKeys = async () =>
    (await sshd.root(`cat ${AUTH}`)).stdout.trim().split('\n');

  beforeAll(async () => {
    sshd = await startSshd();
  });
  afterAll(async () => {
    await sshd?.stop();
  });

  it('dos assets dados de alta en el mismo servidor conectan los dos', async () => {
    await enroll(a);
    await enroll(b);
    expect(await connects(a)).toBe(true);
    expect(await connects(b)).toBe(true);
    const lines = await authorizedKeys();
    expect(lines).toHaveLength(2);
    expect(lines.every((l) => l.startsWith('restrict ssh-ed25519 '))).toBe(
      true,
    );
  });

  it('volver a ejecutar el script no duplica ni toca las líneas ajenas', async () => {
    // Una clave del administrador en la cuenta y otra en la de root: no son de InfraWard.
    await sshd.root(`printf '%s\\n' '${OWN_LINE}' >> ${AUTH}`);
    await sshd.root(
      `install -d -m 700 /root/.ssh && printf '%s\\n' 'ssh-ed25519 AAAAroot root@otro' > /root/.ssh/authorized_keys`,
    );
    await enroll(a);
    await enroll(a);
    const lines = await authorizedKeys();
    expect(lines.filter((l) => l.endsWith(keyComment(a.id)))).toHaveLength(1);
    expect(lines.filter((l) => l.endsWith(keyComment(b.id)))).toHaveLength(1);
    expect(lines).toContain(OWN_LINE);
    expect(lines).toHaveLength(3);
    expect(
      (await sshd.root('cat /root/.ssh/authorized_keys')).stdout.trim(),
    ).toBe('ssh-ed25519 AAAAroot root@otro');
    expect(await connects(a)).toBe(true);
    expect(await connects(b)).toBe(true);
  });

  it('la baja de A solo quita su línea: B sigue conectando y el usuario sigue', async () => {
    const r = await sshd.root(unenrollCommand(a.id, 'inventory'));
    expect(r.code, r.stderr).toBe(0);
    expect(await connects(a)).toBe(false);
    expect(await connects(b)).toBe(true);
    const lines = await authorizedKeys();
    expect(lines.some((l) => l.endsWith(keyComment(a.id)))).toBe(false);
    expect(lines).toContain(OWN_LINE);
    expect(
      (await sshd.root('test -f /etc/sudoers.d/infraward-inventory')).code,
    ).toBe(0);
  });

  it('la baja de B quita el sudoers; el usuario se queda porque tiene una clave del administrador', async () => {
    const r = await sshd.root(unenrollCommand(b.id, 'inventory'));
    expect(r.code, r.stderr).toBe(0);
    expect(await connects(b)).toBe(false);
    expect(
      (await sshd.root('test -e /etc/sudoers.d/infraward-inventory')).code,
    ).not.toBe(0);
    expect((await sshd.root('id inventory')).code).toBe(0);
    expect(await authorizedKeys()).toEqual([OWN_LINE]);
  });

  it('--podman-users escribe la lista de Podman rootless; sin la opción no se toca; un usuario no válido para antes de tocar nada', async () => {
    const PODMAN_USERS = '/etc/infraward/podman-users';
    const users = async () =>
      (await sshd.root(`cat ${PODMAN_USERS}`)).stdout
        .split('\n')
        .filter((l) => l && !l.startsWith('#'));
    // Un asset propio, que se da de baja al final (el último test cuenta las claves que quedan).
    const e = newAsset();
    const r = await enroll(e, '--podman-users=nobody');
    expect(r.stdout + r.stderr).toMatch(/'nobody' no tiene activo el socket de Podman/);
    expect(await users()).toEqual(['nobody']);
    expect((await sshd.root(`stat -c '%U:%G %a' ${PODMAN_USERS}`)).stdout.trim()).toBe('root:root 644');
    await enroll(e);
    expect(await users()).toEqual(['nobody']);
    const d = newAsset();
    const bad = await enroll(d, '--podman-users=nobody,root');
    expect(bad.code).not.toBe(0);
    expect(bad.stdout + bad.stderr).toMatch(/'root' es root/);
    expect(await users()).toEqual(['nobody']);
    expect((await authorizedKeys()).some((l) => l.includes(d.id))).toBe(false);
    await enroll(e, '--podman-users=');
    expect(await users()).toEqual([]);
    // La última baja borra la lista con el sudoers.
    const off = await sshd.root(unenrollCommand(e.id, 'inventory'));
    expect(off.code, off.stderr).toBe(0);
    expect((await sshd.root(`test -e ${PODMAN_USERS}`)).code).not.toBe(0);
  });

  it('sin claves ajenas, la última baja borra también el usuario', async () => {
    const c = newAsset();
    await sshd.root(`sed -i '/admin@portatil$/d' ${AUTH}`);
    await enroll(c);
    expect(await connects(c)).toBe(true);
    const r = await sshd.root(unenrollCommand(c.id, 'inventory'));
    expect(r.code, r.stderr).toBe(0);
    expect((await sshd.root('id inventory')).code).not.toBe(0);
    expect(
      (await sshd.root('test -e /etc/sudoers.d/infraward-inventory')).code,
    ).not.toBe(0);
  });
});
