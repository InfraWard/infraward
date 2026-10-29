import { execFileSync } from 'node:child_process';
import { gunzipSync } from 'node:zlib';
import {
  embeddedCommand,
  installCommand,
  keyComment,
  manualCommand,
  unenrollCommand,
} from './commands.js';

const ID = '3f1c2a9e-0000-4000-8000-000000000001';

describe('comandos de enrolamiento', () => {
  it('comando de alta', () => {
    expect(installCommand('https://iw.example/', 'T'.repeat(43))).toBe(
      `curl -fsSL https://iw.example/enroll/${'T'.repeat(43)} | sudo bash`,
    );
  });

  it('con --install-sudo se ejecuta como root sin sudo (puede no estar instalado)', () => {
    expect(installCommand('https://iw.example', 'T'.repeat(43), true)).toBe(
      `curl -fsSL https://iw.example/enroll/${'T'.repeat(43)} | bash -s -- --install-sudo`,
    );
  });

  it('script embebido: base64 de gzip del script, sin comillas que escapar', () => {
    const script =
      '#!/usr/bin/env bash\nmain() { echo \'hola\'; }\nmain "$@" </dev/null\n';
    const command = embeddedCommand(script);
    const match =
      /^echo '([A-Za-z0-9+/=]+)' \| base64 -d \| gunzip \| sudo bash$/.exec(
        command,
      );
    expect(match).not.toBeNull();
    expect(gunzipSync(Buffer.from(match![1], 'base64')).toString()).toBe(
      script,
    );
    expect(embeddedCommand(script, true)).toMatch(
      /\| gunzip \| bash -s -- --install-sudo$/,
    );
    execFileSync('bash', ['-n', '-c', command]);
    // La tubería sin el intérprete final reproduce el script tal cual.
    const decoded = execFileSync('bash', [
      '-c',
      command.replace(/ \| sudo bash$/, ''),
    ]).toString();
    expect(decoded).toBe(script);
  });

  it('alternativa manual', () => {
    const key = `ssh-ed25519 AAAA ${keyComment(ID)}`;
    const command = manualCommand(key);
    expect(command).toContain(`echo '${key}' >> ~/.ssh/authorized_keys`);
    execFileSync('bash', ['-n', '-c', command]);
  });

  it('baja con el usuario dedicado: quita la clave y, si no quedan, sudoers y usuario', () => {
    const command = unenrollCommand(ID, 'inventory');
    execFileSync('bash', ['-n', '-c', command]);
    expect(command).toContain(`/ inventory@infraward:${ID}\\$/d`);
    expect(command).toContain('rm -f /etc/sudoers.d/infraward-inventory');
    // Los ayudantes (el de la v4 y el de Plesk de la v3) se van con el sudoers.
    expect(command).toContain('/usr/local/libexec/infraward/infraward-query');
    expect(command).toContain('/usr/local/libexec/infraward/plesk-query');
    expect(command).toContain('userdel -r inventory');
  });

  it('baja en modo CA: quita la confianza en la CA y el acceso de administración', () => {
    const command = unenrollCommand(ID, 'inventory', 'ca_certificate');
    execFileSync('bash', ['-n', '-c', command]);
    expect(command).toContain('/etc/ssh/sshd_config.d/00-infraward.conf');
    expect(command).toContain('/etc/ssh/sshd_config.d/01-infraward-admin.conf');
    expect(command).toContain('/etc/sudoers.d/infraward-admin');
    // La cuenta solo se borra si la creó InfraWard (marca), antes de quitar la CA.
    expect(command).toMatch(
      /\[ ! -f \/etc\/infraward\/admin-access-created-user \] \|\| \{ userdel -r infraward-admin/,
    );
    expect(command.indexOf('01-infraward-admin.conf')).toBeLessThan(
      command.indexOf('trusted_user_ca_keys'),
    );
  });

  it('baja con un usuario manual: solo quita la línea de su clave', () => {
    const command = unenrollCommand(ID, 'deploy');
    expect(command).toBe(
      `sudo sed -i '/ inventory@infraward:${ID}$/d' ~deploy/.ssh/authorized_keys`,
    );
  });

  it('el comando de baja funciona sobre un authorized_keys real', () => {
    const other = 'ssh-ed25519 BBBB admin@laptop';
    const ours = `restrict ssh-ed25519 AAAA ${keyComment(ID)}`;
    // El sed de la baja, sin sudo ni ~usuario, sobre un fichero temporal.
    const sed = unenrollCommand(ID, 'deploy')
      .replace(/^sudo /, '')
      .replace('~deploy/.ssh/authorized_keys', '"$1"');
    const out = execFileSync('bash', [
      '-c',
      `f=$(mktemp); printf '%s\\n%s\\n' "$2" "$3" > "$f"; set -- "$f"; ${sed.replace('-i', process.platform === 'darwin' ? "-i ''" : '-i')}; cat "$f"; rm -f "$f"`,
      'x',
      'placeholder',
      other,
      ours,
    ]).toString();
    expect(out).toBe(`${other}\n`);
  });
});
