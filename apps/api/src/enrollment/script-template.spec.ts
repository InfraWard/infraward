import { execFileSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import {
  INFRAWARD_QUERY_HELPER,
  LEGACY_PLESK_QUERY_HELPER,
} from '@infraward/connectors';
import {
  ADMIN_ACCESS_VERSION,
  SSH_CA_CONFIG_VERSION,
  SUDOERS_VERSION,
} from '@infraward/shared-types';
import {
  EnrollScriptTemplate,
  type EnrollScriptValues,
} from './script-template.js';

const ID = '3f1c2a9e-0000-4000-8000-000000000001';
const VALUES: EnrollScriptValues = {
  mode: 'online',
  apiUrl: 'https://infraward.example.com',
  token: 'A'.repeat(43),
  authMode: 'static_key',
  publicKey: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGt+ inventory@infraward:${ID}`,
  keyComment: `inventory@infraward:${ID}`,
  sudoersVersion: SUDOERS_VERSION,
  caKeys: [],
  caVersion: SSH_CA_CONFIG_VERSION,
  issuedAt: Math.floor(Date.now() / 1000),
};
const CA_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAcAcA';
const CA: EnrollScriptValues = {
  ...VALUES,
  authMode: 'ca_certificate',
  publicKey: '',
  caKeys: [CA_KEY, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINeXt'],
};

describe('EnrollScriptTemplate', () => {
  const template = EnrollScriptTemplate.load();

  it('rellena la plantilla del repositorio y el resultado es bash válido', () => {
    const script = template.render(VALUES);
    expect(script).not.toContain('__INFRAWARD_');
    expect(script).toContain(`local api_url='https://infraward.example.com'`);
    expect(script).toContain(`local token='${'A'.repeat(43)}'`);
    expect(script).toContain(`local public_key='${VALUES.publicKey}'`);
    expect(script).toContain(`local version='${SUDOERS_VERSION}'`);
    expect(script).toContain(`local mode='online'`);
    execFileSync('bash', ['-n'], { input: script });
  });

  it('modo embebido: sin URL ni token, imprime las huellas en vez de avisar a la API', () => {
    const script = template.render({
      ...VALUES,
      mode: 'embedded',
      apiUrl: '',
      token: '',
    });
    expect(script).toContain(`local mode='embedded'`);
    expect(script).toContain(`local api_url=''`);
    expect(script).toContain(`local token=''`);
    expect(script).toContain('----- infraward host keys -----');
    execFileSync('bash', ['-n'], { input: script });
  });

  it('el script embebido nunca lleva URL ni token', () => {
    expect(() =>
      template.render({ ...VALUES, mode: 'embedded', apiUrl: '' }),
    ).toThrow(/ni URL ni token/);
    expect(() =>
      template.render({ ...VALUES, mode: 'embedded', token: '' }),
    ).toThrow(/ni URL ni token/);
  });

  it('online exige URL y token', () => {
    expect(() => template.render({ ...VALUES, token: '' })).toThrow(
      'Valor no válido para el script de alta: token',
    );
  });

  it('solo admite --install-sudo (antes de comprobar nada)', () => {
    const script = template.render(VALUES);
    const run = (...args: string[]) => {
      try {
        execFileSync('bash', ['-s', '--', ...args], {
          input: script,
          stdio: 'pipe',
        });
        return '';
      } catch (error) {
        return String((error as { stderr: Buffer }).stderr);
      }
    };
    expect(run('--bogus')).toContain("opción desconocida: '--bogus'");
    // Sin ser root no llega a instalar nada.
    if (process.getuid?.() !== 0) {
      expect(run('--install-sudo')).toContain('hay que ejecutarlo como root');
    }
  });

  it('sin sudo, sugiere --install-sudo; con la opción, lo instala solo si se pidió', () => {
    const script = template.render(VALUES);
    expect(script).toContain('vuelve a ejecutar el comando con --install-sudo');
    expect(script).toMatch(/\[ "\$install_sudo" -eq 1 \] \|\|/);
    expect(script).toContain('AVISO: falta python3');
  });

  it('el sudoers de inventory nunca concede ALL como comando y lleva versión y aviso', () => {
    const script = template.render(VALUES);
    expect(script).toContain('# infraward-sudoers-version: $version');
    expect(script).toMatch(/'pct-exec' ejecuta como root dentro de los CT/);
    expect(script).toMatch(/demonio de Docker equivale a root/);
    const inventorySudoers = functionBody(script, 'write_sudoers');
    expect(inventorySudoers).toContain("'%s ALL=(root) NOPASSWD: %s\\n' \"$user\" \"$QUERY_HELPER\"");
    expect(inventorySudoers).not.toMatch(/NOPASSWD:\s*ALL/);
    // La única regla con ALL es la de la cuenta de administración (opcional, §7).
    expect(script.match(/NOPASSWD:\s*ALL/g)).toEqual(['NOPASSWD: ALL']);
    expect(functionBody(script, 'configure_admin_access')).toContain(
      "'%s ALL=(ALL:ALL) NOPASSWD: ALL\\n' \"$ADMIN_USER\"",
    );
    expect(script).not.toContain('Cmnd_Alias');
    expect(script).toContain('visudo -cqf');
  });

  it('acceso de administración: por defecto no se toca; operator solo en modo CA', () => {
    expect(template.render(CA)).toContain(`local admin_access='keep'`);
    const script = template.render({ ...CA, adminAccess: 'operator' });
    expect(script).toContain(`local admin_access='operator'`);
    expect(script).toContain(`local admin_version='${ADMIN_ACCESS_VERSION}'`);
    execFileSync('bash', ['-n'], { input: script });
    expect(template.render({ ...CA, adminAccess: 'none' })).toContain(
      `local admin_access='none'`,
    );
    expect(() => template.render({ ...VALUES, adminAccess: 'operator' })).toThrow(
      'requiere el modo CA',
    );
    expect(() =>
      template.render({ ...CA, adminAccess: "operator'; rm -rf /" as never }),
    ).toThrow('adminAccess');
    // Drop-in propio, sin claves ni contraseñas, y nunca con el usuario inventory.
    const body = functionBody(script, 'configure_admin_access');
    expect(script).toContain('ADMIN_USER=infraward-admin');
    expect(script).toContain('ADMIN_PRINCIPAL=infraward-operators');
    expect(script).toContain('ADMIN_DROPIN=/etc/ssh/sshd_config.d/01-infraward-admin.conf');
    for (const line of [
      'AuthorizedKeysFile none',
      'PasswordAuthentication no',
      'KbdInteractiveAuthentication no',
      'PermitTTY yes',
      'DisableForwarding yes',
    ])
      expect(body).toContain(`printf '    ${line}\\n'`);
    expect(body).toContain('sshd_test');
    expect(body).toContain('restore_admin_access');
    expect(body).toContain('[ "$inventory_before" != "$inventory_after" ]');
  });

  it('todo se ejecuta dentro de main(), invocada en la última línea', () => {
    const lines = template.render(VALUES).trimEnd().split('\n');
    expect(lines.at(-1)).toBe('main "$@" </dev/null');
  });

  it.each<[keyof EnrollScriptValues, string]>([
    ['mode', 'offline'],
    ['mode', "online'; id"],
    ['apiUrl', "https://x.example/'; rm -rf / #"],
    ['apiUrl', 'https://x.example/?q=1'],
    ['apiUrl', 'file:///etc/passwd'],
    ['token', `${'A'.repeat(42)}'`],
    ['token', 'corto'],
    ['publicKey', `ssh-rsa AAAA inventory@infraward:${ID}`],
    ['publicKey', `ssh-ed25519 AAAA' x inventory@infraward:${ID}`],
    ['keyComment', `root@infraward:${ID}`],
    ['sudoersVersion', '1; id'],
    ['authMode', 'root'],
    ['caVersion', '0'],
    ['issuedAt', '1; id'],
  ])('rechaza %s = %s', (key, value) => {
    expect(() => template.render({ ...VALUES, [key]: value })).toThrow(
      `Valor no válido para el script de alta: ${key}`,
    );
  });

  it('modo CA: sin clave estática, con las claves de la CA y la versión', () => {
    const script = template.render(CA);
    expect(script).toContain(`local auth='ca_certificate'`);
    expect(script).toContain(`local public_key=''`);
    expect(script).toContain(
      `local ca_keys='${CA_KEY}\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINeXt'`,
    );
    expect(script).toContain(`local ca_version='${SSH_CA_CONFIG_VERSION}'`);
    // La configuración de sshd va en un Match User y se valida antes de recargar.
    expect(script).toContain('printf \'Match User %s\\n\' "$user"');
    expect(script).toContain('TrustedUserCAKeys');
    expect(script).toContain('AuthorizedPrincipalsFile');
    expect(script).toMatch(/if ! err=\$\(sshd_test\)/);
    // sshd_test crea el directorio de separación de privilegios si falta (y quita el \r de sshd).
    expect(script).toContain("tr -d '\\r' | sed -n 's|^Missing privilege separation directory:");
    expect(script).toContain('install -d -m 0755 -o root -g root "$dir"');
    expect(script).toContain('restore_ssh_ca');
    execFileSync('bash', ['-n'], { input: script });
  });

  it('modo CA: con el reloj del servidor atrasado se para antes de tocar nada', () => {
    // Generado «dentro de una hora»: para el servidor, su reloj va una hora atrasado.
    const script = template.render({
      ...CA,
      issuedAt: Math.floor(Date.now() / 1000) + 3600,
    });
    expect(script).toMatch(/local issued_at='\d+'/);
    expect(script).toContain('el reloj del servidor va atrasado');
    // El orden: la comprobación va antes de crear el usuario o tocar sshd.
    expect(script.indexOf('el reloj del servidor va atrasado')).toBeLessThan(
      script.indexOf('configure_ssh_ca "$user"'),
    );
    execFileSync('bash', ['-n'], { input: script });
  });

  it('modo CA y estático no se mezclan', () => {
    expect(() =>
      template.render({ ...CA, publicKey: VALUES.publicKey }),
    ).toThrow(/no lleva clave estática/);
    expect(() => template.render({ ...VALUES, caKeys: [CA_KEY] })).toThrow(
      /no lleva claves de CA/,
    );
    expect(() => template.render({ ...CA, caKeys: [] })).toThrow(/entre 1 y 4/);
    expect(() => template.render({ ...VALUES, publicKey: '' })).toThrow(
      'Valor no válido para el script de alta: publicKey',
    );
  });

  it.each([
    "ssh-ed25519 AAAA'; id",
    'ssh-rsa AAAAB3NzaC1yc2E',
    `${CA_KEY} comentario`,
    `${CA_KEY}\nssh-ed25519 AAAA`,
  ])('rechaza una clave de CA no válida: %s', (key) => {
    expect(() => template.render({ ...CA, caKeys: [key] })).toThrow(
      'Valor no válido para el script de alta: caKeys',
    );
  });

  it('falla al cargar una plantilla inexistente o sin marcadores', () => {
    expect(() => EnrollScriptTemplate.load('/no/existe.tmpl')).toThrow(
      /No se puede leer/,
    );
    expect(() => EnrollScriptTemplate.fromString('#!/bin/bash\n')).toThrow(
      /faltan marcadores/,
    );
  });

  it('sudoers v4: una sola regla con el ayudante de root, en la ruta que usa el worker', () => {
    const source = readFileSync(
      new URL('../../../../ansible/enroll/enroll.sh.tmpl', import.meta.url),
      'utf8',
    );
    expect(source).toContain(`QUERY_HELPER=${INFRAWARD_QUERY_HELPER}`);
    expect(source).toContain(`LEGACY_PLESK_HELPER=${LEGACY_PLESK_QUERY_HELPER}`);
    expect(source).toContain(
      `printf '%s ALL=(root) NOPASSWD: %s\\n' "$user" "$QUERY_HELPER"`,
    );
    // Ninguna regla con comodines, regex ni comandos sueltos.
    expect(source).not.toMatch(/add (docker|pvesh|pct|qm|plesk|dmidecode|ss) /);
    expect(source).not.toContain('sudo_supports_regex');
  });

});

describe('enroll.sh: ~/.ssh del usuario de inventario (revisión #3, M5)', () => {
  const script = EnrollScriptTemplate.load().render(VALUES);
  const comment = VALUES.keyComment;
  const keyLine = `restrict ${VALUES.publicKey}`;
  let home: string;
  let victim: string;

  /**
   * Las funciones de verdad del script, con `as_user` sin cambiar de usuario (los tests no
   * corren como root): lo que se prueba es que no se sigue ningún enlace y qué se escribe.
   */
  function run(body: string): { status: number; stderr: string } {
    const harness = [
      'log() { printf \'[infraward] %s\\n\' "$*" >&2; }',
      'die() { log "ERROR: $*"; exit 1; }',
      functionBody(script, 'check_ssh_paths') + '\n}',
      functionBody(script, 'replace_key_line') + '\n}',
      'as_user() { shift; "$@"; }',
      'set -euo pipefail',
      body,
    ].join('\n');
    try {
      execFileSync('bash', ['-c', harness, 'bash', home, userInfo().username], {
        stdio: 'pipe',
      });
      return { status: 0, stderr: '' };
    } catch (error) {
      const e = error as { status: number; stderr: Buffer };
      return { status: e.status, stderr: String(e.stderr) };
    }
  }
  const install = (line = keyLine) =>
    run(
      `check_ssh_paths "$1" "$2" && replace_key_line "$1/.ssh/authorized_keys" '${comment}' '${line}' "$2"`,
    );

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'enroll-home-'));
    victim = mkdtempSync(join(tmpdir(), 'enroll-victim-'));
    writeFileSync(
      join(victim, 'authorized_keys'),
      'ssh-ed25519 AAAA root@admin\n',
    );
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(victim, { recursive: true, force: true });
  });

  it('sustituye solo la línea del asset y deja las demás (600)', () => {
    mkdirSync(join(home, '.ssh'), { mode: 0o700 });
    const file = join(home, '.ssh', 'authorized_keys');
    writeFileSync(
      file,
      `ssh-ed25519 OTRA admin@laptop\nrestrict vieja ${comment}\n`,
    );
    expect(install().status).toBe(0);
    expect(readFileSync(file, 'utf8')).toBe(
      `ssh-ed25519 OTRA admin@laptop\n${keyLine}\n`,
    );
    expect(lstatSync(file).mode & 0o777).toBe(0o600);
    // Con línea vacía, solo la quita (modo CA).
    expect(install('').status).toBe(0);
    expect(readFileSync(file, 'utf8')).toBe('ssh-ed25519 OTRA admin@laptop\n');
  });

  it('~/.ssh como enlace simbólico: aborta sin tocar el destino', () => {
    symlinkSync(victim, join(home, '.ssh'));
    const res = install();
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain('es un enlace simbólico');
    expect(readFileSync(join(victim, 'authorized_keys'), 'utf8')).toBe(
      'ssh-ed25519 AAAA root@admin\n',
    );
  });

  it('authorized_keys como enlace simbólico: aborta sin tocar el destino', () => {
    mkdirSync(join(home, '.ssh'), { mode: 0o700 });
    symlinkSync(
      join(victim, 'authorized_keys'),
      join(home, '.ssh', 'authorized_keys'),
    );
    const res = install();
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain('es un enlace simbólico');
    expect(readFileSync(join(victim, 'authorized_keys'), 'utf8')).toBe(
      'ssh-ed25519 AAAA root@admin\n',
    );
  });

  it('un enlace que aparece entre la comprobación y la escritura se sustituye, no se sigue', () => {
    mkdirSync(join(home, '.ssh'), { mode: 0o700 });
    const file = join(home, '.ssh', 'authorized_keys');
    symlinkSync(join(victim, 'authorized_keys'), file);
    // Sin check_ssh_paths (como si el enlace llegara después): `mv` cambia la entrada.
    const res = run(
      `replace_key_line "$1/.ssh/authorized_keys" '${comment}' '${keyLine}' "$2"`,
    );
    expect(res.status).toBe(0);
    expect(lstatSync(file).isSymbolicLink()).toBe(false);
    expect(readFileSync(join(victim, 'authorized_keys'), 'utf8')).toBe(
      'ssh-ed25519 AAAA root@admin\n',
    );
    expect(existsSync(join(home, '.ssh'))).toBe(true);
  });

  it('el alta crea ~/.ssh y escribe como el usuario, nunca como root', () => {
    const body = functionBody(script, 'main');
    expect(body).toContain('as_user "$user" mkdir -p -m 700 "$home/.ssh"');
    expect(body).not.toContain('install -d -m 700 -o "$user"');
    expect(functionBody(script, 'replace_key_line')).toContain(
      'as_user "$user" sh -c',
    );
  });
});

/** Cuerpo de una función de bash del script (de `nombre() {` a la `}` de la columna 0). */
function functionBody(script: string, name: string): string {
  const start = script.indexOf(`\n${name}() {`);
  expect(start, name).toBeGreaterThan(0);
  return script.slice(start, script.indexOf('\n}\n', start));
}
