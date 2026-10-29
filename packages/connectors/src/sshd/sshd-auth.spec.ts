import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { parseSshdAuth, SSHD_AUTH_SCRIPT } from './sshd-auth.js';

const dir = mkdtempSync(join(tmpdir(), 'infraward-sshd-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** `sshd` falso: imprime una configuración de `sshd -T` completa (con claves y rutas). */
function fakeSshd(name: string, config: string): string {
  const bin = join(dir, name);
  mkdirSync(bin, { recursive: true });
  writeFileSync(
    join(bin, 'sshd'),
    `#!/bin/sh
[ "$1" = "-T" ] || exit 9
[ "$2" = "-C" ] || exit 9
[ "$3" = "user=root,host=localhost,addr=127.0.0.1" ] || exit 9
cat <<'CONF'
${config}
CONF
`,
  );
  chmodSync(join(bin, 'sshd'), 0o755);
  return bin;
}

function run(path: string) {
  return spawnSync('sh', ['-c', SSHD_AUTH_SCRIPT, 'sh'], {
    encoding: 'utf8',
    env: { PATH: `${path}:/usr/bin:/bin` },
  });
}

const FULL = `port 22
permitrootlogin yes
passwordauthentication yes
kbdinteractiveauthentication no
hostkey /etc/ssh/ssh_host_ed25519_key
authorizedkeyscommand /usr/local/bin/centinela-comando
trustedusercakeys /etc/ssh/infraward/trusted_user_ca_keys
banner /etc/issue.centinela`;

describe('SSHD_AUTH_SCRIPT', () => {
  it('saca solo las tres opciones de autenticación', () => {
    const r = run(fakeSshd('a', FULL));
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(
      'permitrootlogin\tyes\npasswordauthentication\tyes\nkbdinteractiveauthentication\tno\n',
    );
    expect(r.stdout).not.toMatch(/centinela|hostkey|\/etc/);
    expect(parseSshdAuth(r.stdout)).toEqual({
      permitRootLogin: 'yes',
      passwordAuthentication: true,
      kbdInteractiveAuthentication: false,
    });
  });

  it('OpenSSH antiguo: challengeresponseauthentication', () => {
    const r = run(
      fakeSshd(
        'b',
        'permitrootlogin without-password\npasswordauthentication no\nchallengeresponseauthentication yes',
      ),
    );
    expect(parseSshdAuth(r.stdout)).toEqual({
      permitRootLogin: 'prohibit-password',
      passwordAuthentication: false,
      kbdInteractiveAuthentication: true,
    });
  });

  it('sin sshd sale con 3', () => {
    const empty = join(dir, 'vacio');
    mkdirSync(empty, { recursive: true });
    const r = spawnSync('/bin/sh', ['-c', SSHD_AUTH_SCRIPT, 'sh'], {
      encoding: 'utf8',
      env: { PATH: empty },
    });
    // /usr/sbin/sshd puede existir en la máquina de los tests: entonces no sale con 3.
    if (r.status === 3) expect(r.stdout).toBe('');
    else expect(r.stdout).not.toMatch(/hostkey|\/etc/);
  });

  it('cumple las restricciones para copiarlo en el ayudante (sin comillas simples en el awk ni ${)', () => {
    expect(SSHD_AUTH_SCRIPT).not.toMatch(/\{\{|\{%|\{#|\$\{/);
    const awk = SSHD_AUTH_SCRIPT.slice(SSHD_AUTH_SCRIPT.indexOf("awk '") + 5);
    expect(awk.slice(0, awk.lastIndexOf("'"))).not.toContain("'");
  });
});

describe('parseSshdAuth', () => {
  it('null si faltan datos o hay valores extraños', () => {
    expect(parseSshdAuth('')).toBeNull();
    expect(parseSshdAuth('permitrootlogin yes')).toBeNull();
    expect(parseSshdAuth('permitrootlogin quizás\npasswordauthentication yes')).toBeNull();
    expect(parseSshdAuth('permitrootlogin yes\npasswordauthentication sí')).toBeNull();
  });
});
