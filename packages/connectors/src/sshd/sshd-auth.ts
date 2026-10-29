import type { SshdAuthFacts } from '@infraward/shared-types';

/**
 * Autenticación efectiva de sshd (sudoers v7, QoL-7; DESIGN §19). Se ejecuta EN EL SERVIDOR como
 * root (`sh -c SSHD_AUTH_SCRIPT sh`): `sshd -T` necesita root para cargar las host keys. Evalúa
 * la configuración para una conexión de `root` (los bloques `Match User root` cuentan) y saca
 * **solo** `permitrootlogin`, `passwordauthentication` y `kbdinteractiveauthentication`
 * (`challengeresponseauthentication` en OpenSSH < 8.7): ni claves, ni rutas, ni el resto de la
 * configuración. Solo lee: nunca cambia nada. Sin sshd, sale con 3.
 *
 * El ayudante (`ansible/enroll/enroll.sh.tmpl`) lo lleva tal cual (un test lo compara). Sin
 * comillas simples dentro del awk ni `{{`, `{%`, `{#` o `${`.
 */
export const SSHD_AUTH_SCRIPT = `LC_ALL=C
export LC_ALL
S=$(command -v sshd 2>/dev/null)
for c in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do
  [ -n "$S" ] && break
  [ -x "$c" ] && S=$c
done
[ -n "$S" ] || exit 3
"$S" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | awk '
$1 == "permitrootlogin" || $1 == "passwordauthentication" || $1 == "kbdinteractiveauthentication" || $1 == "challengeresponseauthentication" { print $1 "\\t" $2 }
'
`;

const ROOT_LOGIN = new Set([
  'yes',
  'no',
  'prohibit-password',
  'without-password',
  'forced-commands-only',
]);

/**
 * Lee la salida del script. null si no hay datos suficientes (sin sshd, sin root o salida
 * extraña): mejor no avisar que avisar mal.
 */
export function parseSshdAuth(stdout: string): SshdAuthFacts | null {
  const values = new Map<string, string>();
  for (const line of stdout.split('\n')) {
    const [key, value, extra] = line.trim().split(/\s+/);
    if (!key || !value || extra !== undefined) continue;
    if (!/^[a-z]+$/.test(key) || !/^[a-z-]+$/.test(value)) continue;
    values.set(key, value);
  }
  const root = values.get('permitrootlogin');
  const password = values.get('passwordauthentication');
  const kbd =
    values.get('kbdinteractiveauthentication') ??
    values.get('challengeresponseauthentication');
  if (!root || !ROOT_LOGIN.has(root) || !isYesNo(password)) return null;
  return {
    permitRootLogin: root === 'without-password' ? 'prohibit-password' : root,
    passwordAuthentication: password === 'yes',
    kbdInteractiveAuthentication: kbd === 'yes',
  };
}

function isYesNo(v: string | undefined): v is 'yes' | 'no' {
  return v === 'yes' || v === 'no';
}
