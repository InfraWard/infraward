import {
  PODMAN_USER_NAME,
  PODMAN_USERS_FILE,
  podmanUserState,
  type PodmanRootlessUser,
} from '@infraward/shared-types';

export { PODMAN_USERS_FILE };

/** Máximo de usuarios que informa `PODMAN_USERS_SCRIPT`. */
export const PODMAN_USERS_MAX = 200;

/**
 * Detección de Podman rootless (sudoers v8). Se ejecuta EN EL SERVIDOR como root
 * (`sh -c PODMAN_USERS_SCRIPT sh`), solo lee y no habla con ningún socket. Junta por uid:
 * - `L`: usuarios de `PODMAN_USERS_FILE` (habilitados);
 * - `C`: contenedores en marcha de cada uid no root, contados por sus procesos `conmon` (uno por
 *   contenedor; las sesiones de `exec` repiten el id);
 * - `S`: sockets de Podman de usuario (`/run/user/<uid>/podman/podman.sock`);
 * - `H`: usuarios locales (`/etc/passwd`, 1000 ≤ uid < 65534) con almacén de Podman en su home
 *   (`~/.local/share/containers/storage`).
 * y saca una línea por uid: `P <uid> <habilitado> <socket> <almacén> <linger> <contenedores>
 * <usuario|?>` (linger: `/var/lib/systemd/linger/<usuario>`). `/etc/subuid` no cuenta: `useradd`
 * reparte rangos a todos los usuarios, use o no Podman.
 * Solo salen uids, nombres de usuario, banderas y números. El ayudante
 * (`ansible/enroll/enroll.sh.tmpl`) lo lleva tal cual (un test lo compara). Sin comillas simples
 * dentro del awk ni `{{`, `{%`, `{#` o `${`.
 */
export const PODMAN_USERS_SCRIPT = `LC_ALL=C
export LC_ALL
F=${PODMAN_USERS_FILE}
{
  if [ -r "$F" ]; then
    for u in $(awk '{ sub(/#.*/, ""); for (i = 1; i <= NF; i++) if ($i ~ /^[a-z_][a-z0-9_.-]*$/ && length($i) <= 32) print $i }' "$F"); do
      n=$(id -u -- "$u" 2>/dev/null) || continue
      echo "$n L"
    done
  fi
  for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = conmon ] || continue
    u=$(awk '/^Uid:/ { print $2; exit }' "$d/status" 2>/dev/null)
    c=$(tr '\\0' '\\n' <"$d/cmdline" 2>/dev/null | awk 'p == "-c" || p == "--cid" { print; exit } { p = $0 }')
    [ -n "$c" ] && echo "$u C $c"
  done | sort -u
  for s in /run/user/[0-9]*/podman/podman.sock; do
    [ -S "$s" ] && echo "$s" | awk -F/ '{ print $4, "S" }'
  done
  awk -F: '$3 >= 1000 && $3 < 65534 && $6 ~ /^\\// { print $3, $6 }' /etc/passwd 2>/dev/null | while read -r n h; do
    [ -d "$h/.local/share/containers/storage" ] && echo "$n H"
  done
} | awk '$1 ~ /^[1-9][0-9]*$/ { u[$1] = 1; if ($2 == "L") l[$1] = 1; else if ($2 == "S") s[$1] = 1; else if ($2 == "H") h[$1] = 1; else if ($2 == "C") c[$1]++ } END { for (n in u) print n, l[n] + 0, s[n] + 0, h[n] + 0, c[n] + 0 }' | sort -n | head -n ${PODMAN_USERS_MAX} | while read -r n l s h c; do
  m=$(id -nu "$n" 2>/dev/null || echo "?")
  k=0
  [ -e "/var/lib/systemd/linger/$m" ] && k=1
  echo "P $n $l $s $h $k $c $m"
done
`;

/** Usuario habilitado (de la lista) al que se le puede preguntar por su socket. */
export interface PodmanUser {
  uid: number;
  name: string;
  /** ¿Tiene activo el socket de Podman? Sin él no se le puede preguntar. */
  socket: boolean;
}

export interface PodmanUsers {
  /** Todos los detectados (habilitados o no), por uid. */
  detected: PodmanRootlessUser[];
  /** Los habilitados con nombre: los que el descubridor consulta (si tienen socket). */
  users: PodmanUser[];
}

const UID = /^[1-9][0-9]{0,9}$/;
const FLAG = /^[01]$/;

/** Lee la salida de `PODMAN_USERS_SCRIPT`; las líneas que no se entienden se ignoran. */
export function parsePodmanUsers(stdout: string): PodmanUsers {
  const detected: PodmanRootlessUser[] = [];
  for (const line of stdout.split('\n')) {
    const [kind, uid, l, s, h, k, c, name, extra] = line.trim().split(/\s+/);
    if (kind !== 'P' || extra !== undefined || !uid || !UID.test(uid)) continue;
    if (![l, s, h, k].every((f) => f !== undefined && FLAG.test(f))) continue;
    if (!c || !/^[0-9]{1,6}$/.test(c) || !name) continue;
    if (detected.some((u) => u.uid === Number(uid))) continue;
    detected.push({
      uid: Number(uid),
      name: PODMAN_USER_NAME.test(name) ? name : null,
      enabled: l === '1',
      socket: s === '1',
      storage: h === '1',
      linger: k === '1',
      containers: Number(c),
    });
    if (detected.length >= PODMAN_USERS_MAX) break;
  }
  const users = detected
    .filter((u): u is PodmanRootlessUser & { name: string } => u.enabled && u.name !== null)
    .map((u) => ({ uid: u.uid, name: u.name, socket: u.socket }));
  return { detected, users };
}

/**
 * Avisos de lo que no se ve de Podman rootless: contenedores en marcha de usuarios sin habilitar
 * y usuarios habilitados sin el socket activo. Los usuarios con almacén o socket pero sin
 * contenedores en marcha solo salen en la ficha (no son una recolección parcial).
 */
export function podmanRootlessWarnings(info: Pick<PodmanUsers, 'detected'>): string[] {
  const warnings: string[] = [];
  for (const u of info.detected) {
    const who = u.name ?? `uid ${u.uid}`;
    const state = podmanUserState(u);
    if (state === 'not_enabled' && u.containers > 0)
      warnings.push(
        `${u.containers} contenedor${u.containers === 1 ? '' : 'es'} de Podman rootless de ${who} sin inventariar: habilítalo desde la ficha («Usuarios de Podman»)`,
      );
    else if (state === 'no_socket')
      warnings.push(
        `Podman rootless de ${who}: sin socket activo, sus contenedores no se ven (vuelve a habilitarlo desde la ficha)`,
      );
  }
  return warnings;
}
