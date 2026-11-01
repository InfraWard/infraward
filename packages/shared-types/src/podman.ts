// Podman rootless en los hosts (sudoers v8): usuarios detectados y cómo habilitarlos (DESIGN §8).

/**
 * Lista de usuarios de Podman rootless que InfraWard inventaría (uno por línea; `#` comenta). El
 * ayudante de root solo habla con el socket de los usuarios de esta lista: es el consentimiento
 * explícito del administrador del servidor. La escribe el comando «Habilitar» de la ficha
 * (`PODMAN_ENABLE_SCRIPT`) o, opcionalmente, el script de alta con `--podman-users=a,b`.
 */
export const PODMAN_USERS_FILE = '/etc/infraward/podman-users';

/** Nombre de usuario válido para Podman rootless (el mismo patrón en el ayudante y los scripts). */
export const PODMAN_USER_NAME = /^[a-z_][a-z0-9_.-]{0,31}$/;

/** Máximo de usuarios que se habilitan de una vez. */
export const PODMAN_ENABLE_MAX_USERS = 20;

/**
 * Usuario con Podman rootless que la recolección ha detectado (`facts.detected.podmanUsers`).
 * Señales (todas de solo lectura, como root en el servidor):
 * - `containers`: contenedores en marcha (procesos `conmon` del usuario, uno por contenedor);
 * - `socket`: `/run/user/<uid>/podman/podman.sock` existe (`podman.socket` activo);
 * - `storage`: su home (de `/etc/passwd`, uid ≥ 1000) tiene `~/.local/share/containers/storage`;
 * - `enabled`: está en `PODMAN_USERS_FILE`.
 * `linger` (`/var/lib/systemd/linger/<usuario>`) solo informa: sin él, el socket desaparece al
 * cerrar su última sesión.
 */
export interface PodmanRootlessUser {
  uid: number;
  /** null si el uid no tiene usuario (contenedores de un uid sin entrada en passwd). */
  name: string | null;
  enabled: boolean;
  socket: boolean;
  storage: boolean;
  linger: boolean;
  containers: number;
}

/**
 * Estado de un usuario para la ficha:
 * - `inventoried`: habilitado y con socket: sus contenedores se inventarían;
 * - `no_socket`: habilitado, pero sin socket: no se le puede preguntar;
 * - `not_enabled`: detectado y fuera de la lista: no se inventaría.
 */
export type PodmanUserState = 'inventoried' | 'no_socket' | 'not_enabled';

export function podmanUserState(user: PodmanRootlessUser): PodmanUserState {
  if (!user.enabled) return 'not_enabled';
  return user.socket ? 'inventoried' : 'no_socket';
}

/** ¿Se puede ofrecer «Habilitar»? (tiene nombre y no está ya inventariado). */
export function podmanUserNeedsEnable(user: PodmanRootlessUser): boolean {
  return (
    user.name !== null && PODMAN_USER_NAME.test(user.name) && podmanUserState(user) !== 'inventoried'
  );
}

/**
 * Habilita Podman rootless para los usuarios que recibe como argumentos (`sh -c <script> sh a b`).
 * Se ejecuta como root en el servidor, a mano (`podmanEnableCommand`) o por el acceso de
 * administración desde la ficha (terminal de solo lectura). Por cada usuario:
 * `loginctl enable-linger` (su gestor de systemd sigue vivo sin sesión), `systemctl --user enable
 * --now podman.socket` como ese usuario, y lo añade a `PODMAN_USERS_FILE` (escritura atómica, sin
 * seguir enlaces). Valida todos los nombres antes de tocar nada. Es idempotente.
 * POSIX sh, sin `${` (va dentro de una plantilla de TypeScript).
 */
export const PODMAN_ENABLE_SCRIPT = `set -u
F=${PODMAN_USERS_FILE}
[ "$(id -u)" = 0 ] || { echo 'Hay que ejecutarlo como root (sudo)' >&2; exit 1; }
[ $# -gt 0 ] || { echo 'Faltan los usuarios' >&2; exit 64; }
command -v loginctl >/dev/null 2>&1 || { echo 'Hace falta systemd (loginctl) para el socket de Podman de cada usuario' >&2; exit 1; }
for u in "$@"; do
  case $u in [a-z_]*) ;; *) echo "Usuario no válido: $u" >&2; exit 64 ;; esac
  case $u in *[!a-z0-9_.-]*) echo "Usuario no válido: $u" >&2; exit 64 ;; esac
  [ "$(printf %s "$u" | wc -c)" -le 32 ] || { echo "Usuario no válido: $u" >&2; exit 64; }
  n=$(id -u -- "$u" 2>/dev/null) || { echo "El usuario $u no existe" >&2; exit 1; }
  [ "$n" != 0 ] || { echo 'root no es un usuario de Podman rootless' >&2; exit 64; }
done
if [ -L "$F" ] || [ -L /etc/infraward ]; then echo "$F es un enlace simbólico: no se toca" >&2; exit 1; fi
rc=0
for u in "$@"; do
  n=$(id -u -- "$u")
  echo "== $u (uid $n)"
  echo "+ loginctl enable-linger $u"
  loginctl enable-linger "$u" || { echo "No se pudo activar linger para $u" >&2; rc=1; continue; }
  i=0
  while [ ! -S "/run/user/$n/bus" ] && [ $i -lt 30 ]; do sleep 1; i=$((i + 1)); done
  echo "+ systemctl --user enable --now podman.socket (como $u)"
  e="XDG_RUNTIME_DIR=/run/user/$n DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$n/bus"
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$u" -- env $e systemctl --user enable --now podman.socket
  else
    su -s /bin/sh -c "env $e systemctl --user enable --now podman.socket" "$u"
  fi || { echo "No se pudo activar el socket de Podman de $u" >&2; rc=1; continue; }
  if [ -S "/run/user/$n/podman/podman.sock" ]; then
    echo "Socket: /run/user/$n/podman/podman.sock"
  else
    echo "AVISO: no aparece /run/user/$n/podman/podman.sock" >&2
    rc=1
  fi
done
install -d -m 755 -o root -g root /etc/infraward || exit 1
t=$(mktemp /etc/infraward/.podman-users.XXXXXX) || exit 1
{
  if [ -f "$F" ]; then cat "$F"; else echo '# Usuarios de Podman rootless que inventaría InfraWard.'; fi
  for u in "$@"; do grep -qxF -- "$u" "$F" 2>/dev/null || echo "$u"; done
} >"$t"
chmod 644 "$t" && mv -f "$t" "$F" || { rm -f "$t"; exit 1; }
echo "+ $F: $(grep -v '^#' "$F" | tr '\\n' ' ')"
echo 'Listo: vuelve a recolectar el servidor en InfraWard para ver sus contenedores.'
exit $rc
`;

/** Delimitador del heredoc de `podmanEnableCommand` (no aparece en el script). */
const HEREDOC = 'INFRAWARD_PODMAN';

/**
 * Comando para copiar y ejecutar en el servidor con una cuenta con sudo: el script por la entrada
 * estándar (heredoc entre comillas: nada se expande) y los usuarios como argumentos.
 * @throws si algún nombre no es válido o la lista está vacía o es demasiado larga.
 */
export function podmanEnableCommand(users: readonly string[]): string {
  if (users.length === 0 || users.length > PODMAN_ENABLE_MAX_USERS)
    throw new Error('Lista de usuarios de Podman vacía o demasiado larga');
  for (const user of users)
    if (!PODMAN_USER_NAME.test(user)) throw new Error(`Usuario de Podman no válido: ${user}`);
  return `sudo sh -s -- ${users.join(' ')} <<'${HEREDOC}'\n${PODMAN_ENABLE_SCRIPT}${HEREDOC}\n`;
}
