import type { CollectedProcess } from '@infraward/shared-types';

/** Como mucho, procesos y paquetes de librerías por proceso (el script y el parser). */
export const PROCESS_PACKAGES_MAX = 300;
export const PROCESS_LIB_PACKAGES_MAX = 100;

/**
 * Qué paquetes usan los procesos en marcha (sudoers v6, sesión 19; DESIGN §7 y §9). Se ejecuta
 * EN EL SERVIDOR como root (`sh -c PROCESS_PACKAGES_SCRIPT sh`, sin argumentos; los dos
 * opcionales solo los usan los tests para cambiar la raíz de /proc y de los cgroups):
 * 1. Procesos: los que escuchan (`ss -Htulpn`) y el primero de cada servicio de systemd en marcha
 *    (sus cgroups). Fuera los de contenedores, CT y VMs (su ejecutable no es del servidor).
 * 2. De cada uno, el ejecutable (`/proc/<pid>/exe`) y las `.so` que tiene cargadas (`maps`).
 * 3. El paquete de cada ruta, en una sola llamada (`dpkg -S` o `rpm -qf`), con la otra forma de
 *    la ruta de usrmerge (`/usr/lib/x` ↔ `/lib/x`).
 * Salida, una línea por proceso: `P<TAB>pid<TAB>nombre<TAB>unidad<TAB>paquete del ejecutable<TAB>
 * paquetes de librerías separados por comas`. Nunca rutas, entorno ni línea de órdenes; cada
 * nombre pasa por una lista blanca.
 *
 * El ayudante (`ansible/enroll/enroll.sh.tmpl`) y el playbook lo llevan tal cual (un test lo
 * compara). Sin comillas simples dentro de los awk ni `{{`, `{%`, `{#` o `${`.
 */
export const PROCESS_PACKAGES_SCRIPT = `P=$1
[ -n "$P" ] || P=/proc
G=$2
[ -n "$G" ] || G=/sys/fs/cgroup
LC_ALL=C
export LC_ALL
pids=$( {
  ss -Htulpn 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2
  for f in "$G"/system.slice/*.service/cgroup.procs "$G"/systemd/system.slice/*.service/cgroup.procs; do
    [ -r "$f" ] && head -n 1 "$f"
  done
} | grep -E '^[0-9]+$' | sort -un | head -n ${PROCESS_PACKAGES_MAX} )
set -f
procs=$(for pid in $pids; do
  cg=$(cat "$P/$pid/cgroup" 2>/dev/null)
  case $cg in (*docker*|*containerd*|*libpod*|*lxc.payload*|*machine.slice*|*kubepods*) continue ;; esac
  exe=$(readlink "$P/$pid/exe" 2>/dev/null) || continue
  [ -n "$exe" ] || continue
  comm=$(head -n 1 "$P/$pid/comm" 2>/dev/null)
  unit=$(printf '%s\\n' "$cg" | sed -n 's#^.*/\\([^/]*\\.service\\)$#\\1#p' | head -n 1)
  printf 'X\\t%s\\t%s\\t%s\\t%s\\n' "$pid" "$comm" "$unit" "$exe"
  awk -v p="$pid" '$6 ~ /\\.so/ { print "L\\t" p "\\t" $6 }' "$P/$pid/maps" 2>/dev/null | sort -u | head -n 400
done)
paths=$(printf '%s\\n' "$procs" | awk -F '\\t' '
  $1 == "X" || $1 == "L" {
    p = ($1 == "X") ? $5 : $3
    sub(/ \\(deleted\\)$/, "", p)
    if (p !~ /^\\/[^ ]*$/) next
    print p
    if (p ~ /^\\/usr\\/(lib|lib32|lib64|libx32|bin|sbin)\\//) print substr(p, 5)
    else if (p ~ /^\\/(lib|lib32|lib64|libx32|bin|sbin)\\//) print "/usr" p
  }' | sort -u | head -n 8000)
owners=""
if [ -n "$paths" ]; then
  if command -v dpkg >/dev/null 2>&1; then
    owners=$(dpkg -S $paths 2>/dev/null | awk '
      index($0, "diversion by ") == 1 { next }
      { i = index($0, ": /"); if (!i) next
        k = substr($0, 1, i - 1); sub(/,.*/, "", k); sub(/:.*/, "", k)
        print "O\\t" substr($0, i + 2) "\\t" k }')
  elif command -v rpm >/dev/null 2>&1; then
    real=$(for p in $paths; do [ -e "$p" ] && printf '%s\\n' "$p"; done)
    if [ -n "$real" ]; then
      owners=$( { printf '%s\\n' "$real"; echo '#'; rpm -qf --qf '%{NAME}\\n' $real 2>/dev/null; } | awk '
        !s && $0 == "#" { s = 1; next }
        !s { R[++n] = $0; next }
        { m++; if ($0 !~ / /) print "O\\t" R[m] "\\t" $0 }')
    fi
  fi
fi
{ printf '%s\\n' "$owners"; printf '%s\\n' "$procs"; } | awk -F '\\t' '
function canon(p) {
  sub(/ \\(deleted\\)$/, "", p)
  if (p ~ /^\\/usr\\/(lib|lib32|lib64|libx32|bin|sbin)\\//) p = substr(p, 5)
  return p
}
function safe(t) { return (t ~ /^[A-Za-z0-9][A-Za-z0-9._+:@-]*$/) ? substr(t, 1, 128) : "" }
$1 == "O" { k = canon($2); if (!(k in OWN)) OWN[k] = $3; next }
$1 == "X" { if ($2 in IDX) next; n++; PID[n] = $2; NAME[n] = $3; UNIT[n] = $4; EXE[n] = $5; IDX[$2] = n; next }
$1 == "L" {
  if (!($2 in IDX)) next
  i = IDX[$2]; k = canon($3)
  if (!(k in OWN)) next
  q = safe(OWN[k])
  if (q == "" || ((i, q) in SEEN) || C[i] >= ${PROCESS_LIB_PACKAGES_MAX}) next
  SEEN[i, q] = 1; C[i]++
  LIBS[i] = LIBS[i] "," q
}
END {
  for (i = 1; i <= n; i++) {
    e = canon(EXE[i]); ep = (e in OWN) ? safe(OWN[e]) : ""
    out = ""; cnt = split(LIBS[i], parts, ",")
    for (j = 1; j <= cnt; j++) if (parts[j] != "" && parts[j] != ep) out = out (out == "" ? "" : ",") parts[j]
    print "P\\t" PID[i] "\\t" safe(NAME[i]) "\\t" safe(UNIT[i]) "\\t" ep "\\t" out
  }
}'
`;

const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._+:@-]{0,127}$/;

/** Salida del script → procesos (lo que no encaja se descarta). */
export function parseProcessPackages(output: string): CollectedProcess[] {
  const out: CollectedProcess[] = [];
  const seen = new Set<number>();
  for (const line of output.split('\n')) {
    const [tag, pidText, name, unit, exe, libs] = line
      .replace(/\r$/, '')
      .split('\t');
    if (tag !== 'P') continue;
    const pid = Number(pidText);
    if (!Number.isInteger(pid) || pid <= 0 || seen.has(pid)) continue;
    seen.add(pid);
    const ok = (v: string | undefined) => (v && SAFE_NAME.test(v) ? v : null);
    const exePackage = ok(exe);
    out.push({
      pid,
      name: ok(name) ?? '',
      unit: ok(unit),
      exePackage,
      libPackages: [
        ...new Set(
          (libs ?? '')
            .split(',')
            .map(ok)
            .filter((p): p is string => p !== null && p !== exePackage),
        ),
      ].slice(0, PROCESS_LIB_PACKAGES_MAX),
    });
    if (out.length >= PROCESS_PACKAGES_MAX) break;
  }
  return out;
}
