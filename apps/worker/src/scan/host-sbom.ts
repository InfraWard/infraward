import { isSudoDenial } from '@infraward/connectors';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { StreamingHostExec } from '../ssh/ssh-client.js';
import { SkipScan } from './scan-errors.js';

/**
 * Ficheros que se copian de un servidor o CT para generar su SBOM con `trivy rootfs` en el worker
 * (DESIGN §9): identificación del sistema y BDs de paquetes del SO. Lista CERRADA; todos son
 * legibles por cualquier usuario, así que se leen con `cat` sin sudo (en un CT, por `pct-exec`).
 * No cubre librerías de lenguajes sueltas en el disco (jar, node_modules, pip…).
 */
export const HOST_RELEASE_FILES = [
  'etc/os-release',
  'usr/lib/os-release',
  'etc/debian_version',
  // Ubuntu también tiene debian_version: sin lsb-release, Trivy lo toma por Debian testing.
  'etc/lsb-release',
  'var/lib/ubuntu-advantage/status.json',
  'etc/alpine-release',
  'etc/redhat-release',
  'etc/centos-release',
  'etc/fedora-release',
  'etc/almalinux-release',
  'etc/rocky-release',
  'etc/oracle-release',
  'etc/system-release',
  'etc/mariner-release',
  'etc/azurelinux-release',
  'etc/SuSE-release',
] as const;

export const HOST_PACKAGE_DATABASES = [
  'var/lib/dpkg/status',
  'lib/apk/db/installed',
  'var/lib/rpm/rpmdb.sqlite',
  // Con WAL, lo último instalado puede estar aún en el -wal.
  'var/lib/rpm/rpmdb.sqlite-wal',
  'var/lib/rpm/Packages',
  'var/lib/rpm/Packages.db',
  'usr/lib/sysimage/rpm/rpmdb.sqlite',
  'usr/lib/sysimage/rpm/rpmdb.sqlite-wal',
  'usr/lib/sysimage/rpm/Packages.db',
] as const;

const CANDIDATES: readonly string[] = [
  ...HOST_RELEASE_FILES,
  ...HOST_PACKAGE_DATABASES,
];
const DATABASES = new Set<string>(
  HOST_PACKAGE_DATABASES.filter((f) => !f.endsWith('-wal')),
);

const DPKG_STATUS = 'var/lib/dpkg/status';

/**
 * Quita de la BD de dpkg los paquetes sin ficheros instalados (`config-files`: desinstalado con su
 * configuración; `not-installed`). Trivy solo descarta los marcados `deinstall`/`purge`, así que
 * un `install ok config-files` saldría como instalado y con sus CVE, sin binarios en el disco
 * (Ansible y `dpkg -l` tampoco lo cuentan). Qué es vulnerable lo sigue decidiendo Trivy.
 */
export function pruneDpkgStatus(text: string): string {
  return text
    .split(/\n{2,}/)
    .filter(
      (stanza) =>
        !/^Status: \S+ \S+ (config-files|not-installed)\s*$/m.test(stanza),
    )
    .join('\n\n');
}

export interface HostCopy {
  /** Ficheros copiados (rutas relativas a la raíz). */
  files: string[];
  bytes: number;
  /** Listados por `ls` pero que `cat` no pudo leer. */
  unreadable: string[];
}

/**
 * Copia las BDs de paquetes del host a `dest` (la raíz que analiza `trivy rootfs`): un `ls` para
 * saber cuáles existen y un `cat` por fichero directo a disco, cada uno en su ruta canónica como
 * fichero normal (un enlace como `/etc/os-release` se lee siguiendo el enlace). Nada se
 * desempaqueta ni se escribe en el host. Límites de bytes (en total) y de tiempo.
 */
export async function copyPackageDatabases(
  host: StreamingHostExec,
  dest: string,
  limits: { maxBytes: number; timeoutMs: number },
): Promise<HostCopy> {
  const deadline = Date.now() + limits.timeoutMs;
  const listed = await host.run([
    'ls',
    '-1d',
    '--',
    ...CANDIDATES.map((f) => `/${f}`),
  ]);
  // Solo hay sudo en un CT (`pct-exec` del ayudante del nodo).
  if (isSudoDenial(listed.stderr, listed.code))
    throw new SkipScan(
      'sudo no permite leer el CT desde el nodo: vuelve a ejecutar el script de alta en el nodo (sudoers v4)',
    );
  // `ls` sale con 2 si falta alguno: vale lo que lista, y solo lo que está en la lista.
  const present = new Set(
    listed.stdout
      .split('\n')
      .map((l) => l.trim().replace(/^\//, ''))
      .filter((f) => CANDIDATES.includes(f)),
  );
  const copy: HostCopy = { files: [], bytes: 0, unreadable: [] };
  for (const file of CANDIDATES.filter((f) => present.has(f))) {
    const remaining = deadline - Date.now();
    if (remaining <= 0)
      throw new SkipScan(
        `Tiempo agotado copiando las BDs de paquetes (TRIVY_SCAN_TIMEOUT)`,
      );
    const target = join(dest, file);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const result = await host.streamArgvToFile(
      ['cat', '--', `/${file}`],
      target,
      {
        maxBytes: limits.maxBytes - copy.bytes,
        timeoutMs: remaining,
      },
    );
    if (result.limit === 'size')
      throw new SkipScan(
        `Las BDs de paquetes superan HOST_SBOM_MAX_SIZE (${Math.round(limits.maxBytes / 1024 ** 2)} MiB)`,
      );
    if (result.limit === 'time')
      throw new SkipScan(
        `Tiempo agotado copiando las BDs de paquetes (TRIVY_SCAN_TIMEOUT)`,
      );
    copy.bytes += result.bytes;
    if (result.code === 0) copy.files.push(file);
    else {
      // Nada a medias: Trivy no debe ver un fichero cortado.
      await rm(target, { force: true });
      copy.unreadable.push(`/${file}`);
    }
  }
  if (copy.files.includes(DPKG_STATUS)) {
    const status = join(dest, DPKG_STATUS);
    await writeFile(status, pruneDpkgStatus(await readFile(status, 'utf8')));
  }
  if (!copy.files.some((f) => DATABASES.has(f)))
    throw new SkipScan(
      copy.unreadable.length
        ? `No se pudo leer ninguna BD de paquetes (${copy.unreadable.join(', ')})`
        : 'Ninguna BD de paquetes reconocida (dpkg, apk o rpm)',
    );
  return copy;
}
