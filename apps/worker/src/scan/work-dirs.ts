import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { currentWorkerName, WorkerIdentity } from '../redis/worker-identity.js';

/** Directorios de los escaneos de antes de separarlos por réplica (sesión W-0). */
const LEGACY_PREFIXES = ['scan-', 'host-', 'reevaluate-'];
/** Directorios temporales de las claves SSH (`SshClient.withMaterial`). */
const SSH_PREFIX = 'infraward-ssh-';

/** Base de los escaneos (`WORKER_SCAN_DIR`, compartida o no entre réplicas). */
export function scanBaseDir(
  config: ConfigService<EnvironmentVariables, true>,
): string {
  return (
    config.get('WORKER_SCAN_DIR', { infer: true }) ??
    join(tmpdir(), 'infraward-scan')
  );
}

/**
 * Directorio de trabajo de un job (`<base>/<réplica>/<prefijo>XXXXXX`, 700): cada réplica tiene
 * el suyo, así que al arrancar puede borrar lo que dejó a medias sin tocar lo de las demás.
 */
export async function makeWorkDir(
  base: string,
  prefix: string,
): Promise<string> {
  const root = join(base, currentWorkerName());
  await mkdir(root, { recursive: true, mode: 0o700 });
  return mkdtemp(join(root, prefix));
}

/**
 * Limpieza al arrancar (DESIGN §20): lo que una ejecución anterior de esta réplica dejó a medias
 * (imágenes de `docker save`, copias de BDs de paquetes, claves SSH en el tmpfs) si murió sin
 * poder borrarlo.
 */
@Injectable()
export class WorkDirCleaner {
  private readonly logger = new Logger(WorkDirCleaner.name);
  private readonly scanBase: string;
  private readonly sshBase: string;
  /** Lo que lleva más que esto sin tocarse no es de ningún job vivo. */
  private readonly staleMs: number;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    private readonly identity: WorkerIdentity,
  ) {
    this.scanBase = scanBaseDir(config);
    this.sshBase =
      config.get('WORKER_TMP_DIR', { infer: true }) ??
      (existsSync('/dev/shm') ? '/dev/shm' : tmpdir());
    this.staleMs =
      2 *
      Math.max(
        config.get('TRIVY_SCAN_TIMEOUT', { infer: true }),
        config.get('COLLECT_TIMEOUT', { infer: true }),
      ) *
      1000;
  }

  async clean(): Promise<void> {
    let removed = 0;
    const now = Date.now();
    const stale = async (path: string) => {
      const info = await stat(path).catch(() => null);
      return !!info && now - info.mtimeMs > this.staleMs;
    };
    const remove = async (path: string) => {
      await rm(path, { recursive: true, force: true });
      removed++;
    };
    // El directorio de esta réplica: nada de lo que hay es de un job vivo.
    const own = join(this.scanBase, this.identity.name);
    if (existsSync(own)) await remove(own);
    for (const entry of await readdir(this.scanBase, { withFileTypes: true }).catch(
      () => [],
    )) {
      if (!entry.isDirectory()) continue;
      const path = join(this.scanBase, entry.name);
      const legacy = LEGACY_PREFIXES.some((p) => entry.name.startsWith(p));
      // De otra réplica: solo si ya no está viva y lleva tiempo sin tocarse.
      if (
        (legacy || !(await this.identity.alive(entry.name))) &&
        (await stale(path))
      )
        await remove(path);
    }
    // Claves SSH (tmpfs compartido entre procesos de la misma máquina): solo las viejas.
    for (const name of await readdir(this.sshBase).catch(() => [] as string[]))
      if (name.startsWith(SSH_PREFIX) && (await stale(join(this.sshBase, name))))
        await remove(join(this.sshBase, name));
    if (removed)
      this.logger.log(`${removed} directorios temporales huérfanos borrados`);
  }
}
