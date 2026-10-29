import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { QUEUE_NAMES, type QueueName } from '@infraward/shared-types';

const WORKER_MAIN = resolve(
  import.meta.dirname,
  '../../../worker/dist/main.js',
);

/**
 * Colas de trabajo (todas menos `system`, donde siempre puede haber un recálculo de prioridades
 * retrasado): las que se esperan vacías al terminar una cadena de jobs.
 */
export const WORK_QUEUES: readonly QueueName[] = Object.values(QUEUE_NAMES).filter(
  (q) => q !== QUEUE_NAMES.system,
);

/** Variables que el worker comparte con la API (las deja prepareEnv en process.env). */
const SHARED_ENV = [
  'NODE_ENV',
  'REDIS_HOST',
  'REDIS_PORT',
  'REDIS_DB',
  'DATABASE_HOST',
  'DATABASE_PORT',
  'DATABASE_USER',
  'DATABASE_PASSWORD',
  'DATABASE_NAME',
  'SECRETS_PROVIDERS',
  'SECRETS_LOCAL_MASTER_KEY_FILE',
  'SECRETS_LOCAL_MASTER_KEY',
];

export interface TestWorker {
  child: ChildProcess;
  output: string[];
}

/** Lanza el worker compilado como proceso aparte, con el mismo Redis, BD y clave que la API. */
export async function startWorker(
  extra: Record<string, string> = {},
): Promise<TestWorker> {
  if (!existsSync(WORKER_MAIN)) {
    throw new Error(
      `No existe ${WORKER_MAIN}: compila antes el worker (pnpm --filter @infraward/worker build)`,
    );
  }
  // Sin re-evaluación ni reconciliación periódicas (con `every`, BullMQ las lanzaría al
  // arrancar): cada test las pide.
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    SBOM_REEVALUATE_INTERVAL: '0',
    RECONCILE_TICK: '0',
    // Sin descargas reales de KEV ni EPSS (los e2e que las prueban apuntan a un servidor falso).
    VULN_INTEL_INTERVAL: '0',
    // Sin la muestra diaria: su job scheduler deja un job retrasado en `system` y los e2e que
    // esperan colas vacías no acabarían (el de paneles la activa).
    METRICS_SAMPLE_INTERVAL: '0',
    KEV_URL: '',
    EPSS_URL: '',
    // stopWorker espera 10 s antes de matarlo: un job en curso vuelve a la cola antes.
    WORKER_SHUTDOWN_GRACE: '5',
  };
  for (const name of SHARED_ENV) env[name] = process.env[name] ?? '';
  const child = spawn(process.execPath, [WORKER_MAIN], {
    env: { ...env, ...extra },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const output: string[] = [];
  child.stdout!.on('data', (d: Buffer) => output.push(d.toString()));
  child.stderr!.on('data', (d: Buffer) => output.push(d.toString()));
  await waitFor(
    () => output.join('').includes('Worker listo'),
    30_000,
    () => `el worker no arrancó:\n${output.join('')}`,
  );
  return { child, output };
}

export async function stopWorker(
  worker: TestWorker | undefined,
): Promise<void> {
  if (!worker || worker.child.exitCode !== null) return;
  const exited = new Promise((done) => worker.child.once('exit', done));
  worker.child.kill('SIGTERM');
  await Promise.race([exited, sleep(10_000)]);
  if (worker.child.exitCode === null) worker.child.kill('SIGKILL');
}

export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeoutMs: number,
  describe: () => string,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await condition())) {
    if (Date.now() > deadline) throw new Error(`Timeout: ${describe()}`);
    await sleep(100);
  }
}

/**
 * Espera a que el worker haya calculado la prioridad de todos los findings abiertos o aceptados
 * (`findings.prioritize`, que va unos segundos después de cada escaneo o recolección).
 */
export async function waitPrioritized(
  db: { query: (sql: string) => Promise<unknown> },
  timeoutMs = 20_000,
): Promise<void> {
  await waitFor(
    async () => {
      const [row] = (await db.query(
        `SELECT count(*)::int AS n FROM findings
          WHERE status IN ('open', 'accepted') AND priority IS NULL`,
      )) as { n: number }[];
      return row!.n === 0;
    },
    timeoutMs,
    () => 'findings sin prioridad',
  );
  // Y que no quede ninguno a punto de recalcularse (otra pasada en cola).
  await sleep(4000);
}
