import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { waitFor, type TestWorker } from './worker.js';

const WORKER_MAIN = resolve(import.meta.dirname, '../../../worker/dist/main.js');

/** Puerto TCP libre en 127.0.0.1 (para el gateway: la API tiene que conocerlo antes). */
export function freePort(): Promise<number> {
  return new Promise((done, fail) => {
    const server = createServer();
    server.once('error', fail);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => done(typeof address === 'object' && address ? address.port : 0));
    });
  });
}

/**
 * Lanza el modo `gateway` del worker compilado (`node dist/main.js gateway`) con su propio
 * entorno: Redis, BD, la API y el secreto compartido. Nada del gestor de secretos.
 */
export async function startGateway(env: Record<string, string>): Promise<TestWorker> {
  if (!existsSync(WORKER_MAIN))
    throw new Error(`No existe ${WORKER_MAIN}: compila antes el worker`);
  const shared = [
    'NODE_ENV',
    'REDIS_HOST',
    'REDIS_PORT',
    'REDIS_DB',
    'DATABASE_HOST',
    'DATABASE_PORT',
    'DATABASE_USER',
    'DATABASE_PASSWORD',
    'DATABASE_NAME',
  ];
  const base: Record<string, string> = { PATH: process.env.PATH ?? '' };
  for (const name of shared) base[name] = process.env[name] ?? '';
  const child = spawn(process.execPath, [WORKER_MAIN, 'gateway'], {
    env: { ...base, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const output: string[] = [];
  child.stdout!.on('data', (d: Buffer) => output.push(d.toString()));
  child.stderr!.on('data', (d: Buffer) => output.push(d.toString()));
  await waitFor(
    () => output.join('').includes('Gateway listo') || child.exitCode !== null,
    30_000,
    () => `el gateway no arrancó:\n${output.join('')}`,
  );
  if (child.exitCode !== null) throw new Error(`el gateway salió:\n${output.join('')}`);
  return { child, output };
}
