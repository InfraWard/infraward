import { Logger } from '@nestjs/common';
import type { DataSource } from 'typeorm';
import { SCHEMA_RETRY_MS, SchemaGate } from './schema-gate.js';

const entities = [
  { tablePath: 'assets', columns: [{ databaseName: 'id' }, { databaseName: 'name' }] },
  { tablePath: 'job_runs', columns: [{ databaseName: 'id' }, { databaseName: 'worker' }] },
];

function gate(query: (sql: string) => Promise<unknown>) {
  const db = { entityMetadatas: entities, query: vi.fn(query) };
  return { gate: new SchemaGate(db as unknown as DataSource), db };
}

const pgError = (code: string, message: string) =>
  Object.assign(new Error(message), { code });

describe('SchemaGate', () => {
  it('comprueba todas las columnas de cada entidad sin leer filas', async () => {
    const { gate: g, db } = gate(() => Promise.resolve([]));
    await expect(g.missing()).resolves.toBeNull();
    expect(db.query.mock.calls.map((c) => c[0])).toEqual([
      'SELECT "id", "name" FROM "assets" LIMIT 0',
      'SELECT "id", "worker" FROM "job_runs" LIMIT 0',
    ]);
  });

  it('una columna sin migrar: dice cuál; la BD caída, solo el tipo del error', async () => {
    const missing = gate((sql) =>
      sql.includes('job_runs')
        ? Promise.reject(pgError('42703', 'column "worker" does not exist'))
        : Promise.resolve([]),
    );
    await expect(missing.gate.missing()).resolves.toBe(
      'job_runs: column "worker" does not exist',
    );
    const down = gate(() => Promise.reject(pgError('ECONNREFUSED', 'connect ECONNREFUSED 10.0.0.1:5432')));
    await expect(down.gate.missing()).resolves.toBe('la base de datos no responde (Error)');
  });

  it('espera (sin tomar jobs) hasta que la API aplica la migración', async () => {
    vi.useFakeTimers();
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    let migrated = false;
    const { gate: g } = gate((sql) =>
      !migrated && sql.includes('job_runs')
        ? Promise.reject(pgError('42703', 'column "worker" does not exist'))
        : Promise.resolve([]),
    );
    let done = false;
    const waiting = g.wait().then(() => (done = true));
    await vi.advanceTimersByTimeAsync(SCHEMA_RETRY_MS * 2);
    expect(done).toBe(false);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('Esperando a que la API aplique las migraciones'),
    );
    migrated = true;
    await vi.advanceTimersByTimeAsync(SCHEMA_RETRY_MS);
    await waiting;
    expect(log).toHaveBeenCalledWith('Esquema de la base de datos al día');
    warn.mockRestore();
    log.mockRestore();
    vi.useRealTimers();
  });
});
