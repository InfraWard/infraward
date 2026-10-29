import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { migrations } from './migrations/index.js';

// Las migraciones se registran a mano en migrations/index.ts: este test impide olvidarse
// de una (no se ejecutaría nunca) o registrar una que ya no existe.
const MIGRATIONS_DIR = join(import.meta.dirname, 'migrations');
const MIGRATION_FILE = /^(\d{13})-[\w-]+\.ts$/;

async function migrationClassesOnDisk() {
  const files = readdirSync(MIGRATIONS_DIR).filter((f) =>
    MIGRATION_FILE.test(f),
  );
  const classes: { file: string; name: string; timestamp: string }[] = [];
  for (const file of files) {
    const exported = Object.values(await import(join(MIGRATIONS_DIR, file)));
    expect(
      exported,
      `${file} debe exportar exactamente una clase`,
    ).toHaveLength(1);
    classes.push({
      file,
      name: (exported[0] as { name: string }).name,
      timestamp: MIGRATION_FILE.exec(file)![1],
    });
  }
  return classes;
}

describe('registro de migraciones', () => {
  it('index.ts registra todas las migraciones de la carpeta y ninguna más', async () => {
    const onDisk = (await migrationClassesOnDisk()).map((m) => m.name).sort();
    const registered = migrations.map((m) => m.name).sort();
    expect(registered).toEqual(onDisk);
  });

  it('están en orden cronológico y el nombre de clase lleva el timestamp del fichero', async () => {
    const byName = new Map(
      (await migrationClassesOnDisk()).map((m) => [m.name, m]),
    );
    const timestamps = migrations.map((m) => {
      const onDisk = byName.get(m.name)!;
      expect(m.name.endsWith(onDisk.timestamp), onDisk.file).toBe(true);
      return Number(onDisk.timestamp);
    });
    expect(timestamps).toEqual([...timestamps].sort((a, b) => a - b));
  });
});
