import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

/** Cada cuánto se vuelve a mirar el esquema mientras falte algo. */
export const SCHEMA_RETRY_MS = 5000;
/** Cada cuánto se repite el aviso en el log mientras se espera. */
const WARN_EVERY_MS = 30_000;

/**
 * El esquema lo migra la API al arrancar (DESIGN §4): si el worker arranca a la vez (`pnpm dev`, un
 * despliegue con las dos imágenes nuevas) podría tomar jobs antes y fallarlos por una columna que
 * aún no existe. Antes de consumir las colas, comprueba que existen todas las tablas y columnas de
 * sus entidades (`SELECT <columnas> … LIMIT 0`) y, si falta algo o la BD no responde, espera.
 */
@Injectable()
export class SchemaGate {
  private readonly logger = new Logger(SchemaGate.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  /** Lo que falta (`tabla.columna`, o el motivo si la BD no responde), o null si está todo. */
  async missing(): Promise<string | null> {
    for (const meta of this.db.entityMetadatas) {
      const columns = meta.columns.map((c) => `"${c.databaseName}"`).join(', ');
      try {
        await this.db.query(
          `SELECT ${columns} FROM "${meta.tablePath}" LIMIT 0`,
        );
      } catch (error) {
        const code = (error as { code?: string }).code;
        // 42P01: tabla inexistente; 42703: columna inexistente.
        if (code === '42P01' || code === '42703')
          return `${meta.tablePath}: ${(error as Error).message}`;
        return `la base de datos no responde (${(error as Error).name})`;
      }
    }
    return null;
  }

  /** Espera a que el esquema tenga todo lo que usa el worker. */
  async wait(): Promise<void> {
    let warnedAt = 0;
    for (;;) {
      const missing = await this.missing();
      if (!missing) {
        if (warnedAt) this.logger.log('Esquema de la base de datos al día');
        return;
      }
      if (Date.now() - warnedAt >= WARN_EVERY_MS) {
        this.logger.warn(
          `Esperando a que la API aplique las migraciones antes de tomar jobs (${missing})`,
        );
        warnedAt = Date.now();
      }
      await new Promise((done) => setTimeout(done, SCHEMA_RETRY_MS));
    }
  }
}
