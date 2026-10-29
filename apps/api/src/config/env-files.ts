import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

/** Ficheros .env de la API, por orden de prioridad (las variables ya definidas no se pisan). */
export const ENV_FILES = [resolve(import.meta.dirname, '../../.env')];

/** Carga los .env en process.env para usos fuera de Nest (CLI de TypeORM). */
export function loadEnvFiles(): void {
  for (const file of ENV_FILES) {
    if (existsSync(file)) process.loadEnvFile(file);
  }
}
