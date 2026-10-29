import { resolve } from 'node:path';

/** Ficheros .env del worker, por orden de prioridad (las variables ya definidas no se pisan). */
export const ENV_FILES = [resolve(import.meta.dirname, '../../.env')];
