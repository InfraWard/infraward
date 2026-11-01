/**
 * Guarda un secreto en un proveedor con escritura (local u OpenBao) y nada más:
 *
 *   printf '{"client_secret":"…"}' | pnpm --filter @infraward/api secrets:put secret://local/oidc/keycloak
 *
 * Los campos llegan en JSON por la entrada estándar (nunca en argv: se vería en `ps` y en el
 * historial) y no se imprimen. Usa la configuración de la API (apps/api/.env) y su BD.
 */
import { Logger, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { parseSecretRef, SecretsService } from '@infraward/secrets';
import { ENV_FILES } from '../config/env-files.js';
import { validateEnv } from '../config/env.validation.js';
import { DatabaseModule } from '../database/database.module.js';
import { apiSecretsModule } from '../secrets/secrets-api.module.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ENV_FILES,
      validate: validateEnv,
    }),
    DatabaseModule,
    apiSecretsModule,
  ],
})
class SecretPutModule {}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function parseFields(raw: string): Record<string, string> {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error('La entrada estándar no es JSON');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data))
    throw new Error(
      'La entrada tiene que ser un objeto JSON {"campo":"valor"}',
    );
  const entries = Object.entries(data);
  if (
    entries.length === 0 ||
    entries.some(([, v]) => typeof v !== 'string' || !v)
  )
    throw new Error('Cada campo tiene que ser un texto no vacío');
  return Object.fromEntries(entries) as Record<string, string>;
}

async function main(): Promise<void> {
  const ref = process.argv[2];
  if (!ref || process.argv.length > 3)
    throw new Error(
      'Uso: secrets:put secret://<proveedor>/<ruta>  (campos en JSON por stdin)',
    );
  const parsed = parseSecretRef(ref);
  if (parsed.field !== undefined)
    throw new Error(
      'La referencia para guardar no lleva #campo (los campos van en el JSON)',
    );
  if (process.stdin.isTTY)
    throw new Error(
      'Pasa los campos por la entrada estándar (p. ej. con printf … |)',
    );
  const fields = parseFields(await readStdin());

  const app = await NestFactory.createApplicationContext(SecretPutModule, {
    logger: ['error', 'warn'],
  });
  try {
    const stored = await app.get(SecretsService).store(ref, fields);
    const names = Object.keys(fields).join(', ');
    Logger.log(`Guardado en ${stored} (campos: ${names})`, 'secrets:put');
  } finally {
    await app.close();
  }
}

try {
  await main();
} catch (error: unknown) {
  // Solo el mensaje: nunca la entrada.
  Logger.error((error as Error).message, undefined, 'secrets:put');
  process.exitCode = 1;
}
