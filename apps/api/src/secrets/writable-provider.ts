import { ConflictException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { SecretsService } from '@infraward/secrets';
import {
  secretsProviders,
  type EnvironmentVariables,
} from '../config/env.validation.js';

/** Primer proveedor activo que admite escritura (SECRETS_PROVIDERS, por orden); si no hay, 409. */
export function writableSecretsProvider(
  secrets: SecretsService,
  config: ConfigService<EnvironmentVariables, true>,
): string {
  const id = secretsProviders(
    config.get('SECRETS_PROVIDERS', { infer: true }),
  ).find((p) => secrets.provider(p).set);
  if (!id)
    throw new ConflictException(
      'Ningún proveedor de secretos activo admite escritura',
    );
  return id;
}
