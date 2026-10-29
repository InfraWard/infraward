import { DOMAIN_ENTITIES } from '@infraward/domain';
import { SECRETS_ENTITIES, VAULT_ENTITIES } from '@infraward/secrets';
import type { DataSourceOptions } from 'typeorm';
import { AuditEvent } from '../audit/audit-event.entity.js';
import { ApiToken } from '../auth/api-token.entity.js';
import { UserRecoveryCode } from '../auth/mfa/recovery-code.entity.js';
import { UserSession } from '../auth/user-session.entity.js';
import { Dashboard } from '../dashboard/dashboard.entity.js';
import { AccessPolicy } from '../access/access-policy.entity.js';
import { TerminalSession } from '../terminal/terminal-session.entity.js';
import { User } from '../users/user.entity.js';
import { VAULT_API_ENTITIES } from '../vault/vault-entry.entity.js';
import { migrations } from './migrations/index.js';

export interface DatabaseConnection {
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
}

/**
 * Opciones comunes de TypeORM para la API y para el CLI de migraciones.
 * El esquema solo cambia mediante migraciones (nunca `synchronize`).
 */
export function databaseOptions(
  connection: DatabaseConnection,
): DataSourceOptions {
  return {
    type: 'postgres',
    ...connection,
    entities: [User, UserSession, ApiToken, UserRecoveryCode, AuditEvent, Dashboard, TerminalSession, AccessPolicy, ...DOMAIN_ENTITIES, ...SECRETS_ENTITIES, ...VAULT_ENTITIES, ...VAULT_API_ENTITIES],
    migrations,
    synchronize: false,
    // gen_random_uuid() es nativo desde PostgreSQL 13: no hace falta instalar extensiones.
    uuidExtension: 'pgcrypto',
    installExtensions: false,
    // Sin JIT: las consultas de la API son cortas y su coste estimado (las listas agrupadas de
    // findings) lo dispara; compilar costaba más que ejecutar (de 15 ms a 157 ms en Vulnerabilidades).
    extra: { options: '-c jit=off' },
    migrationsTableName: 'migrations',
    // 'schema' incluye el resumen de migraciones (pendientes y ejecutadas).
    logging: ['error', 'warn', 'migration', 'schema'],
  };
}
