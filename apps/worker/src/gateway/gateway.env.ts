import 'reflect-metadata';
import { plainToInstance, Transform } from 'class-transformer';
import {
  IsBoolean,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min,
  validateSync,
} from 'class-validator';
import { resolve } from 'node:path';
import { NODE_ENVS, resolveRedisPassword } from '../config/env.validation.js';

/**
 * Fichero .env del gateway (no el del worker: ese lleva los secretos). Las variables ya
 * definidas no se pisan.
 */
export const GATEWAY_ENV_FILES = [resolve(import.meta.dirname, '../../.env.gateway')];

/**
 * El gateway nunca accede al gestor de secretos (DESIGN §11, §12): pide a la API el certificado
 * de cada sesión. Si le llega alguna de estas variables, no arranca (una configuración copiada
 * del worker le daría acceso a todos los secretos de la app).
 */
export const GATEWAY_FORBIDDEN_ENV =
  /^(SECRETS_[A-Z_]*|OPENBAO_[A-Z_]*|VAULT_[A-Z_]*|TERMINAL_OPENBAO_[A-Z_]*)$/;

function EnvBoolean(defaultValue: boolean) {
  return Transform(({ obj, key }: { obj: Record<string, unknown>; key: string }) => {
    const raw = obj[key];
    if (raw === undefined || raw === '') return defaultValue;
    return typeof raw === 'string' ? raw.trim().toLowerCase() === 'true' : raw;
  });
}

/**
 * Variables del modo `gateway` del worker (sesión 21): Redis (cupos e identidad), la BD (solo
 * lee las rutas de los assets), SSH, la API (canje de tickets y certificados) y los límites de
 * las sesiones. Sin colas ni secretos.
 */
export class GatewayEnvironment {
  @IsIn(NODE_ENVS)
  NODE_ENV: (typeof NODE_ENVS)[number] = 'development';

  @IsString()
  REDIS_HOST: string = 'localhost';

  @IsInt()
  @Min(1)
  @Max(65535)
  REDIS_PORT: number = 6379;

  @IsOptional()
  @IsString()
  REDIS_PASSWORD?: string;

  /** Fichero con la contraseña de Redis (mejor que REDIS_PASSWORD; ver resolveRedisPassword). */
  @IsOptional()
  @IsString()
  REDIS_PASSWORD_FILE?: string;

  @IsInt()
  @Min(0)
  @Max(15)
  REDIS_DB: number = 0;

  @IsString()
  DATABASE_HOST: string = 'localhost';

  @IsInt()
  @Min(1)
  @Max(65535)
  DATABASE_PORT: number = 5432;

  @IsString()
  DATABASE_USER: string;

  @IsString()
  DATABASE_PASSWORD: string;

  @IsString()
  DATABASE_NAME: string;

  /** Directorio de las claves efímeras (tmpfs); por defecto /dev/shm. */
  @IsOptional()
  @IsString()
  WORKER_TMP_DIR?: string;

  @IsInt()
  @Min(1)
  @Max(120)
  SSH_CONNECT_TIMEOUT: number = 15;

  /** Puerto y dirección del WebSocket de la terminal (`/terminal`) y de `/healthz`. */
  @IsInt()
  @Min(1)
  @Max(65535)
  GATEWAY_PORT: number = 3010;

  @IsString()
  GATEWAY_HOST: string = '0.0.0.0';

  /** Nombre fijo de la réplica (si no, `gateway-<n>`). */
  @IsOptional()
  @Matches(/^[A-Za-z0-9._-]{1,64}$/)
  GATEWAY_NAME?: string;

  /** URL de la API para el gateway (red interna; p. ej. `http://api:3000`), sin barra final. */
  @Matches(/^https?:\/\/[A-Za-z0-9.:[\]_-]+(\/[A-Za-z0-9._~/-]*[A-Za-z0-9._~-])?$/)
  GATEWAY_API_URL: string;

  /** Fichero con el secreto compartido con la API (`Authorization: Gateway …`). */
  @IsString()
  GATEWAY_API_SECRET_FILE: string;

  /**
   * Orígenes web admitidos en el WebSocket (separados por comas). Una conexión con otra cabecera
   * `Origin` se rechaza; sin `Origin` (el cliente de línea de órdenes), se admite.
   */
  @IsOptional()
  @IsString()
  WEB_ORIGIN?: string;

  /** Tomar la IP del cliente de `X-Forwarded-For` (solo detrás de un proxy de confianza). */
  @EnvBoolean(false)
  @IsBoolean()
  GATEWAY_TRUST_PROXY: boolean = false;

  /**
   * Parada ordenada: avisa a cada sesión y espera como mucho esto (segundos) antes de cerrarlas.
   * Menor que el `stop_grace_period` del contenedor.
   */
  @IsInt()
  @Min(0)
  @Max(3600)
  GATEWAY_SHUTDOWN_GRACE: number = 60;

  /**
   * Cada cuántos segundos late el gateway a la API con sus sesiones (sesión 22): la API las da por
   * vivas, mantiene la sesión web de quien teclea y devuelve las que hay que cortar. Menor que el
   * `TERMINAL_HEARTBEAT_TIMEOUT` de la API (60 s).
   */
  @IsInt()
  @Min(1)
  @Max(120)
  GATEWAY_HEARTBEAT_INTERVAL: number = 15;

  /** Sesiones interactivas a la vez contra un mismo host raíz (aparte de los jobs). */
  @IsInt()
  @Min(1)
  @Max(64)
  HOST_MAX_TERMINAL_SESSIONS: number = 4;

  /** Sesiones a la vez por persona. */
  @IsInt()
  @Min(1)
  @Max(32)
  TERMINAL_MAX_SESSIONS_PER_USER: number = 3;

  /** Cierre por inactividad (segundos sin datos en ningún sentido). */
  @IsInt()
  @Min(60)
  @Max(86400)
  TERMINAL_IDLE_TIMEOUT: number = 900;

  /** Duración máxima de una sesión (segundos). */
  @IsInt()
  @Min(60)
  @Max(604800)
  TERMINAL_MAX_DURATION: number = 28800;

  // Los lee el semáforo por host compartido con el worker (aquí solo se usa el cupo de terminal).
  @IsInt()
  @Min(1)
  @Max(64)
  HOST_MAX_JOBS: number = 2;

  @IsInt()
  @Min(1)
  @Max(64)
  HOST_MAX_SCAN_JOBS: number = 1;
}

export function validateGatewayEnv(config: Record<string, unknown>): GatewayEnvironment {
  const forbidden = Object.keys(config).filter(
    (k) => GATEWAY_FORBIDDEN_ENV.test(k) && config[k] !== undefined && config[k] !== '',
  );
  if (forbidden.length > 0)
    throw new Error(
      `El gateway no accede al gestor de secretos: quita ${forbidden.sort().join(', ')} de su entorno (pide los certificados a la API)`,
    );
  const env = plainToInstance(GatewayEnvironment, config, { enableImplicitConversion: true });
  const errors = validateSync(env, { skipMissingProperties: false });
  if (errors.length > 0) {
    // Solo nombres de variables y restricciones incumplidas: nunca los valores.
    const detail = errors
      .map((e) => `  - ${e.property}: ${Object.keys(e.constraints ?? {}).join(', ')}`)
      .join('\n');
    throw new Error(`Configuración del gateway inválida:\n${detail}`);
  }
  resolveRedisPassword(env);
  return env;
}

/** Orígenes web admitidos en el WebSocket (vacío: solo clientes sin `Origin`). */
export function gatewayOrigins(env: Pick<GatewayEnvironment, 'WEB_ORIGIN'>): string[] {
  return (env.WEB_ORIGIN ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean)
    .map((o) => new URL(o).origin);
}
