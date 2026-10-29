import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import {
  KNOWN_SECRET_PROVIDERS,
  loadOpenBaoConfig,
  openBaoSourceFromEnv,
  parseSecretRef,
} from '@infraward/secrets';
import { PASSWORD_MIN_LENGTH } from '@infraward/shared-types';
import { plainToInstance, Transform } from 'class-transformer';
import {
  IsBoolean,
  IsEmail,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  IsUrl,
  Matches,
  Max,
  Min,
  MaxLength,
  MinLength,
  validateSync,
} from 'class-validator';
import { parseRoleMapping } from '../auth/oidc/oidc-settings.js';

export const NODE_ENVS = ['development', 'test', 'production'] as const;

/**
 * Booleano del entorno: solo `true` (sin distinguir mayúsculas) es verdadero; sin definir, el
 * valor por defecto. Lee `obj[key]`: con la conversión implícita, `value` ya sería
 * Boolean('false') === true.
 */
function EnvBoolean(defaultValue: boolean) {
  return Transform(
    ({ obj, key }: { obj: Record<string, unknown>; key: string }) => {
      const raw = obj[key];
      if (raw === undefined || raw === '') return defaultValue;
      return typeof raw === 'string'
        ? raw.trim().toLowerCase() === 'true'
        : raw;
    },
  );
}

const URL_OPTIONS = {
  protocols: ['http', 'https'],
  require_protocol: true,
  require_tld: false,
};

/** Variables de entorno de la API. Se validan al arrancar: si algo falla, la API no inicia. */
export class EnvironmentVariables {
  @IsIn(NODE_ENVS)
  NODE_ENV: (typeof NODE_ENVS)[number] = 'development';

  @IsInt()
  @Min(1)
  @Max(65535)
  PORT: number = 3000;

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

  /** Índice de base de datos de Redis (los e2e usan uno propio para no mezclarse con desarrollo). */
  @IsInt()
  @Min(0)
  @Max(15)
  REDIS_DB: number = 0;

  /** Caducidad absoluta de una sesión web, en segundos (por defecto 12 h). */
  @IsInt()
  @Min(300)
  @Max(7 * 24 * 3600)
  SESSION_TTL: number = 12 * 3600;

  /** Caducidad por inactividad de una sesión web, en segundos (por defecto 2 h). */
  @IsInt()
  @Min(60)
  SESSION_IDLE_TTL: number = 2 * 3600;

  /**
   * Cookie de sesión `Secure` con el prefijo `__Host-` (por defecto). Solo se puede desactivar
   * fuera de producción (p. ej. un navegador que no acepte cookies Secure en http://localhost).
   */
  @EnvBoolean(true)
  @IsBoolean()
  SESSION_COOKIE_SECURE: boolean = true;

  /** Validez de una contraseña temporal (alta o restablecimiento), en segundos (por defecto 24 h). */
  @IsInt()
  @Min(300)
  @Max(7 * 24 * 3600)
  TEMP_PASSWORD_TTL: number = 24 * 3600;

  /**
   * Proxies de confianza para la IP real del cliente (X-Forwarded-For): `false` (por defecto),
   * `true` (cualquiera: solo si la API no es accesible directamente) o una lista de IP/CIDR o
   * nombres de proxy-addr (`loopback`, `uniquelocal`) separados por comas.
   *
   * Seguridad: pon la dirección exacta del proxy inverso que hay delante de la API. Con un valor
   * amplio (`true`, `uniquelocal`), cualquier cliente de ese rango puede falsear X-Forwarded-For y
   * saltarse los límites por IP (login, alta). El límite de login por cuenta sigue valiendo.
   */
  @Matches(/^(true|false|[0-9A-Za-z.:/_-]+(, *[0-9A-Za-z.:/_-]+)*)$/)
  TRUST_PROXY: string = 'false';

  /**
   * Orígenes de la web (esquema, host y puerto), separados por comas, con los que se compara la
   * cabecera Origin de las peticiones que modifican datos. Por defecto, el origen de PUBLIC_URL
   * y, en desarrollo, también el de `ng serve` (http://localhost:4200).
   */
  @IsOptional()
  @Matches(/^https?:\/\/[A-Za-z0-9.:[\]_-]+(,https?:\/\/[A-Za-z0-9.:[\]_-]+)*$/)
  WEB_ORIGIN?: string;

  /** Intentos de login permitidos por IP en cada ventana de LOGIN_THROTTLE_TTL. */
  @IsInt()
  @Min(1)
  LOGIN_THROTTLE_LIMIT: number = 5;

  /** Ventana (y bloqueo tras superarla) del límite de login, en segundos. */
  @IsInt()
  @Min(1)
  LOGIN_THROTTLE_TTL: number = 60;

  /**
   * Logins fallidos permitidos por cuenta (email) en cada ventana de LOGIN_ACCOUNT_THROTTLE_TTL,
   * desde cualquier IP. Complementa el límite por IP contra la fuerza bruta repartida entre muchas
   * direcciones. No bloquea las redes desde las que la cuenta ya entró bien (DESIGN §14).
   */
  @IsInt()
  @Min(1)
  LOGIN_ACCOUNT_THROTTLE_LIMIT: number = 10;

  /** Ventana (y bloqueo al llegar al límite) del límite de login por cuenta, en segundos. */
  @IsInt()
  @Min(1)
  LOGIN_ACCOUNT_THROTTLE_TTL: number = 300;

  /**
   * Dónde viven los contadores de los límites de intentos: `redis` (por defecto; los comparten
   * todas las réplicas de la API) o `memory` (por proceso: N réplicas dejan N veces el límite;
   * pensado para los tests).
   */
  @IsIn(['redis', 'memory'])
  THROTTLE_STORAGE: 'redis' | 'memory' = 'redis';

  /**
   * Ventana de la reautenticación reciente (step-up), en segundos (por defecto 10 min): las
   * acciones sensibles exigen haber confirmado la identidad (TOTP o login en el proveedor OIDC)
   * hace menos de esto.
   */
  @IsInt()
  @Min(60)
  @Max(3600)
  REAUTH_MAX_AGE: number = 600;

  /**
   * Caché corta de los datos de cada widget del panel, en segundos (QoL-8; los de tareas en
   * curso, 5 s). 0 la desactiva.
   */
  @IsInt()
  @Min(0)
  @Max(600)
  DASHBOARD_CACHE_TTL: number = 30;

  /** Usuario administrador que se crea al arrancar si no existe ningún usuario. */
  @IsOptional()
  @IsEmail()
  ADMIN_EMAIL?: string;

  @IsOptional()
  @IsString()
  @MinLength(PASSWORD_MIN_LENGTH)
  ADMIN_PASSWORD?: string;

  /**
   * Login local con email y contraseña (DESIGN §14). Con `false` solo entra por contraseña el
   * admin de emergencia (LOCAL_LOGIN_EMERGENCY_EMAIL); exige OIDC configurado.
   */
  @EnvBoolean(true)
  @IsBoolean()
  LOCAL_LOGIN: boolean = true;

  /** Admin local de emergencia: el único que entra con contraseña si LOCAL_LOGIN=false. */
  @IsOptional()
  @IsEmail()
  LOCAL_LOGIN_EMERGENCY_EMAIL?: string;

  /** Issuer del proveedor OIDC (activa el login con OIDC). En producción, https. */
  @IsOptional()
  @IsUrl({
    ...URL_OPTIONS,
    allow_fragments: false,
    allow_query_components: false,
  })
  OIDC_ISSUER?: string;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  OIDC_CLIENT_ID?: string;

  /** Referencia `secret://…` al secreto del cliente (sin ella, cliente público con PKCE). */
  @IsOptional()
  @IsString()
  OIDC_CLIENT_SECRET_REF?: string;

  /** Cómo se autentica el cliente en el token endpoint. */
  @IsIn(['client_secret_basic', 'client_secret_post'])
  OIDC_TOKEN_AUTH_METHOD: 'client_secret_basic' | 'client_secret_post' =
    'client_secret_basic';

  /**
   * URL de retorno registrada en el proveedor: la ruta /api/auth/oidc/callback de la web (la
   * cookie de sesión se pone en el origen de la web). Su origen es también el de la redirección
   * final tras entrar o salir.
   */
  @IsOptional()
  @IsUrl({
    ...URL_OPTIONS,
    allow_fragments: false,
    allow_query_components: false,
  })
  OIDC_REDIRECT_URI?: string;

  /** Nombre del proveedor en el botón «Entrar con …». */
  @IsString()
  @MinLength(1)
  @MaxLength(40)
  OIDC_PROVIDER_NAME: string = 'OIDC';

  /** Scopes pedidos (separados por espacios; tiene que incluir openid). */
  @Matches(/^[\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*$/)
  OIDC_SCOPES: string = 'openid email profile';

  /**
   * Claim con los grupos (string o lista). Primero el nombre literal (p. ej. un claim con URL) y,
   * si no existe, como ruta con puntos (`realm_access.roles`).
   */
  @IsString()
  @MinLength(1)
  OIDC_GROUPS_CLAIM: string = 'groups';

  /** `grupo=rol` separados por comas; con varios grupos gana el rol con más permisos. */
  @IsOptional()
  @IsString()
  OIDC_ROLE_MAPPING?: string;

  /** Sin ningún grupo con rol: acceso denegado (por defecto) o viewer. */
  @IsIn(['deny', 'viewer'])
  OIDC_UNMAPPED: 'deny' | 'viewer' = 'deny';

  /**
   * Alta automática aunque el proveedor no marque el email como verificado. Por defecto no: si
   * el proveedor deja registrarse sin verificar, alguien crearía la cuenta con el email de otra
   * persona y esta quedaría bloqueada (`already_linked`). Solo para proveedores que no mandan
   * `email_verified` y verifican los emails por su cuenta (p. ej. Entra ID). Nunca afecta al
   * enlace con una cuenta local, que siempre exige `email_verified: true`.
   */
  @EnvBoolean(false)
  @IsBoolean()
  OIDC_ALLOW_UNVERIFIED_SIGNUP: boolean = false;

  /** Proveedores de secretos activos, separados por comas (p. ej. `local` u `openbao,local`). */
  @Matches(/^[a-z][a-z0-9-]*(,[a-z][a-z0-9-]*)*$/)
  SECRETS_PROVIDERS: string = 'local';

  /** Clave maestra del proveedor local en base64 (32 bytes). Mejor usar la variante _FILE. */
  @IsOptional()
  @IsString()
  SECRETS_LOCAL_MASTER_KEY?: string;

  /** Fichero con la clave maestra del proveedor local (p. ej. un secret de Podman/Docker). */
  @IsOptional()
  @IsString()
  SECRETS_LOCAL_MASTER_KEY_FILE?: string;

  /** OpenBao (si `openbao` está en SECRETS_PROVIDERS): URL, p. ej. https://bao.example:8200. */
  @IsOptional()
  @IsString()
  OPENBAO_ADDR?: string;

  /** role_id del AppRole de la app (nunca un token root). */
  @IsOptional()
  @IsString()
  OPENBAO_ROLE_ID?: string;

  /** secret_id del AppRole en claro. Mejor usar la variante _FILE. */
  @IsOptional()
  @IsString()
  OPENBAO_SECRET_ID?: string;

  /** Fichero con el secret_id del AppRole (p. ej. un secret de Podman/Docker). */
  @IsOptional()
  @IsString()
  OPENBAO_SECRET_ID_FILE?: string;

  /** Punto de montaje del motor KV v2 (por defecto `secret`). */
  @IsOptional()
  @IsString()
  OPENBAO_KV_MOUNT?: string;

  /** Prefijo dentro del KV para las rutas de las referencias (por defecto `infraward`). */
  @IsOptional()
  @IsString()
  OPENBAO_KV_PREFIX?: string;

  /** Punto de montaje de AppRole (por defecto `approle`). */
  @IsOptional()
  @IsString()
  OPENBAO_APPROLE_MOUNT?: string;

  /** Montaje del motor SSH en modo CA (por defecto `infraward-ssh`). */
  @IsOptional()
  @IsString()
  OPENBAO_SSH_MOUNT?: string;

  /** Rol de firma de certificados SSH (por defecto `inventory`). */
  @IsOptional()
  @IsString()
  OPENBAO_SSH_ROLE?: string;

  /** Tiempo máximo de cada petición a OpenBao, en ms. */
  @IsOptional()
  @IsInt()
  @Min(100)
  @Max(60000)
  OPENBAO_TIMEOUT_MS?: number;

  /**
   * Almacén de la caja fuerte de credenciales (QoL-7): `none` (sin caja fuerte), `local` (tabla
   * `vault_local_secrets` con su propia clave) u `openbao` (prefijo y AppRole propios). Solo lo
   * tiene la API: el worker no declara ninguna variable VAULT_* y no puede leerla.
   */
  @IsIn(['none', 'local', 'openbao'])
  VAULT_PROVIDER: 'none' | 'local' | 'openbao' = 'none';

  /** Versiones del secreto que se conservan por entrada. */
  @IsInt()
  @Min(1)
  @Max(100)
  VAULT_MAX_VERSIONS: number = 10;

  /** Clave de la caja fuerte local en base64 (32 bytes), distinta de SECRETS_LOCAL_MASTER_KEY. */
  @IsOptional()
  @IsString()
  VAULT_LOCAL_MASTER_KEY?: string;

  /** Fichero con la clave de la caja fuerte local (mejor que la variable). */
  @IsOptional()
  @IsString()
  VAULT_LOCAL_MASTER_KEY_FILE?: string;

  /** role_id de la AppRole de la caja fuerte (`infraward-vault`), no la de la app. */
  @IsOptional()
  @IsString()
  VAULT_OPENBAO_ROLE_ID?: string;

  /** secret_id de la AppRole de la caja fuerte. Mejor la variante _FILE. */
  @IsOptional()
  @IsString()
  VAULT_OPENBAO_SECRET_ID?: string;

  @IsOptional()
  @IsString()
  VAULT_OPENBAO_SECRET_ID_FILE?: string;

  /** Prefijo del KV de la caja fuerte (por defecto `infraward-vault`, fuera del de la app). */
  @IsOptional()
  @IsString()
  VAULT_OPENBAO_KV_PREFIX?: string;

  /** Revelados por usuario en cada ventana (además de la reautenticación). */
  @IsInt()
  @Min(1)
  VAULT_REVEAL_THROTTLE_LIMIT: number = 20;

  /** Ventana del límite de revelados, en segundos. */
  @IsInt()
  @Min(1)
  VAULT_REVEAL_THROTTLE_TTL: number = 600;

  /**
   * Terminal (sesión 21, DESIGN §11): role_id de la AppRole `infraward-terminal`, la única que
   * puede firmar con el rol de la terminal. Solo la tiene la API (ni el worker ni el gateway).
   * Sin ella, la terminal no está disponible.
   */
  @IsOptional()
  @IsString()
  TERMINAL_OPENBAO_ROLE_ID?: string;

  /** secret_id de la AppRole de la terminal. Mejor la variante _FILE. */
  @IsOptional()
  @IsString()
  TERMINAL_OPENBAO_SECRET_ID?: string;

  @IsOptional()
  @IsString()
  TERMINAL_OPENBAO_SECRET_ID_FILE?: string;

  /** Rol de firma de la terminal en el motor SSH (por defecto `infraward-operator`). */
  @IsOptional()
  @IsString()
  TERMINAL_OPENBAO_SSH_ROLE?: string;

  /**
   * Vida de los certificados de la terminal, en segundos. sshd solo los comprueba al
   * autenticar: la sesión sigue aunque caduquen.
   */
  @IsInt()
  @Min(30)
  @Max(300)
  TERMINAL_CERT_TTL: number = 120;

  /**
   * Fichero con el secreto compartido con el gateway (lo presenta en `Authorization: Gateway …`
   * en `/internal/gateway/*`). Sin él, esas rutas no existen (404).
   */
  @IsOptional()
  @IsString()
  GATEWAY_API_SECRET_FILE?: string;

  /**
   * Dónde conecta el navegador con el gateway, sin barra final: lo normal es una ruta del mismo
   * origen que la web (`/gateway`: la web hace de proxy y la cookie de la sesión viaja en el
   * upgrade, que el gateway exige) o una URL `ws://`/`wss://`. `POST /terminal/sessions`
   * devuelve `<GATEWAY_PUBLIC_URL>/terminal`.
   */
  @IsOptional()
  @Matches(
    /^(wss?:\/\/[A-Za-z0-9.:[\]_-]+)?(\/[A-Za-z0-9._~/-]*[A-Za-z0-9._~-])?$/,
  )
  @MinLength(2)
  GATEWAY_PUBLIC_URL?: string;

  /**
   * Segundos sin latido del gateway tras los que el barrido da una terminal por perdida
   * (`gateway_lost`; el gateway late cada 15 s).
   */
  @IsInt()
  @Min(5)
  @Max(600)
  TERMINAL_HEARTBEAT_TIMEOUT: number = 60;

  /** Cada cuántos segundos barre la API las terminales sin latido y los tickets caducados. */
  @IsInt()
  @Min(1)
  @Max(300)
  TERMINAL_SWEEP_INTERVAL: number = 30;

  /** Comprobaciones de referencias (POST /secrets/check) por usuario en cada ventana. */
  @IsInt()
  @Min(1)
  SECRETS_CHECK_THROTTLE_LIMIT: number = 30;

  /** Ventana (y bloqueo tras superarla) del límite de POST /secrets/check, en segundos. */
  @IsInt()
  @Min(1)
  SECRETS_CHECK_THROTTLE_TTL: number = 60;

  /**
   * URL con la que los servidores llegan a la API (la usa el script de alta:
   * `curl -fsSL <PUBLIC_URL>/enroll/<token>`). Sin barra final ni query.
   */
  @IsUrl({
    protocols: ['http', 'https'],
    require_protocol: true,
    require_tld: false,
    allow_query_components: false,
    allow_fragments: false,
  })
  @Matches(/^https?:\/\/[A-Za-z0-9.:[\]_-]+(\/[A-Za-z0-9._~/-]*)?$/)
  PUBLIC_URL: string;

  /** Validez del token de enrolamiento en segundos (DESIGN §7: 15–30 minutos). */
  @IsInt()
  @Min(900)
  @Max(1800)
  ENROLLMENT_TOKEN_TTL: number = 1200;

  /** Peticiones a /enroll/* (públicas) por IP en cada ventana de ENROLL_THROTTLE_TTL. */
  @IsInt()
  @Min(1)
  ENROLL_THROTTLE_LIMIT: number = 20;

  /** Ventana (y bloqueo tras superarla) del límite de /enroll/*, en segundos. */
  @IsInt()
  @Min(1)
  ENROLL_THROTTLE_TTL: number = 60;

  /** Plantilla del script de alta (por defecto, ansible/enroll/enroll.sh.tmpl del repositorio). */
  @IsOptional()
  @IsString()
  ENROLL_SCRIPT_TEMPLATE?: string;

  /** Vida de la caché de secretos en memoria, en segundos (0 = sin caché). */
  @IsInt()
  @Min(0)
  @Max(300)
  SECRETS_CACHE_TTL: number = 60;

  /**
   * Servir sin autenticación la referencia de la API (`/docs`) y el documento OpenAPI
   * (`/openapi.json`): `true` o `false`. Sin definir: activos fuera de producción y apagados en
   * producción (ver `docsPublic`). Cualquier otro valor es un error, para que la validación y
   * `docsPublic` nunca discrepen.
   */
  @Transform(({ obj, key }: { obj: Record<string, unknown>; key: string }) => {
    const raw = obj[key];
    if (raw === undefined || raw === '') return undefined;
    if (typeof raw !== 'string') return raw;
    const value = raw.trim().toLowerCase();
    return value === 'true' ? true : value === 'false' ? false : raw;
  })
  @IsOptional()
  @IsBoolean()
  DOCS_PUBLIC?: boolean;
}

/** Lista de proveedores de secretos activos. */
export function secretsProviders(value: string): string[] {
  return value.split(',');
}

/** Variables opcionales en las que vacío = sin definir (los e2e las vacían para no heredar el .env). */
const EMPTY_IS_UNSET =
  /^(OIDC_[A-Z_]+|LOCAL_LOGIN_EMERGENCY_EMAIL|VAULT_[A-Z_]+|TERMINAL_OPENBAO_[A-Z_]+|GATEWAY_[A-Z_]+)$/;

export function validateEnv(
  raw: Record<string, unknown>,
): EnvironmentVariables {
  const config = Object.fromEntries(
    Object.entries(raw).filter(
      ([k, v]) => !(v === '' && EMPTY_IS_UNSET.test(k)),
    ),
  );
  const env = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });
  const errors = validateSync(env, { skipMissingProperties: false });
  if (errors.length > 0) {
    // Solo nombres de variables y restricciones incumplidas: nunca los valores.
    const detail = errors
      .map(
        (e) =>
          `  - ${e.property}: ${Object.keys(e.constraints ?? {}).join(', ')}`,
      )
      .join('\n');
    throw new Error(`Configuración de entorno inválida:\n${detail}`);
  }
  resolveRedisPassword(env);
  if (!env.SESSION_COOKIE_SECURE && env.NODE_ENV === 'production') {
    throw new Error(
      'Configuración de entorno inválida: SESSION_COOKIE_SECURE=false no se admite en producción',
    );
  }
  if (env.NODE_ENV === 'production' && !isHttpsOrLoopback(env.PUBLIC_URL)) {
    // El script de alta se descarga con `curl <PUBLIC_URL>/enroll/<token> | sudo bash`: por http,
    // un MITM podría reescribirlo (root en el servidor) o robar el token.
    throw new Error(
      'Configuración de entorno inválida: PUBLIC_URL tiene que ser https en producción (salvo localhost)',
    );
  }
  if ((env.ADMIN_EMAIL === undefined) !== (env.ADMIN_PASSWORD === undefined)) {
    throw new Error(
      'Configuración de entorno inválida: ADMIN_EMAIL y ADMIN_PASSWORD van juntas',
    );
  }
  validateOidc(env);
  const providers = secretsProviders(env.SECRETS_PROVIDERS);
  const unknown = providers.filter((p) => !KNOWN_SECRET_PROVIDERS.includes(p));
  if (unknown.length > 0) {
    throw new Error(
      `Configuración de entorno inválida: SECRETS_PROVIDERS con proveedores desconocidos (${unknown.join(', ')}); disponibles: ${KNOWN_SECRET_PROVIDERS.join(', ')}`,
    );
  }
  if (providers.includes('local')) {
    const hasKey = Boolean(env.SECRETS_LOCAL_MASTER_KEY);
    const hasFile = Boolean(env.SECRETS_LOCAL_MASTER_KEY_FILE);
    if (hasKey === hasFile) {
      throw new Error(
        `Configuración de entorno inválida: el proveedor de secretos local necesita exactamente una de SECRETS_LOCAL_MASTER_KEY o SECRETS_LOCAL_MASTER_KEY_FILE (${hasKey ? 'están las dos' : 'falta'})`,
      );
    }
  }
  if (providers.includes('openbao')) {
    try {
      loadOpenBaoConfig(
        openBaoSourceFromEnv(
          (name) =>
            env[name as keyof EnvironmentVariables] as string | undefined,
        ),
      );
    } catch (e) {
      throw new Error(
        `Configuración de entorno inválida: ${(e as Error).message}`,
        { cause: e },
      );
    }
  }
  return env;
}

function validateOidc(env: EnvironmentVariables): void {
  const fail = (message: string): never => {
    throw new Error(`Configuración de entorno inválida: ${message}`);
  };
  if (!env.OIDC_ISSUER) {
    if (!env.LOCAL_LOGIN)
      fail('LOCAL_LOGIN=false exige un proveedor OIDC (OIDC_ISSUER)');
    return;
  }
  if (!env.OIDC_CLIENT_ID) fail('OIDC_ISSUER exige OIDC_CLIENT_ID');
  if (!env.OIDC_REDIRECT_URI) fail('OIDC_ISSUER exige OIDC_REDIRECT_URI');
  if (env.NODE_ENV === 'production') {
    for (const name of ['OIDC_ISSUER', 'OIDC_REDIRECT_URI'] as const)
      if (!env[name]!.startsWith('https://'))
        fail(`${name} tiene que ser https en producción`);
  }
  if (!env.OIDC_SCOPES.split(' ').includes('openid'))
    fail('OIDC_SCOPES tiene que incluir openid');
  if (env.OIDC_CLIENT_SECRET_REF) {
    try {
      const ref = parseSecretRef(env.OIDC_CLIENT_SECRET_REF);
      if (!ref.field) throw new Error('falta el #campo');
    } catch (e) {
      fail(
        `OIDC_CLIENT_SECRET_REF no es una referencia válida (${(e as Error).message})`,
      );
    }
  }
  try {
    parseRoleMapping(env.OIDC_ROLE_MAPPING);
  } catch (e) {
    fail(`OIDC_ROLE_MAPPING: ${(e as Error).message}`);
  }
}

/** Si `url` usa https o apunta a loopback (localhost, 127.0.0.0/8, ::1). */
export function isHttpsOrLoopback(url: string): boolean {
  const parsed = new URL(url);
  if (parsed.protocol === 'https:') return true;
  const host = parsed.hostname.toLowerCase();
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '[::1]' ||
    /^127(\.\d{1,3}){3}$/.test(host)
  );
}

/**
 * Si se sirven `/docs` y `/openapi.json`: DOCS_PUBLIC si está definida (`true`/`false`) y, si no,
 * solo fuera de producción. Lee el entorno en bruto porque la documentación se monta antes de que
 * Nest valide la configuración (que rechaza cualquier otro valor).
 */
export function docsPublic(raw: {
  DOCS_PUBLIC?: string;
  NODE_ENV?: string;
}): boolean {
  const value = raw.DOCS_PUBLIC?.trim().toLowerCase();
  if (value === 'true') return true;
  if (value === 'false') return false;
  return raw.NODE_ENV !== 'production';
}

/** Valor de `trustProxy` de Fastify a partir de TRUST_PROXY. */
export function trustProxySetting(value: string): boolean | string[] {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value.split(',').map((v) => v.trim());
}

/** Orígenes permitidos de la web (WEB_ORIGIN o el de PUBLIC_URL, más `ng serve` en desarrollo). */
export function webOrigins(
  env: Pick<EnvironmentVariables, 'WEB_ORIGIN' | 'PUBLIC_URL' | 'NODE_ENV'>,
): string[] {
  if (env.WEB_ORIGIN)
    return env.WEB_ORIGIN.split(',').map((o) => new URL(o).origin);
  const origins = [new URL(env.PUBLIC_URL).origin];
  if (env.NODE_ENV === 'development') origins.push('http://localhost:4200');
  return origins;
}

/**
 * REDIS_PASSWORD_FILE: la contraseña de Redis desde un fichero (p. ej. un secreto de compose en
 * /run/secrets) en vez de la variable REDIS_PASSWORD, que se ve en `docker inspect` y en el
 * entorno de cada proceso. Excluyentes. El valor queda en REDIS_PASSWORD de la config ya
 * validada, así que quien abre conexiones no cambia. Los errores nombran la variable, nunca el valor.
 */
export function resolveRedisPassword(env: {
  REDIS_PASSWORD?: string;
  REDIS_PASSWORD_FILE?: string;
}): void {
  const file = env.REDIS_PASSWORD_FILE;
  if (!file) return;
  if (env.REDIS_PASSWORD)
    throw new Error(
      'Configuración de entorno inválida: REDIS_PASSWORD y REDIS_PASSWORD_FILE son excluyentes',
    );
  let value: string;
  try {
    value = readFileSync(file, 'utf8').trim();
  } catch (error) {
    throw new Error(
      `Configuración de entorno inválida: REDIS_PASSWORD_FILE: no se puede leer el fichero (${(error as NodeJS.ErrnoException).code ?? 'error'})`,
      { cause: error },
    );
  }
  if (!value)
    throw new Error('Configuración de entorno inválida: REDIS_PASSWORD_FILE está vacío');
  env.REDIS_PASSWORD = value;
}
