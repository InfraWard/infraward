import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import {
  KNOWN_SECRET_PROVIDERS,
  loadOpenBaoConfig,
  openBaoSourceFromEnv,
} from '@infraward/secrets';
import { QUEUE_NAMES, type QueueName } from '@infraward/shared-types';
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

/** Opcional vacía (`VAR=` o `${VAR:-}` en compose) = sin definir. */
function EmptyAsUndefined() {
  return Transform(({ value }: { value: unknown }) => (value === '' ? undefined : value));
}

/** Variables de entorno del worker. Se validan al arrancar: si algo falla, el worker no inicia. */
export class EnvironmentVariables {
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

  /** Índice de base de datos de Redis (los e2e usan uno propio para no mezclarse con desarrollo). */
  @IsInt()
  @Min(0)
  @Max(15)
  REDIS_DB: number = 0;

  // Paralelismo y réplicas (DESIGN §20). Concurrencia de cada cola en esta réplica; 0 = esta
  // réplica no la consume (workers especializados).

  /** Colas `system` (consultas, KEV/EPSS, prioridad, métricas) y `enrollment` (verificación del alta). */
  @IsInt()
  @Min(0)
  @Max(100)
  WORKER_CONCURRENCY: number = 5;

  /** Recolecciones (`asset.collect`) a la vez. */
  @IsInt()
  @Min(0)
  @Max(100)
  COLLECT_CONCURRENCY: number = 4;

  /** Descubrimientos (`asset.discover`) a la vez. */
  @IsInt()
  @Min(0)
  @Max(100)
  DISCOVERY_CONCURRENCY: number = 2;

  /** Sincronizaciones de dominios, pruebas de conectores y caminos de servicios a la vez. */
  @IsInt()
  @Min(0)
  @Max(100)
  DOMAINS_SYNC_CONCURRENCY: number = 2;

  /**
   * Envíos de alertas (`alert.deliver`, `alert.test`) a la vez: cola propia, para que un webhook
   * lento no espere tras KEV/EPSS o la prioridad (cola `system`) ni las retrase.
   */
  @IsInt()
  @Min(0)
  @Max(50)
  ALERTS_CONCURRENCY: number = 2;

  /** Comprobaciones de la reconciliación (`inventory.reconcile`) a la vez. */
  @IsInt()
  @Min(0)
  @Max(16)
  RECONCILE_CONCURRENCY: number = 1;

  /** Escaneos de imágenes (`image.scan`) a la vez. Sin ella, la antigua SCAN_CONCURRENCY. */
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(16)
  IMAGE_SCAN_CONCURRENCY?: number;

  /** SBOMs de servidores y CT (`host.scan`) a la vez. */
  @IsInt()
  @Min(0)
  @Max(16)
  HOST_SCAN_CONCURRENCY: number = 1;

  /** Re-evaluaciones de SBOMs (`sbom.reevaluate`) a la vez. */
  @IsInt()
  @Min(0)
  @Max(4)
  SBOM_CONCURRENCY: number = 1;

  /**
   * Jobs a la vez contra un mismo host raíz (el servidor al que se conecta por SSH; los CT
   * cuentan contra su nodo), sumando todas las réplicas.
   */
  @IsInt()
  @Min(1)
  @Max(64)
  HOST_MAX_JOBS: number = 2;

  /** De ellos, escaneos y rellenos de SBOMs (prioridad baja). No mayor que HOST_MAX_JOBS. */
  @IsInt()
  @Min(1)
  @Max(64)
  HOST_MAX_SCAN_JOBS: number = 1;

  /**
   * Nombre de la réplica en la Actividad. Sin él, `worker-<n>`: el menor número libre, reservado
   * en Redis (una réplica que reinicia recupera el suyo).
   */
  @IsOptional()
  @Matches(/^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/)
  WORKER_NAME?: string;

  /** Puede ser líder (jobs periódicos, Actividad, huérfanos). Los workers remotos, no. */
  @EnvBoolean(true)
  @IsBoolean()
  WORKER_LEADER_ELIGIBLE: boolean = true;

  /**
   * Segundos que se espera a los jobs en curso al parar; después se abortan y vuelven a la cola.
   * Menor que el `stop_grace_period` del contenedor (120 s en el compose de ejemplo).
   */
  @IsInt()
  @Min(1)
  @Max(3600)
  WORKER_SHUTDOWN_GRACE: number = 90;

  /** Días que se conserva el historial de ejecuciones (`job_runs`, la Actividad). */
  @IsInt()
  @Min(1)
  @Max(3650)
  JOB_RUNS_RETENTION_DAYS: number = 30;

  /**
   * Días que se conserva el log de cada ejecución (pasos, comandos, stderr y resultado; DESIGN
   * §20, «Log de cada ejecución»). Como mucho lo que dure su fila de `job_runs`: al podarse el
   * historial, su log se va con él.
   */
  @IsInt()
  @Min(1)
  @Max(3650)
  COLLECTION_LOG_RETENTION_DAYS: number = 30;

  /** Tope del log de una ejecución (KiB); al llegar se descartan las líneas siguientes. */
  @IsInt()
  @Min(32)
  @Max(4096)
  COLLECTION_LOG_MAX_KB: number = 256;

  // Base de datos: el worker lee y actualiza el inventario (las migraciones las aplica la API).
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

  /** Proveedores de secretos activos (los mismos que en la API). */
  @Matches(/^[a-z][a-z0-9-]*(,[a-z][a-z0-9-]*)*$/)
  SECRETS_PROVIDERS: string = 'local';

  /** Clave maestra del proveedor local en base64 (32 bytes). Mejor usar la variante _FILE. */
  @IsOptional()
  @IsString()
  SECRETS_LOCAL_MASTER_KEY?: string;

  /** Fichero con la clave maestra del proveedor local (la misma que usa la API). */
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

  /** Vida de la caché de secretos en memoria, en segundos (0 = sin caché). */
  @IsInt()
  @Min(0)
  @Max(300)
  SECRETS_CACHE_TTL: number = 30;

  /**
   * Directorio para los ficheros temporales con secretos (claves SSH). Debe ser tmpfs para que
   * nunca toquen disco; por defecto /dev/shm si existe.
   */
  @IsOptional()
  @IsString()
  WORKER_TMP_DIR?: string;

  /** Tiempo máximo de conexión SSH (y de ssh-keyscan), en segundos. */
  @IsInt()
  @Min(1)
  @Max(120)
  SSH_CONNECT_TIMEOUT: number = 15;

  /** Vida de los certificados SSH de la CA (modo CA), en segundos: pocos minutos. */
  @IsInt()
  @Min(60)
  @Max(1800)
  SSH_CERT_TTL: number = 300;

  /**
   * Antes de abrir una conexión, si al certificado le quedan menos de estos segundos se firma
   * otro. Menor que SSH_CERT_TTL.
   */
  @IsInt()
  @Min(10)
  @Max(1799)
  SSH_CERT_RENEW_MARGIN: number = 60;

  /** Ejecutable de `ansible-playbook` (en el PATH o ruta absoluta). */
  @IsString()
  ANSIBLE_PLAYBOOK_BIN: string = 'ansible-playbook';

  /** Directorio `ansible/` del repositorio (playbooks); por defecto, el del propio monorepo. */
  @IsOptional()
  @IsString()
  ANSIBLE_DIR?: string;

  /** Tiempo máximo de una recolección con Ansible, en segundos. */
  @IsInt()
  @Min(30)
  @Max(3600)
  COLLECT_TIMEOUT: number = 600;

  // Escaneo de imágenes con Trivy (DESIGN §9).

  /** Ejecutable de `trivy` (en el PATH o ruta absoluta). */
  @IsString()
  TRIVY_BIN: string = 'trivy';

  /**
   * Caché compartida de las bases de datos de Trivy (vulnerabilidades y Java, ~3 GB) para todos
   * los escaneos del worker. Por defecto `~/.cache/infraward/trivy`.
   */
  @IsOptional()
  @IsString()
  TRIVY_CACHE_DIR?: string;

  /** Horas tras las que se vuelven a descargar las bases de datos de Trivy. */
  @IsInt()
  @Min(1)
  @Max(168)
  TRIVY_DB_MAX_AGE: number = 12;

  /** Tiempo máximo de un escaneo (descarga de la imagen + Trivy), en segundos. */
  @IsInt()
  @Min(30)
  @Max(7200)
  TRIVY_SCAN_TIMEOUT: number = 900;

  /** Tamaño máximo de una imagen a escanear, en bytes (4 GiB por defecto). */
  @IsInt()
  @Min(1024 * 1024)
  TRIVY_MAX_IMAGE_SIZE: number = 4 * 1024 ** 3;

  /** Obsoleta (antes de la sesión W-0): IMAGE_SCAN_CONCURRENCY si no está. */
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(16)
  SCAN_CONCURRENCY?: number;

  /**
   * Directorio de trabajo de los escaneos (las imágenes se descargan aquí). En disco, no tmpfs:
   * una imagen puede ocupar más de un GB. Por defecto `<tmp del sistema>/infraward-scan`.
   */
  @IsOptional()
  @IsString()
  WORKER_SCAN_DIR?: string;

  // SBOMs (DESIGN §9).

  /**
   * Horas entre re-evaluaciones de los SBOMs guardados con `trivy sbom` (sin conectarse a las
   * máquinas). 0 = desactivada.
   */
  @IsInt()
  @Min(0)
  @Max(720)
  SBOM_REEVALUATE_INTERVAL: number = 24;

  /**
   * Bytes máximos de las BDs de paquetes que se copian de un servidor o CT para su SBOM
   * (256 MiB por defecto; una rpmdb grande ronda decenas de MB).
   */
  @IsInt()
  @Min(1024 * 1024)
  HOST_SBOM_MAX_SIZE: number = 256 * 1024 ** 2;

  // Priorización (DESIGN §9, sesión 19): CISA KEV y EPSS de FIRST.

  /** Horas entre descargas de KEV y EPSS (con caché HTTP: sin cambios no se descarga). 0 = nunca. */
  @IsInt()
  @Min(0)
  @Max(720)
  VULN_INTEL_INTERVAL: number = 12;

  // Gráficos de evolución del panel (QoL-8, DESIGN §15).

  /** Horas entre muestras de métricas (una por día basta; se repite sin duplicar). 0 = nunca. */
  @IsInt()
  @Min(0)
  @Max(168)
  METRICS_SAMPLE_INTERVAL: number = 24;

  /** Días que se guardan las muestras diarias; después queda una por semana. */
  @IsInt()
  @Min(7)
  @Max(3650)
  METRICS_DAILY_RETENTION_DAYS: number = 365;

  /** Días que se guardan las muestras semanales. 0 = sin límite. */
  @IsInt()
  @Min(0)
  @Max(36500)
  METRICS_RETENTION_DAYS: number = 0;

  /** Catálogo KEV de CISA (JSON). Vacío = sin KEV (entorno sin salida a Internet). */
  @Matches(/^(https?:\/\/[^\s]+)?$/)
  KEV_URL: string =
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

  /** Puntuaciones EPSS del día (CSV con gzip). Vacío = sin EPSS. */
  @Matches(/^(https?:\/\/[^\s]+)?$/)
  EPSS_URL: string =
    'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';

  /** Milisegundos máximos de cada descarga de KEV o EPSS. */
  @IsInt()
  @Min(1000)
  @Max(600_000)
  VULN_INTEL_TIMEOUT_MS: number = 120_000;

  // Reconciliación (DESIGN §10). El intervalo de cada nodo raíz sale de su política de inventario.

  /**
   * Segundos entre comprobaciones de qué nodos raíz toca reconciliar (0 = reconciliación
   * periódica apagada; la manual sigue).
   */
  @IsInt()
  @Min(0)
  @Max(86_400)
  RECONCILE_TICK: number = 300;

  /**
   * Descubrimientos completos de su ámbito sin ver un asset `missing` tras los que pasa a
   * `retired` (contando el que lo marcó como desaparecido).
   */
  @IsInt()
  @Min(1)
  @Max(1000)
  RECONCILE_RETIRE_AFTER: number = 3;

  // Inventario de dominios (DESIGN §13).

  /** API de Cloudflare (los e2e la apuntan a un simulado). */
  @Matches(/^https?:\/\/[^\s]+$/)
  CLOUDFLARE_API_URL: string = 'https://api.cloudflare.com/client/v4';

  /** Bootstrap de RDAP de IANA (qué servidor sirve cada TLD). */
  @Matches(/^https?:\/\/[^\s]+$/)
  RDAP_BOOTSTRAP_URL: string = 'https://data.iana.org/rdap/dns.json';

  /** Milisegundos máximos de cada petición a la API del proveedor o a RDAP. */
  @IsInt()
  @Min(1000)
  @Max(120_000)
  DOMAINS_HTTP_TIMEOUT_MS: number = 15_000;

  /** Milisegundos máximos de cada lectura del certificado en el 443. */
  @IsInt()
  @Min(200)
  @Max(60_000)
  DOMAINS_TLS_TIMEOUT_MS: number = 5000;

  /** Puerto en el que se lee el certificado (443; los e2e usan otro). */
  @IsInt()
  @Min(1)
  @Max(65_535)
  DOMAINS_TLS_PORT: number = 443;

  /** Lecturas del 443 y resoluciones DNS a la vez. */
  @IsInt()
  @Min(1)
  @Max(64)
  DOMAINS_CONCURRENCY: number = 8;

  /**
   * Servidores DNS para comprobar los CNAME y resolver los nombres del 443
   * (`ip[:puerto]`, separados por comas). Sin ella, los del sistema.
   */
  @IsOptional()
  @Matches(/^[0-9a-fA-F.:[\]]+(,[0-9a-fA-F.:[\]]+)*$/)
  DOMAINS_DNS_SERVERS?: string;

  // Alertas fuera de la app (DESIGN §10): webhooks y correo.

  /** URL de la web (`https://infraward.example`): los enlaces de las alertas. Sin ella, sin enlaces. */
  @EmptyAsUndefined()
  @IsOptional()
  @Matches(/^https?:\/\/[^\s]+$/)
  ALERTS_PUBLIC_URL?: string;

  /** Webhooks por `http:` (por defecto solo `https:`). */
  @EnvBoolean(false)
  @IsBoolean()
  ALERTS_WEBHOOK_ALLOW_HTTP: boolean = false;

  /**
   * Webhooks a IPs privadas (RFC 1918, CGNAT, ULA), p. ej. un ntfy o n8n de casa. Loopback, enlace
   * local y metadatos de la nube, nunca.
   */
  @EnvBoolean(false)
  @IsBoolean()
  ALERTS_WEBHOOK_ALLOW_PRIVATE: boolean = false;

  /** Milisegundos máximos de cada envío (webhook o correo). */
  @IsInt()
  @Min(1000)
  @Max(120_000)
  ALERTS_TIMEOUT_MS: number = 10_000;

  /** Servidor SMTP de las alertas por correo. Sin él, los canales de correo no envían. */
  @EmptyAsUndefined()
  @IsOptional()
  @IsString()
  SMTP_HOST?: string;

  @IsInt()
  @Min(1)
  @Max(65_535)
  SMTP_PORT: number = 587;

  /** TLS desde el principio (465). Si no, STARTTLS obligatorio (salvo SMTP_REQUIRE_TLS=false). */
  @EnvBoolean(false)
  @IsBoolean()
  SMTP_SECURE: boolean = false;

  /** Exigir STARTTLS cuando SMTP_SECURE=false (solo un relay local sin TLS lo desactiva). */
  @EnvBoolean(true)
  @IsBoolean()
  SMTP_REQUIRE_TLS: boolean = true;

  @EmptyAsUndefined()
  @IsOptional()
  @IsString()
  SMTP_USER?: string;

  /** Contraseña SMTP como referencia `secret://<proveedor>/<ruta>#<campo>` (nunca en claro). */
  @EmptyAsUndefined()
  @IsOptional()
  @Matches(/^secret:\/\/[^\s]+#[^\s]+$/)
  SMTP_PASSWORD_REF?: string;

  /** Remitente (`InfraWard <alertas@example.com>`). */
  @EmptyAsUndefined()
  @IsOptional()
  @IsString()
  SMTP_FROM?: string;
}

/** Concurrencia de cada cola en esta réplica (0 = no la consume), DESIGN §20. */
export function queueConcurrency(
  env: Pick<
    EnvironmentVariables,
    | 'WORKER_CONCURRENCY'
    | 'COLLECT_CONCURRENCY'
    | 'DISCOVERY_CONCURRENCY'
    | 'DOMAINS_SYNC_CONCURRENCY'
    | 'RECONCILE_CONCURRENCY'
    | 'IMAGE_SCAN_CONCURRENCY'
    | 'SCAN_CONCURRENCY'
    | 'HOST_SCAN_CONCURRENCY'
    | 'SBOM_CONCURRENCY'
    | 'ALERTS_CONCURRENCY'
  >,
): Record<QueueName, number> {
  const imageScan = env.IMAGE_SCAN_CONCURRENCY ?? env.SCAN_CONCURRENCY ?? 1;
  return {
    [QUEUE_NAMES.system]: env.WORKER_CONCURRENCY,
    [QUEUE_NAMES.enrollment]: env.WORKER_CONCURRENCY,
    [QUEUE_NAMES.collect]: env.COLLECT_CONCURRENCY,
    [QUEUE_NAMES.discovery]: env.DISCOVERY_CONCURRENCY,
    [QUEUE_NAMES.domains]: env.DOMAINS_SYNC_CONCURRENCY,
    [QUEUE_NAMES.reconcile]: env.RECONCILE_CONCURRENCY,
    [QUEUE_NAMES.imageScan]: imageScan,
    [QUEUE_NAMES.hostScan]: env.HOST_SCAN_CONCURRENCY,
    [QUEUE_NAMES.sbom]: env.SBOM_CONCURRENCY,
    [QUEUE_NAMES.alerts]: env.ALERTS_CONCURRENCY,
    // Cola anterior a W-0: solo se drena lo que quedara en ella al actualizar.
    [QUEUE_NAMES.scan]: Math.min(
      1,
      imageScan + env.HOST_SCAN_CONCURRENCY + env.SBOM_CONCURRENCY,
    ),
  };
}

/** Lista de proveedores de secretos activos. */
export function secretsProviders(value: string): string[] {
  return value.split(',');
}

export function validateEnv(
  config: Record<string, unknown>,
): EnvironmentVariables {
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
  if (env.SSH_CERT_RENEW_MARGIN >= env.SSH_CERT_TTL) {
    throw new Error(
      'Configuración de entorno inválida: SSH_CERT_RENEW_MARGIN debe ser menor que SSH_CERT_TTL',
    );
  }
  if (env.HOST_MAX_SCAN_JOBS > env.HOST_MAX_JOBS) {
    throw new Error(
      'Configuración de entorno inválida: HOST_MAX_SCAN_JOBS no puede ser mayor que HOST_MAX_JOBS',
    );
  }
  if (Object.values(queueConcurrency(env)).every((n) => n === 0)) {
    throw new Error(
      'Configuración de entorno inválida: todas las concurrencias son 0 (el worker no consumiría ninguna cola)',
    );
  }
  if (env.SMTP_HOST && !env.SMTP_FROM) {
    throw new Error('Configuración de entorno inválida: SMTP_HOST necesita SMTP_FROM (remitente)');
  }
  if (Boolean(env.SMTP_USER) !== Boolean(env.SMTP_PASSWORD_REF)) {
    throw new Error(
      'Configuración de entorno inválida: SMTP_USER y SMTP_PASSWORD_REF van juntas (o ninguna)',
    );
  }
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
