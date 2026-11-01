// Contratos del alta de servidores (DESIGN §7).
import type { Asset, AssetStatus } from './assets.js';
import type { InventoryPolicyFields } from './inventory.js';
import type { JobName, JobState } from './jobs.js';
import type { AdminAccessRequest } from './terminal.js';

/** Usuario dedicado que crea el script de alta. */
export const ENROLL_SSH_USER = 'inventory';

/**
 * Versión de la lista de comandos del sudoers que instala el script de alta.
 * - v1: comandos de lectura de la recolección y los descubridores.
 * - v2: `docker save sha256:<id>` (regex de sudo ≥ 1.9.10) para escanear imágenes con Trivy.
 * - v3: `docker volume ls -q`, `docker network ls --format {{.Name}}` (volúmenes y redes sin
 *   uso) y las consultas fijas de `plesk db` del descubridor de Plesk.
 * - v4: una sola regla, el ayudante de root `infraward-query` con una lista cerrada de consultas
 *   (válido con sudo-rs). El worker solo usa el ayudante: con v1–v3 la recolección es parcial.
 * - v5: rutas de los proxies (`nginx-routes`, `docker-nginx-routes`: `nginx -T` filtrado en el
 *   propio servidor) y etiquetas de Traefik/Caddy en la plantilla de `docker inspect` (QoL-5b).
 * - v6: `process-packages` (ejecutable y librerías de cada proceso en marcha o en escucha y su
 *   paquete, calculado en el propio servidor) para la priorización (sesión 19).
 * - v7: `sshd-auth` (`sshd -T` filtrado en el propio servidor: solo `PermitRootLogin`,
 *   `PasswordAuthentication` y `KbdInteractiveAuthentication`) para el aviso de login de root o
 *   por contraseña (QoL-7).
 * - v8: consultas `podman-*` (contenedores, imágenes, volúmenes, redes y pods de Podman como root
 *   y, por su socket, de los usuarios rootless de `/etc/infraward/podman-users`; `podman save`
 *   para escanear las imágenes) y `podman-users` (usuarios de esa lista y contenedores rootless
 *   de otros usuarios, para avisar de los que no se ven).
 */
export const SUDOERS_VERSION = 8;

/**
 * Qué pasa si al servidor le falta una capacidad: `outdated` = aviso «sudoers desactualizado»
 * (hay que volver a ejecutar el script); `note` = el servidor funciona, pero se avisa de lo que
 * no se ve, como nota informativa.
 */
export type SudoersMissingEffect = 'outdated' | 'note';

export interface SudoersCapability {
  /** Versión del sudoers que la trae. */
  version: number;
  /** Roles del servidor que la necesitan. */
  roles: readonly string[];
  onMissing: SudoersMissingEffect;
  /** Qué no se ve sin ella (para la nota o el motivo del aviso). */
  description: string;
}

/**
 * ÚNICA tabla de qué versión del sudoers exige cada capacidad (DESIGN §14). Los avisos
 * («sudoers desactualizado»), las notas y las comprobaciones del worker salen de aquí.
 */
export const SUDOERS_CAPABILITIES = {
  // v4: todo lo que necesita root pasa por el ayudante `infraward-query` (lista cerrada de
  // consultas), la única regla del sudoers. Con sudo-rs (Ubuntu ≥ 25.10) es lo único que
  // funciona: no admite comodines, espacios ni regex en los argumentos. Cualquier servidor.
  helper: {
    version: 4,
    roles: ['*'],
    onMissing: 'outdated',
    description:
      'puertos, hardware y consultas de Docker, Proxmox y Plesk (ayudante de root de la v4)',
  },
  'docker.save': {
    version: 4,
    roles: ['docker-host'],
    onMissing: 'outdated',
    description: 'imágenes sin escanear con Trivy (hace falta docker save)',
  },
  // v8: Podman (rootful y rootless de los usuarios de la lista). Con un sudoers anterior el
  // ayudante rechaza las consultas `podman-*`: el host no se lista.
  podman: {
    version: 8,
    roles: ['podman-host'],
    onMissing: 'outdated',
    description:
      'contenedores, imágenes, volúmenes y redes de Podman (y el escaneo de sus imágenes)',
  },
  plesk: {
    version: 4,
    roles: ['plesk'],
    onMissing: 'outdated',
    description:
      'dominios, suscripciones, bases de datos y certificados de Plesk',
  },
  // v5: qué servicio sirve cada dominio. Sin ella el inventario está completo; solo se corta el
  // camino de los dominios en ese proxy.
  proxies: {
    version: 5,
    roles: ['*'],
    onMissing: 'note',
    description:
      'rutas de nginx, Nginx Proxy Manager, Traefik y Caddy (qué servicio sirve cada dominio)',
  },
  // v6: qué paquete es de qué proceso. Sin ella la prioridad de los paquetes del servidor no
  // sabe si están en marcha ni en qué puertos escuchan.
  processes: {
    version: 6,
    roles: ['*'],
    onMissing: 'note',
    description:
      'qué paquetes usan los procesos en marcha y en escucha (prioridad de las vulnerabilidades)',
  },
  // v7: configuración efectiva de sshd (`sshd -T`, solo la autenticación) para avisar del login
  // de root o por contraseña (caja fuerte, QoL-7).
  sshd: {
    version: 7,
    roles: ['*'],
    onMissing: 'note',
    description:
      'si sshd admite el login de root o por contraseña (configuración efectiva de sshd)',
  },
} as const satisfies Record<string, SudoersCapability>;
export type SudoersCapabilityName = keyof typeof SUDOERS_CAPABILITIES;

const CAPABILITIES = Object.entries(SUDOERS_CAPABILITIES) as [
  SudoersCapabilityName,
  SudoersCapability,
][];

/**
 * ¿Tiene el servidor esta capacidad? `version` null = sin sudoers de InfraWard (alta manual).
 * `via: 'pct'` (CT recogido desde el nodo) = root en el CT: todas.
 */
export function sudoersAllows(
  capability: SudoersCapabilityName,
  version: number | null,
  via: 'ssh' | 'pct' = 'ssh',
): boolean {
  return (
    via === 'pct' || (version ?? 0) >= SUDOERS_CAPABILITIES[capability].version
  );
}

/** Capacidades que necesita un servidor con estos roles (`'*'` = cualquier servidor). */
export function sudoersCapabilitiesFor(
  roles: readonly string[],
): SudoersCapabilityName[] {
  return CAPABILITIES.filter(([, c]) =>
    c.roles.some((r) => r === '*' || roles.includes(r)),
  ).map(([name]) => name);
}

/**
 * Versión del sudoers que necesita un servidor con estos roles: la mayor de las capacidades
 * cuya falta es `outdated` (las `note` no la suben).
 */
export function requiredSudoersVersion(roles: readonly string[]): number {
  return Math.max(
    1,
    ...sudoersCapabilitiesFor(roles)
      .map((name) => SUDOERS_CAPABILITIES[name] as SudoersCapability)
      .filter((c) => c.onMissing === 'outdated')
      .map((c) => c.version),
  );
}

/** Lo que le falta a un servidor por su versión del sudoers, separado en avisos y notas. */
export interface SudoersGaps {
  /** Capacidades `outdated` que faltan: el servidor sale como «sudoers desactualizado». */
  outdated: SudoersCapabilityName[];
  /** Notas informativas («volúmenes sin uso no listados: requiere sudoers v3»). */
  notes: string[];
}

export function sudoersGaps(
  roles: readonly string[],
  version: number | null,
): SudoersGaps {
  const gaps: SudoersGaps = { outdated: [], notes: [] };
  const notes = new Map<number, string[]>();
  for (const name of sudoersCapabilitiesFor(roles)) {
    if (sudoersAllows(name, version)) continue;
    const c = SUDOERS_CAPABILITIES[name] as SudoersCapability;
    if (c.onMissing === 'outdated') gaps.outdated.push(name);
    else notes.set(c.version, [...(notes.get(c.version) ?? []), c.description]);
  }
  // Una nota por versión: «volúmenes sin uso no listados y redes sin uso no listadas: …».
  for (const [v, list] of [...notes].sort(([a], [b]) => a - b)) {
    const text = list.join(' y ');
    gaps.notes.push(
      `${text.charAt(0).toUpperCase()}${text.slice(1)}: requiere sudoers v${v}. Vuelve a ejecutar el script de alta para actualizarlo`,
    );
  }
  return gaps;
}

/** Datos de conexión de un asset (no secretos). */
export interface AssetConnection {
  host: string;
  port: number;
  user: string;
}

/** Credenciales de un asset: solo referencias `secret://…`, nunca valores. */
export interface AssetCredentials {
  /** Clave privada SSH (formato OpenSSH). */
  sshPrivateKey?: string;
  /** Token de API de un conector de dominios (`dns_provider`, QoL-5). */
  apiToken?: string;
}

/**
 * Cómo entra el worker en un servidor (DESIGN §6, §7):
 * - `static_key`: clave ed25519 permanente; la privada en el proveedor de secretos y la pública
 *   en `authorized_keys`.
 * - `ca_certificate`: sin claves permanentes. En cada job, un par efímero firmado por la CA SSH
 *   del proveedor (OpenBao) con vida corta; el servidor confía en la CA (`TrustedUserCAKeys`).
 */
export const SSH_AUTH_MODES = ['static_key', 'ca_certificate'] as const;
export type SshAuthMode = (typeof SSH_AUTH_MODES)[number];

/** Único principal de los certificados: el usuario dedicado (AuthorizedPrincipalsFile). */
export const SSH_CERT_PRINCIPAL = 'inventory';

export const ENROLLMENT_METHODS = ['script', 'manual'] as const;
export type EnrollmentMethod = (typeof ENROLLMENT_METHODS)[number];

/**
 * `initial`: alta. `sudoers_update`: volver a ejecutar el script con las mismas credenciales
 * (actualiza el sudoers y, en modo CA, las claves de la CA). `ca_migration`: pasar un servidor
 * de clave estática a certificados (al verificarse, la clave estática se borra).
 */
export const ENROLLMENT_PURPOSES = [
  'initial',
  'sudoers_update',
  'ca_migration',
] as const;
export type EnrollmentPurpose = (typeof ENROLLMENT_PURPOSES)[number];

/**
 * `pending`: token emitido, esperando al script o a la confirmación manual.
 * `confirmed`: el script avisó (o el admin confirmó); verificación encolada.
 * `verified`: el worker conectó por SSH. `failed`: la verificación falló (ver `error`).
 * `cancelled`: sustituido o cerrado al retirar el asset.
 */
export const ENROLLMENT_STATUSES = [
  'pending',
  'confirmed',
  'verified',
  'failed',
  'cancelled',
] as const;
export type EnrollmentStatus = (typeof ENROLLMENT_STATUSES)[number];

/** Tipos de host key que el script puede reportar (salida de `ssh-keygen -lf`). */
export const HOST_KEY_TYPES = ['ED25519', 'ECDSA', 'RSA'] as const;
export type HostKeyType = (typeof HOST_KEY_TYPES)[number];

export interface HostKeyFingerprint {
  type: HostKeyType;
  /** `SHA256:<base64 sin relleno>`. */
  fingerprint: string;
}

export interface EnrollServerRequest {
  /** IP o hostname con el que el worker llega al servidor. */
  host: string;
  port?: number;
  name?: string;
  /** Añade `--install-sudo` a los comandos: el script instala sudo si falta (p. ej. Proxmox). */
  installSudo?: boolean;
  /**
   * Por defecto `ca_certificate` si hay un proveedor con CA SSH y alguna CA vigente; si no,
   * `static_key`.
   */
  authMode?: SshAuthMode;
  /**
   * `operator`: el script instala también el acceso interactivo de administración (sesión 22;
   * solo en modo CA; exige `users.manage` y reautenticación reciente). Por defecto, sin él.
   */
  adminAccess?: 'operator';
  /** Tags del servidor desde el alta (QoL-6b). */
  tags?: string[];
  /** Proyectos en los que entra (`include`); requiere `projects.write`. */
  projectIds?: string[];
  /**
   * Regla propia de política (o la de una plantilla, `INVENTORY_POLICY_PRESETS`); requiere
   * `policy.write`. Se aplica antes de la primera recolección y escaneo.
   */
  policy?: InventoryPolicyFields;
}

/** Cuerpo de `POST /assets/:id/enrollment/token`. */
export interface IssueEnrollmentTokenRequest {
  installSudo?: boolean;
  /**
   * `ca_certificate` sobre un servidor activo en modo estático abre una migración a CA
   * (`ca_migration`). Sin indicar, el modo actual del asset.
   */
  authMode?: SshAuthMode;
  /**
   * Acceso interactivo de administración (DESIGN §7): `operator` lo instala (cuenta
   * `infraward-admin` con sudo; solo en modo CA) y `none` lo retira. Sin indicar, el script
   * conserva lo que haya. Activarlo exige `users.manage` y reautenticación reciente.
   */
  adminAccess?: AdminAccessRequest;
}

export interface Enrollment {
  id: string;
  assetId: string;
  method: EnrollmentMethod;
  purpose: EnrollmentPurpose;
  /** Modo de acceso que instala el script de este enrolamiento. */
  authMode: SshAuthMode;
  /** Acceso de administración que pide este enrolamiento (null: no lo toca). */
  adminAccess: AdminAccessRequest | null;
  status: EnrollmentStatus;
  /** `pending` con el token caducado. */
  expired: boolean;
  expiresAt: string | null;
  /** Clave pública instalada; null en modo CA (no hay clave permanente). */
  publicKey: string | null;
  sshUser: string;
  reportedHostKeys: HostKeyFingerprint[];
  sudoersVersion: number | null;
  error: string | null;
  jobId: string | null;
  confirmedAt: string | null;
  verifiedAt: string | null;
  createdAt: string;
}

/** Enrolamiento recién emitido: los comandos con el token solo se devuelven en este momento. */
export interface IssuedEnrollment extends Enrollment {
  /** `curl -fsSL <url>/enroll/<token> | sudo bash` (como root y con `--install-sudo` si se pidió). */
  command: string;
  /**
   * Para servidores que no llegan a la API (VPN, NAT): el script en base64 dentro del propio
   * comando. No lleva token ni avisa a la API; imprime las huellas de las host keys, que se
   * pegan en la confirmación (`hostKeys`).
   */
  embeddedCommand: string;
  /** Alternativa manual: añadir la clave pública a `authorized_keys`. null en modo CA. */
  manualCommand: string | null;
}

export interface EnrollServerResponse {
  asset: Asset;
  enrollment: IssuedEnrollment;
}

export interface ConfirmManualEnrollmentRequest {
  /** Usuario en cuya cuenta se añadió la clave. Nunca `root`. */
  sshUser: string;
  /**
   * Huellas de las host keys obtenidas fuera de banda (las imprime el script embebido). Con
   * ellas, el worker solo acepta una de esas claves; sin ellas, TOFU.
   */
  hostKeys?: HostKeyFingerprint[];
}

const FINGERPRINT_IN_TEXT = /SHA256:([A-Za-z0-9+/]{43})(?![A-Za-z0-9+/=])/;
const KEY_TYPE_IN_TEXT = /(?:^|[\s(])(ED25519|ECDSA|RSA)(?:[\s)]|$)/i;

/**
 * Huellas de host keys pegadas por el usuario: la salida del script embebido
 * (`ED25519 SHA256:…`) o la de `ssh-keygen -lf` (`256 SHA256:… root@host (ED25519)`). Ignora
 * las líneas que no reconoce y quita duplicados.
 */
export function parseHostKeyFingerprints(text: string): HostKeyFingerprint[] {
  const seen = new Set<string>();
  const keys: HostKeyFingerprint[] = [];
  for (const line of text.split(/\r?\n/)) {
    const fp = FINGERPRINT_IN_TEXT.exec(line);
    const type = KEY_TYPE_IN_TEXT.exec(line.replace(FINGERPRINT_IN_TEXT, ' '));
    if (!fp || !type) continue;
    const fingerprint = `SHA256:${fp[1]}`;
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    keys.push({
      type: type[1].toUpperCase() as HostKeyType,
      fingerprint,
    });
  }
  return keys;
}

/**
 * Lo que envía el script al terminar. Llega sin autenticar (solo con el token): se valida y solo
 * sirve para fijar la host key; la versión del sudoers la lee el worker al conectar.
 */
export interface EnrollDoneRequest {
  hostKeys: HostKeyFingerprint[];
}

/** Comando para quitar el acceso de InfraWard de un servidor dado de baja. */
export interface CredentialRevocation {
  assetId: string;
  /** Si se borró la clave privada del proveedor de secretos. */
  secretRemoved: boolean;
  command: string;
}

export interface EnrollmentVerifyJobData {
  enrollmentId: string;
}

export interface EnrollmentVerifyJobResult {
  assetId: string;
  hostKeyFingerprint: string;
  sudoersVersion: number | null;
  /** Versión del acceso de administración instalado (null si no lo tiene; DESIGN §7). */
  adminAccessVersion: number | null;
  /** Primera recolección encolada tras verificar (o la que ya estaba en cola), si la hay. */
  collectJobId: string | null;
}

// --- Progreso del alta en tiempo real (SSE `GET /assets/:id/enrollment/events`) ---

/**
 * Pasos del stepper tras generar el comando: `waiting` (esperando al script o a la
 * confirmación), `connecting` (verificación por SSH), `scanning` (recolección, descubrimiento
 * y escaneos encadenados), `ready`, y los finales `failed` (reintentable) y `cancelled`.
 */
export const ENROLLMENT_PHASES = [
  'waiting',
  'connecting',
  'scanning',
  'ready',
  'failed',
  'cancelled',
] as const;
export type EnrollmentPhase = (typeof ENROLLMENT_PHASES)[number];

/** Un job de la cadena del alta, sin sus datos ni su resultado. */
export interface EnrollmentJobProgress {
  id: string;
  name: JobName;
  /** Asset sobre el que trabaja (en `image.scan`, null: el job es de la imagen). */
  assetId: string | null;
  state: JobState;
  /** Porcentaje 0-100. */
  progress: number;
  /** Último mensaje de progreso. */
  message: string | null;
  failedReason: string | null;
}

export interface EnrollmentProgress {
  assetId: string;
  assetName: string;
  assetStatus: AssetStatus;
  phase: EnrollmentPhase;
  enrollment: Enrollment;
  /** Verificación y todo lo que encadena: recolecciones, descubrimientos y escaneos. */
  jobs: EnrollmentJobProgress[];
  /** true si la cadena tenía más jobs de los que se siguen. */
  truncated: boolean;
  at: string;
}

/** Estados finales (`unknown`: ya no está en Redis, retención agotada). */
const FINISHED_JOB_STATES: ReadonlySet<JobState> = new Set<JobState>([
  'completed',
  'failed',
  'unknown',
]);

/** Paso del stepper según el enrolamiento y los jobs que encadena la verificación. */
export function enrollmentPhase(
  status: EnrollmentStatus,
  jobs: readonly Pick<EnrollmentJobProgress, 'name' | 'state'>[],
): EnrollmentPhase {
  switch (status) {
    case 'pending':
      return 'waiting';
    case 'confirmed':
      return 'connecting';
    case 'failed':
      return 'failed';
    case 'cancelled':
      return 'cancelled';
    case 'verified': {
      const running = jobs.filter(
        (j) => !FINISHED_JOB_STATES.has(j.state),
      );
      // El enrolamiento se marca verificado antes de que el job encole la recolección: hasta
      // que termina, sigue «conectando» (si no, se vería «listo» un instante).
      if (running.some((j) => j.name === 'enrollment.verify'))
        return 'connecting';
      return running.length > 0 ? 'scanning' : 'ready';
    }
  }
}
