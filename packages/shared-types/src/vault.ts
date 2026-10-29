// Caja fuerte de credenciales (QoL-7, DESIGN §19): credenciales que usa una persona (consola de
// emergencia, paneles web, IPMI…) y que InfraWard nunca usa para conectarse.

export const VAULT_ENTRY_KINDS = ['console', 'web', 'ipmi', 'other'] as const;
export type VaultEntryKind = (typeof VAULT_ENTRY_KINDS)[number];

export const VAULT_ENTRY_KIND_LABELS: Record<VaultEntryKind, string> = {
  console: 'Consola',
  web: 'Web',
  ipmi: 'IPMI / BMC',
  other: 'Otro',
};

/** Estado de la rotación: al día, vencida (supera el plazo) o sin fecha de rotación. */
export const VAULT_ROTATION_STATES = ['ok', 'overdue', 'unknown'] as const;
export type VaultRotationState = (typeof VAULT_ROTATION_STATES)[number];

/** Cómo se creó cada versión del secreto. */
export const VAULT_VERSION_ORIGINS = ['created', 'replaced', 'restored'] as const;
export type VaultVersionOrigin = (typeof VAULT_VERSION_ORIGINS)[number];

/** Para qué se revela: verlo unos segundos o copiarlo al portapapeles. */
export const VAULT_REVEAL_PURPOSES = ['show', 'copy'] as const;
export type VaultRevealPurpose = (typeof VAULT_REVEAL_PURPOSES)[number];

/** Código del 409 cuando la API no tiene almacén de la caja fuerte (VAULT_PROVIDER=none). */
export const VAULT_NOT_CONFIGURED = 'vault_not_configured';

export const VAULT_NAME_MAX = 120;
export const VAULT_USERNAME_MAX = 200;
export const VAULT_URL_MAX = 2000;
export const VAULT_NOTES_MAX = 4000;
export const VAULT_SECRET_MAX = 4096;
export const VAULT_REASON_MAX = 200;
/** Segundos que la web enseña el valor revelado (y tras los que vacía el portapapeles). */
export const VAULT_REVEAL_SECONDS = 30;

export const VAULT_ROTATION_DAYS_MIN = 1;
export const VAULT_ROTATION_DAYS_MAX = 3650;
export const VAULT_RETENTION_DAYS_MIN = 1;
export const VAULT_RETENTION_DAYS_MAX = 365;

export interface VaultSettings {
  /** Plazo de rotación por defecto (días); cada entrada puede tener el suyo. */
  rotationWarnDays: number;
  /** Notificar a los demás admins cada vez que alguien revela una credencial. */
  notifyOnReveal: boolean;
  /** Días que una entrada borrada se puede recuperar antes de destruirla. */
  deleteRetentionDays: number;
}

export const DEFAULT_VAULT_SETTINGS: VaultSettings = {
  rotationWarnDays: 180,
  notifyOnReveal: true,
  deleteRetentionDays: 30,
};

/** Entrada de la caja fuerte: solo metadatos. Nunca el valor ni la referencia al secreto. */
export interface VaultEntry {
  id: string;
  kind: VaultEntryKind;
  name: string;
  username: string | null;
  url: string | null;
  notes: string | null;
  /** Asset al que pertenece (null = suelta, o su asset se purgó). */
  asset: { id: string; name: string; type: string; roles: string[] } | null;
  /** Tiene secreto guardado (una entrada puede crearse solo con los datos). */
  hasSecret: boolean;
  currentVersion: number | null;
  lastRotatedAt: string | null;
  /** Plazo propio (días) o null = el de los ajustes. */
  rotationDays: number | null;
  /** Plazo que se aplica (el propio o el de los ajustes). */
  effectiveRotationDays: number;
  rotationState: VaultRotationState;
  /** Fecha en que vence la rotación (ISO) o null sin fecha de rotación. */
  rotationDueAt: string | null;
  createdAt: string;
  createdBy: string | null;
  updatedAt: string;
  updatedBy: string | null;
  /** Borrada (lógicamente): se destruye en `purgeAt`. */
  deletedAt: string | null;
  deletedBy: string | null;
  purgeAt: string | null;
}

export interface VaultEntryList {
  items: VaultEntry[];
  /** Entradas vigentes con la rotación vencida (en todo el inventario, no solo en la lista). */
  overdue: number;
}

export interface CreateVaultEntryRequest {
  kind: VaultEntryKind;
  name: string;
  username?: string | null;
  url?: string | null;
  notes?: string | null;
  assetId?: string | null;
  rotationDays?: number | null;
  /** El secreto (opcional al crear). Solo de escritura: ninguna respuesta lo devuelve. */
  secret?: string;
  /** Fecha de la última rotación (ISO); por defecto, si lleva secreto, ahora. */
  lastRotatedAt?: string | null;
}

export type UpdateVaultEntryRequest = Partial<
  Omit<CreateVaultEntryRequest, 'secret'>
>;

export interface ReplaceVaultSecretRequest {
  secret: string;
  /** Es una rotación (ya aplicada en el servidor): actualiza la fecha de la última rotación. */
  rotated: boolean;
}

export interface VaultVersion {
  version: number;
  origin: VaultVersionOrigin;
  /** Versión restaurada (si `origin` es `restored`). */
  restoredFrom: number | null;
  createdAt: string;
  createdBy: string | null;
  current: boolean;
  /** El almacén ya no la conserva (supera las versiones guardadas): no se puede restaurar. */
  available: boolean;
}

export interface RevealVaultSecretRequest {
  reason?: string;
  purpose: VaultRevealPurpose;
}

/** La única respuesta con el valor (POST /vault/entries/:id/reveal, solo admin y con step-up). */
export interface RevealVaultSecretResponse {
  value: string;
  version: number;
  expiresInSeconds: number;
}

export interface VaultStatus {
  /** Almacén configurado (`none` = caja fuerte sin configurar). */
  provider: 'none' | 'local' | 'openbao';
  healthy: boolean;
  /** Versiones que conserva el almacén por entrada. */
  maxVersions: number;
}

/** Estado de la rotación de una entrada (vencida si `lastRotatedAt + días <= ahora`). */
export function vaultRotationState(
  lastRotatedAt: Date | string | null,
  days: number,
  now: Date = new Date(),
): { state: VaultRotationState; dueAt: Date | null } {
  if (!lastRotatedAt) return { state: 'unknown', dueAt: null };
  const dueAt = new Date(new Date(lastRotatedAt).getTime() + days * 86_400_000);
  return { state: dueAt.getTime() <= now.getTime() ? 'overdue' : 'ok', dueAt };
}

// --- Generar contraseñas ---

/** Sin caracteres que se confunden al leerlos (0/O, 1/l/I) ni comillas o barras (escapes). */
export const PASSWORD_CLASSES = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!#%+-.:=?@^_~',
} as const;

export const GENERATED_PASSWORD_MIN = 12;
export const GENERATED_PASSWORD_MAX = 128;
export const GENERATED_PASSWORD_DEFAULT = 24;

export interface GeneratePasswordOptions {
  length?: number;
  symbols?: boolean;
}

/**
 * Contraseña aleatoria con al menos un carácter de cada clase. `randomBytes` es la fuente
 * criptográfica (en la web, `crypto.getRandomValues`): sin dependencias de runtime. Elige cada
 * carácter por muestreo con rechazo (sin sesgo de módulo) y baraja con Fisher-Yates.
 */
export function generatePassword(
  randomBytes: (n: number) => Uint8Array,
  options: GeneratePasswordOptions = {},
): string {
  const length = options.length ?? GENERATED_PASSWORD_DEFAULT;
  if (
    !Number.isInteger(length) ||
    length < GENERATED_PASSWORD_MIN ||
    length > GENERATED_PASSWORD_MAX
  ) {
    throw new RangeError(
      `La longitud debe estar entre ${GENERATED_PASSWORD_MIN} y ${GENERATED_PASSWORD_MAX}`,
    );
  }
  const classes: string[] = [
    PASSWORD_CLASSES.lower,
    PASSWORD_CLASSES.upper,
    PASSWORD_CLASSES.digits,
  ];
  if (options.symbols !== false) classes.push(PASSWORD_CLASSES.symbols);
  const all = classes.join('');

  let pool: Uint8Array = new Uint8Array(0);
  let offset = 0;
  const nextByte = (): number => {
    if (offset >= pool.length) {
      pool = randomBytes(256);
      offset = 0;
    }
    return pool[offset++];
  };
  /** Entero uniforme en [0, n) con n ≤ 256. */
  const uniform = (n: number): number => {
    const limit = 256 - (256 % n);
    for (;;) {
      const b = nextByte();
      if (b < limit) return b % n;
    }
  };

  const chars = classes.map((c) => c[uniform(c.length)]);
  while (chars.length < length) chars.push(all[uniform(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = uniform(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// --- Comando para aplicarla (InfraWard nunca la aplica) ---

export interface RotationCommand {
  /** Qué hace, en una frase. */
  title: string;
  /** Comandos interactivos: piden la contraseña, que nunca va en la línea (ni en el historial). */
  commands: string[];
  note?: string;
}

/** Usuario seguro para un comando de shell (si no, el marcador `<usuario>`). */
function shellUser(username: string | null | undefined, fallback: string): string {
  const u = username?.trim();
  return u && /^[A-Za-z0-9._@-]{1,64}$/.test(u) ? u : fallback;
}

/**
 * Comando para aplicar una contraseña nueva según el tipo de entrada y el asset. Nunca incluye
 * la contraseña: el comando la pide y se pega desde el portapapeles.
 */
export function rotationCommand(
  kind: VaultEntryKind,
  username: string | null | undefined,
  hints: { roles?: readonly string[]; assetType?: string | null } = {},
): RotationCommand {
  const roles = hints.roles ?? [];
  if (kind === 'console') {
    const user = shellUser(username, 'root');
    return {
      title: `Cambiar la contraseña de ${user} en el servidor`,
      commands: [user === 'root' ? 'sudo passwd root' : `sudo passwd ${user}`],
      note: 'Pide la contraseña nueva dos veces: pégala desde el portapapeles.',
    };
  }
  if (kind === 'web' && roles.some((r) => r === 'proxmox-node' || r === 'proxmox')) {
    const raw = shellUser(username, 'root@pam');
    const user = raw.includes('@') ? raw : `${raw}@pam`;
    return {
      title: `Cambiar la contraseña de ${user} en Proxmox VE`,
      commands: [`pveum passwd ${user}`],
      note: user.endsWith('@pam')
        ? 'Los usuarios @pam son los del sistema: cambia también su contraseña de consola.'
        : undefined,
    };
  }
  if (kind === 'web' && roles.includes('plesk')) {
    return {
      title: 'Cambiar la contraseña del administrador de Plesk',
      commands: [
        'read -rs PSA_PASSWORD && export PSA_PASSWORD',
        'sudo --preserve-env=PSA_PASSWORD plesk bin admin --set-admin-password -passwd ""',
        'unset PSA_PASSWORD',
      ],
      note: 'Con -passwd "" Plesk la toma de PSA_PASSWORD: `read -s` la lee sin mostrarla ni guardarla en el historial.',
    };
  }
  if (kind === 'ipmi') {
    return {
      title: 'Cambiar la contraseña de un usuario del BMC (IPMI)',
      commands: [
        'sudo ipmitool user list 1',
        'sudo ipmitool user set password <id>',
      ],
      note: 'Busca el id del usuario en la lista; sin la contraseña en la línea, ipmitool la pide.',
    };
  }
  return {
    title: 'Aplicar la contraseña nueva',
    commands: [],
    note: 'Cámbiala desde la interfaz del servicio y después marca la entrada como rotada.',
  };
}
