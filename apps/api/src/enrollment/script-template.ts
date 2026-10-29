import { ADMIN_ACCESS_VERSION, type SshAuthMode } from '@infraward/shared-types';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/** Plantilla del repositorio; misma profundidad desde src/ (tests) y dist/ (compilado). */
export const DEFAULT_SCRIPT_TEMPLATE = resolve(
  import.meta.dirname,
  '../../../../ansible/enroll/enroll.sh.tmpl',
);

/** `online`: avisa a la API con el token. `embedded`: sin token, imprime las huellas. */
export type EnrollScriptMode = 'online' | 'embedded';

export interface EnrollScriptValues {
  mode: EnrollScriptMode;
  /** Vacía en modo `embedded`. */
  apiUrl: string;
  /** Vacío en modo `embedded`. */
  token: string;
  authMode: SshAuthMode;
  /** Clave pública del asset (`static_key`); vacía en modo CA. */
  publicKey: string;
  /** Comentario de la línea del asset en authorized_keys (también en CA: para quitarla). */
  keyComment: string;
  sudoersVersion: number;
  /** Claves públicas de las CA en las que confiar (`ca_certificate`); vacío en modo estático. */
  caKeys: string[];
  caVersion: number;
  /** Cuándo se genera el script (epoch en segundos): en modo CA, el script comprueba el reloj. */
  issuedAt: number;
  /**
   * Acceso interactivo de administración (DESIGN §7): `operator` instala la cuenta
   * `infraward-admin` (solo en modo CA), `none` la retira y `keep` no toca lo que haya.
   */
  adminAccess?: 'keep' | 'operator' | 'none';
  /** `ADMIN_ACCESS_VERSION`: versión de lo que instala el acceso de administración. */
  adminAccessVersion?: number;
}

/** Valores tal como van al script (las claves de la CA, una por línea). */
type ScriptFields = Required<Omit<EnrollScriptValues, 'caKeys'>> & { caKeys: string };

/** Como mucho la CA actual y la siguiente (rotación), con margen. */
const MAX_CA_KEYS = 4;

/**
 * Cada valor va entre comillas simples en el script: solo se aceptan caracteres que no pueden
 * cerrarlas ni inyectar nada. Si algo no cumple, no se genera el script.
 */
const CA_KEY = /^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/;

const RULES: Record<keyof ScriptFields, RegExp> = {
  mode: /^(online|embedded)$/,
  apiUrl: /^https?:\/\/[A-Za-z0-9.:[\]_-]+(\/[A-Za-z0-9._~/-]*)?$/,
  token: /^[A-Za-z0-9_-]{43}$/,
  authMode: /^(static_key|ca_certificate)$/,
  publicKey:
    /^ssh-ed25519 [A-Za-z0-9+/]+={0,2} inventory@infraward:[0-9a-f-]{36}$/,
  keyComment: /^inventory@infraward:[0-9a-f-]{36}$/,
  sudoersVersion: /^[1-9][0-9]{0,5}$/,
  // Una clave por línea (las une `render`); sin comillas posibles.
  caKeys:
    /^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(\nssh-ed25519 [A-Za-z0-9+/]+={0,2})*$/,
  caVersion: /^[1-9][0-9]{0,5}$/,
  issuedAt: /^[1-9][0-9]{9,10}$/,
  adminAccess: /^(keep|operator|none)$/,
  adminAccessVersion: /^[1-9][0-9]{0,5}$/,
};

const PLACEHOLDERS: Record<keyof ScriptFields, string> = {
  mode: '__INFRAWARD_MODE__',
  apiUrl: '__INFRAWARD_API_URL__',
  token: '__INFRAWARD_TOKEN__',
  authMode: '__INFRAWARD_AUTH__',
  publicKey: '__INFRAWARD_PUBLIC_KEY__',
  keyComment: '__INFRAWARD_KEY_COMMENT__',
  sudoersVersion: '__INFRAWARD_SUDOERS_VERSION__',
  caKeys: '__INFRAWARD_CA_KEYS__',
  caVersion: '__INFRAWARD_CA_VERSION__',
  issuedAt: '__INFRAWARD_ISSUED_AT__',
  adminAccess: '__INFRAWARD_ADMIN_ACCESS__',
  adminAccessVersion: '__INFRAWARD_ADMIN_ACCESS_VERSION__',
};

/** Plantilla del script de alta (`ansible/enroll/enroll.sh.tmpl`), cargada y comprobada al arrancar. */
export class EnrollScriptTemplate {
  private constructor(private readonly template: string) {}

  static load(path: string = DEFAULT_SCRIPT_TEMPLATE): EnrollScriptTemplate {
    let template: string;
    try {
      template = readFileSync(path, 'utf8');
    } catch {
      throw new Error(
        `No se puede leer la plantilla del script de alta: ${path}`,
      );
    }
    return EnrollScriptTemplate.fromString(template);
  }

  static fromString(template: string): EnrollScriptTemplate {
    const missing = Object.values(PLACEHOLDERS).filter(
      (p) => !template.includes(p),
    );
    if (missing.length > 0) {
      throw new Error(
        `A la plantilla del script de alta le faltan marcadores: ${missing.join(', ')}`,
      );
    }
    return new EnrollScriptTemplate(template);
  }

  render(values: EnrollScriptValues): string {
    // El script embebido no lleva token ni URL: no puede avisar a la API (ni hace falta).
    const embedded = values.mode === 'embedded';
    if (embedded && (values.apiUrl !== '' || values.token !== '')) {
      throw new Error('El script embebido no lleva ni URL ni token');
    }
    // Modo CA: sin clave estática y con al menos una CA. Estático: sin CA.
    const ca = values.authMode === 'ca_certificate';
    if (ca && values.publicKey !== '')
      throw new Error('En modo CA el script no lleva clave estática');
    if (!ca && values.caKeys.length > 0)
      throw new Error('En modo estático el script no lleva claves de CA');
    if (
      ca &&
      (values.caKeys.length === 0 || values.caKeys.length > MAX_CA_KEYS)
    )
      throw new Error(
        `En modo CA hacen falta entre 1 y ${MAX_CA_KEYS} claves de CA`,
      );
    // El acceso de administración solo entra con certificados de la CA (§7).
    if (!ca && values.adminAccess === 'operator')
      throw new Error(
        'El acceso de administración requiere el modo CA',
      );
    if (values.caKeys.some((k) => !CA_KEY.test(k)))
      throw new Error('Valor no válido para el script de alta: caKeys');
    const fields: ScriptFields = {
      ...values,
      adminAccess: values.adminAccess ?? 'keep',
      adminAccessVersion: values.adminAccessVersion ?? ADMIN_ACCESS_VERSION,
      caKeys: values.caKeys.join('\n'),
    };
    let script = this.template;
    for (const key of Object.keys(PLACEHOLDERS) as (keyof ScriptFields)[]) {
      const value = String(fields[key]);
      const empty =
        (embedded && (key === 'apiUrl' || key === 'token')) ||
        (ca && key === 'publicKey') ||
        (!ca && key === 'caKeys');
      if (empty ? value !== '' : !RULES[key].test(value)) {
        throw new Error(`Valor no válido para el script de alta: ${key}`);
      }
      script = script.replaceAll(PLACEHOLDERS[key], value);
    }
    return script;
  }
}
