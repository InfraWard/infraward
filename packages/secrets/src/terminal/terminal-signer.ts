import {
  loadOpenBaoConfig,
  OPENBAO_ENV,
  type OpenBaoSource,
} from '../openbao/openbao-config.js';
import { OpenBaoSecretProvider } from '../openbao/openbao.provider.js';
import type { FetchFn } from '../openbao/openbao-client.js';

/**
 * Variables del firmante de la terminal (sesión 21, DESIGN §6 y §11). Solo las lee la API: ni el
 * worker ni el gateway las declaran. Dirección, mounts y tiempo de espera son los de la app
 * (OPENBAO_*); la AppRole y el rol de firma, los suyos.
 */
export const TERMINAL_SIGNER_ENV = {
  roleId: 'TERMINAL_OPENBAO_ROLE_ID',
  secretId: 'TERMINAL_OPENBAO_SECRET_ID',
  secretIdFile: 'TERMINAL_OPENBAO_SECRET_ID_FILE',
  sshRole: 'TERMINAL_OPENBAO_SSH_ROLE',
} as const;

/** Rol del motor SSH para la terminal: principal `infraward-operators` y `permit-pty`. */
export const TERMINAL_DEFAULT_SSH_ROLE = 'infraward-operator';

const OPENBAO_NAMES = { ...OPENBAO_ENV, ...TERMINAL_SIGNER_ENV };

export interface TerminalSignerSource {
  /** OpenBao de la app con la AppRole y el rol de la terminal (TERMINAL_OPENBAO_*). */
  openbao: OpenBaoSource;
  /** AppRole y rol de la app (los comparte el worker): la terminal no puede usarlos. */
  appOpenbao?: { roleId?: string; sshRole?: string };
}

/** Petición de firma de la terminal: un principal de rol, el key_id de la sesión y su vida. */
export interface TerminalCertificateRequest {
  publicKey: string;
  principal: string;
  keyId: string;
  ttlSeconds: number;
}

/**
 * Firma los certificados de la terminal con su propia AppRole (`infraward-terminal`), cuya
 * política solo permite el rol `infraward-operator`. La AppRole de la app (la del worker) no
 * puede firmar ese rol: un worker comprometido no emite certificados de administración. Siempre
 * con `permit-pty` y nada más.
 */
export class TerminalCertSigner {
  constructor(private readonly provider: OpenBaoSecretProvider) {}

  sign(request: TerminalCertificateRequest): Promise<string> {
    return this.provider.signSshKey({ ...request, extensions: ['permit-pty'] });
  }

  healthCheck(): Promise<boolean> {
    return this.provider.healthCheck();
  }

  close(): Promise<void> {
    return this.provider.close();
  }
}

/**
 * Crea el firmante de la terminal, o null si no está configurado (sin TERMINAL_OPENBAO_ROLE_ID:
 * la terminal no está disponible). Se niega a arrancar si comparte la AppRole o el rol de firma
 * con la app. Los errores nombran la variable, nunca su valor.
 */
export function createTerminalSigner(
  source: TerminalSignerSource,
  fetchFn?: FetchFn,
): TerminalCertSigner | null {
  const { openbao } = source;
  if (!openbao.roleId && !openbao.secretId && !openbao.secretIdFile) return null;
  const config = loadOpenBaoConfig(
    { ...openbao, sshRole: openbao.sshRole ?? TERMINAL_DEFAULT_SSH_ROLE },
    OPENBAO_NAMES,
  );
  const app = source.appOpenbao;
  if (app?.roleId && app.roleId.trim() === config.credentials.roleId)
    throw new Error(
      `${TERMINAL_SIGNER_ENV.roleId}: la terminal necesita su propia AppRole (infraward-terminal), no la de la app (la tiene también el worker)`,
    );
  if (config.sshRole === (app?.sshRole?.trim() || 'inventory'))
    throw new Error(
      `${TERMINAL_SIGNER_ENV.sshRole}: la terminal necesita su propio rol de firma, no el del inventario`,
    );
  return new TerminalCertSigner(new OpenBaoSecretProvider(config, fetchFn));
}
