/** Token de inyección con la lista de proveedores activos. */
export const SECRET_PROVIDERS = Symbol('SECRET_PROVIDERS');

/** Origen de secretos (local, openbao, vaultwarden…). Los valores nunca se loguean. */
export interface SecretProvider {
  readonly id: string;
  get(path: string, field?: string): Promise<string>;
  set?(path: string, data: Record<string, string>): Promise<void>;
  /** Borra la ruta entera (todos sus campos). Devuelve si existía. */
  delete?(path: string): Promise<boolean>;
  healthCheck(): Promise<boolean>;
  /** Libera recursos al cerrar la app (timers, tokens). */
  close?(): Promise<void>;
}

/** Petición de firma de una clave pública SSH (certificado de usuario de vida corta). */
export interface SshCertificateRequest {
  /** Línea `ssh-ed25519 <base64> [comentario]` de la clave efímera. */
  publicKey: string;
  /** Único principal del certificado (el usuario del servidor, p. ej. `inventory`). */
  principal: string;
  /** Identificador que sshd escribe en su log al aceptar el certificado (trazabilidad). */
  keyId: string;
  ttlSeconds: number;
  /**
   * Extensiones del certificado (lista blanca). Sin ninguna, el certificado equivale a
   * `restrict` (sin pty ni reenvíos): el del inventario. La terminal pide `permit-pty`.
   */
  extensions?: readonly SshCertificateExtension[];
}

/** Únicas extensiones que se piden: un PTY para la terminal (nunca reenvíos ni agente). */
export const SSH_CERTIFICATE_EXTENSIONS = ['permit-pty'] as const;
export type SshCertificateExtension = (typeof SSH_CERTIFICATE_EXTENSIONS)[number];

/** Clave pública de una CA SSH en la que los servidores deben confiar. */
export interface SshCaPublicKey {
  /** Línea `ssh-ed25519 <base64>` (sin comentario). */
  publicKey: string;
  /** `SHA256:…`, como `ssh-keygen -lf`. */
  fingerprint: string;
  /** La que firma ahora (emisor por defecto). */
  active: boolean;
}

/**
 * Capacidad opcional: CA SSH. Solo la implementan los proveedores que la soportan (OpenBao con
 * el motor SSH en modo CA). La clave privada de la CA nunca sale del proveedor.
 */
export interface SshCertificateCapable {
  /** Devuelve el certificado (`ssh-ed25519-cert-v01@openssh.com …`) de la clave. */
  signSshKey(request: SshCertificateRequest): Promise<string>;
  /** Claves de todas las CA vigentes (durante una rotación, la actual y la nueva). */
  sshCaPublicKeys(): Promise<SshCaPublicKey[]>;
}

export function isSshCertificateCapable(
  provider: SecretProvider,
): provider is SecretProvider & SshCertificateCapable {
  const p = provider as Partial<SshCertificateCapable>;
  return (
    typeof p.signSshKey === 'function' &&
    typeof p.sshCaPublicKeys === 'function'
  );
}
