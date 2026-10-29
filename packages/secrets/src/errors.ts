import type { SecretErrorCode } from '@infraward/shared-types';

/**
 * Error de secretos. El mensaje solo describe la referencia (proveedor, ruta, campo) o
 * la clave (su id): **nunca** contiene el valor de un secreto ni material de claves.
 */
export class SecretError extends Error {
  constructor(
    readonly code: SecretErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'SecretError';
  }
}

export class InvalidSecretRefError extends SecretError {
  constructor(reason: string) {
    super('invalid_ref', `Referencia de secreto inválida: ${reason}`);
    this.name = 'InvalidSecretRefError';
  }
}

export class SecretProviderNotConfiguredError extends SecretError {
  constructor(provider: string) {
    super(
      'provider_not_configured',
      `Proveedor de secretos no configurado: ${provider}`,
    );
    this.name = 'SecretProviderNotConfiguredError';
  }
}

export class SecretNotFoundError extends SecretError {
  constructor(provider: string, path: string) {
    super('not_found', `Secreto no encontrado: ${provider}/${path}`);
    this.name = 'SecretNotFoundError';
  }
}

export class SecretFieldNotFoundError extends SecretError {
  constructor(provider: string, path: string, field: string | undefined) {
    super(
      'field_not_found',
      field === undefined
        ? `El secreto ${provider}/${path} tiene varios campos: indica cuál con #campo`
        : `El secreto ${provider}/${path} no tiene el campo ${field}`,
    );
    this.name = 'SecretFieldNotFoundError';
  }
}

export class SecretKeyMismatchError extends SecretError {
  constructor(provider: string, path: string, stored: string, loaded: string) {
    super(
      'key_mismatch',
      `El secreto ${provider}/${path} se cifró con la clave ${stored} y está cargada la ${loaded}`,
    );
    this.name = 'SecretKeyMismatchError';
  }
}

export class SecretDecryptionError extends SecretError {
  constructor(provider: string, path: string) {
    super(
      'decryption_failed',
      `No se pudo descifrar ${provider}/${path}: datos manipulados o fila que no corresponde a esa ruta`,
    );
    this.name = 'SecretDecryptionError';
  }
}

/**
 * Fallo del proveedor (sin conexión, permiso denegado, respuesta inesperada…). El motivo es
 * el tipo de fallo o el estado HTTP: nunca el cuerpo de la respuesta ni credenciales.
 */
export class SecretProviderError extends SecretError {
  constructor(provider: string, path: string | undefined, reason: string) {
    super(
      'provider_error',
      path === undefined
        ? `Proveedor de secretos ${provider}: ${reason}`
        : `Proveedor de secretos ${provider} (${path}): ${reason}`,
    );
    this.name = 'SecretProviderError';
  }
}
