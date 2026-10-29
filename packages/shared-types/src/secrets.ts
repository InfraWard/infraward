/** Prefijo de las referencias a secretos: `secret://<proveedor>/<ruta>#<campo>`. */
export const SECRET_REF_PREFIX = 'secret://';

/** Motivos por los que una referencia no resuelve. Nunca incluyen el valor del secreto. */
export const SECRET_ERROR_CODES = [
  'invalid_ref',
  'provider_not_configured',
  'not_found',
  'field_not_found',
  'key_mismatch',
  'decryption_failed',
  'provider_error',
] as const;
export type SecretErrorCode = (typeof SECRET_ERROR_CODES)[number];

/** Capacidades opcionales de un proveedor de secretos. */
export const SECRET_PROVIDER_CAPABILITIES = ['write', 'ssh_certificates'] as const;
export type SecretProviderCapability =
  (typeof SECRET_PROVIDER_CAPABILITIES)[number];

export interface SecretProviderInfo {
  id: string;
  healthy: boolean;
  capabilities: SecretProviderCapability[];
}

export interface CheckSecretRequest {
  ref: string;
}

/** Resultado de comprobar una referencia: si resuelve, nunca el valor. */
export interface CheckSecretResponse {
  ref: string;
  provider: string;
  resolves: boolean;
  error?: SecretErrorCode;
}
