/** Firmante de los certificados de la terminal (`TerminalCertSigner | null`; null = sin configurar). */
export const TERMINAL_SIGNER = Symbol('TERMINAL_SIGNER');

/** sha256 del secreto compartido con el gateway (`Buffer | null`; null = rutas internas apagadas). */
export const GATEWAY_SECRET_HASH = Symbol('GATEWAY_SECRET_HASH');
