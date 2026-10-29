/** Error del escaneo con un mensaje apto para guardarse y mostrarse (sin secretos). */
export class ScanError extends Error {}

/**
 * No se escanea por un motivo conocido (límites, sudoers, sin BDs de paquetes…): el asset queda
 * `skipped` con el motivo y el job termina bien.
 */
export class SkipScan extends Error {}
