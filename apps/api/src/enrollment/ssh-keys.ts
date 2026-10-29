import { formatSecretRef, parseSecretRef } from '@infraward/secrets';

export { generateSshKeyPair, type SshKeyPair } from '@infraward/secrets';

/** Referencia donde se guarda la clave SSH de un asset (sin campo: guarda la ruta entera). */
export function sshKeySecretPath(provider: string, assetId: string): string {
  return formatSecretRef({ provider, path: `assets/${assetId}/ssh` });
}

/** `secret://p/ruta#campo` → `secret://p/ruta` (para borrar la ruta entera). */
export function secretBaseRef(ref: string): string {
  const { provider, path } = parseSecretRef(ref);
  return formatSecretRef({ provider, path });
}
