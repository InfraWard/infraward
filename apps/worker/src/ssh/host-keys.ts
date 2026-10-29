import type { HostKeyFingerprint, HostKeyType } from '@infraward/shared-types';
import { createHash } from 'node:crypto';

/** Host key leída con `ssh-keyscan`. */
export interface ScannedHostKey {
  /** Algoritmo de la clave (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`). */
  keyType: string;
  /** Blob en base64, tal cual aparece en known_hosts. */
  blob: string;
  type: HostKeyType;
  /** `SHA256:…`, igual que `ssh-keygen -lf`. */
  fingerprint: string;
}

const TYPES: Record<string, HostKeyType> = {
  'ssh-ed25519': 'ED25519',
  'ecdsa-sha2-nistp256': 'ECDSA',
  'ecdsa-sha2-nistp384': 'ECDSA',
  'ecdsa-sha2-nistp521': 'ECDSA',
  'ssh-rsa': 'RSA',
};

/** Preferencia cuando hay varias candidatas. */
const PREFERENCE: HostKeyType[] = ['ED25519', 'ECDSA', 'RSA'];

/** Huella SHA256 de una clave pública, en el formato de OpenSSH (base64 sin relleno). */
export function fingerprintOf(blob: string): string {
  const digest = createHash('sha256')
    .update(Buffer.from(blob, 'base64'))
    .digest('base64');
  return `SHA256:${digest.replace(/=+$/, '')}`;
}

/** Interpreta la salida de `ssh-keyscan` (`<host> <tipo> <base64>` por línea). */
export function parseKeyscan(output: string): ScannedHostKey[] {
  const keys: ScannedHostKey[] = [];
  for (const line of output.split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    const [, keyType, blob] = line.trim().split(/\s+/);
    const type = keyType ? TYPES[keyType] : undefined;
    if (!type || !blob || !/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) continue;
    // El blob empieza por el propio tipo: si no coincide, la línea es basura.
    const embedded = Buffer.from(blob, 'base64');
    const len = embedded.length >= 4 ? embedded.readUInt32BE(0) : -1;
    if (embedded.subarray(4, 4 + len).toString() !== keyType) continue;
    keys.push({ keyType, blob, type, fingerprint: fingerprintOf(blob) });
  }
  return keys;
}

export class HostKeyMismatchError extends Error {}

/**
 * Elige la host key contra la que se conectará (con `StrictHostKeyChecking=yes`):
 * 1. Si el asset ya tiene huella fijada, solo vale esa (si cambió, se aborta).
 * 2. Si no, y el script reportó huellas, una de ellas (la verdad la dice el propio servidor,
 *    leída en local por el script; la keyscan podría venir de un intermediario).
 * 3. Sin huellas reportadas (alta manual): TOFU sobre lo que devuelve la keyscan.
 */
export function selectHostKey(
  scanned: ScannedHostKey[],
  pinned: string | null,
  reported: HostKeyFingerprint[],
): ScannedHostKey {
  if (scanned.length === 0) {
    throw new HostKeyMismatchError(
      'El servidor no ofreció ninguna host key compatible',
    );
  }
  if (pinned) {
    const match = scanned.find((k) => k.fingerprint === pinned);
    if (!match)
      throw new HostKeyMismatchError(
        `La host key del servidor ha cambiado (se esperaba ${pinned}); posible suplantación`,
      );
    return match;
  }
  if (reported.length > 0) {
    const allowed = new Set(reported.map((r) => r.fingerprint));
    const match = preferred(scanned.filter((k) => allowed.has(k.fingerprint)));
    if (!match)
      throw new HostKeyMismatchError(
        'La host key del servidor no coincide con ninguna de las que reportó el script de alta; posible suplantación',
      );
    return match;
  }
  return preferred(scanned)!;
}

function preferred(keys: ScannedHostKey[]): ScannedHostKey | undefined {
  return [...keys].sort(
    (a, b) => PREFERENCE.indexOf(a.type) - PREFERENCE.indexOf(b.type),
  )[0];
}

/** Línea de known_hosts para esa clave (`[host]:puerto` si no es el 22). */
export function knownHostsLine(
  host: string,
  port: number,
  key: ScannedHostKey,
): string {
  const name = port === 22 ? host : `[${host}]:${port}`;
  return `${name} ${key.keyType} ${key.blob}\n`;
}

/** Algoritmos de firma admitidos para esa clave (las RSA firman con rsa-sha2-*). */
export function hostKeyAlgorithms(key: ScannedHostKey): string {
  return key.keyType === 'ssh-rsa' ? 'rsa-sha2-512,rsa-sha2-256' : key.keyType;
}
