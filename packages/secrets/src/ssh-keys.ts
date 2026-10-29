import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';

const KEY_TYPE = 'ssh-ed25519';

/** Par de claves SSH: la privada en formato OpenSSH y la pública en una línea `authorized_keys`. */
export interface SshKeyPair {
  privateKey: string;
  publicKey: string;
}

/**
 * Genera un par ed25519 con `node:crypto` y lo serializa a formato OpenSSH (`openssh-key-v1`
 * sin cifrar, el que lee `ssh -i`). La privada solo debe ir al proveedor de secretos.
 */
export function generateSshKeyPair(comment: string): SshKeyPair {
  const { privateKey } = generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  const seed = Buffer.from(jwk.d!, 'base64url');
  const pub = Buffer.from(jwk.x!, 'base64url');
  try {
    const publicBlob = Buffer.concat([
      sshString(Buffer.from(KEY_TYPE)),
      sshString(pub),
    ]);
    return {
      privateKey: encodePrivateKey(seed, pub, publicBlob, comment),
      publicKey: `${KEY_TYPE} ${publicBlob.toString('base64')} ${comment}`,
    };
  } finally {
    seed.fill(0);
  }
}

/** Clave pública SSH en una línea (`<tipo> <base64> [comentario]`), ya validada. */
export interface SshPublicKey {
  type: string;
  /** Blob de la clave en base64 (lo que se firma y de lo que sale la huella). */
  blob: string;
  comment: string;
}

const PUBLIC_KEY_LINE =
  /^(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa|[a-z0-9-]+-cert-v01@openssh\.com) ([A-Za-z0-9+/]+={0,2})(?: (.*))?$/;

/** Parsea una línea de clave pública (o de certificado); null si no tiene esa forma. */
export function parseSshPublicKey(line: string): SshPublicKey | null {
  const m = PUBLIC_KEY_LINE.exec(line.trim());
  if (!m) return null;
  const blob = Buffer.from(m[2], 'base64');
  // El blob empieza por el propio tipo: si no coincide, la línea está manipulada.
  if (blob.length < 4) return null;
  const len = blob.readUInt32BE(0);
  if (blob.subarray(4, 4 + len).toString('latin1') !== m[1]) return null;
  return { type: m[1], blob: m[2], comment: m[3] ?? '' };
}

/** Huella `SHA256:<base64 sin relleno>` de una clave pública, como la de `ssh-keygen -lf`. */
export function sshPublicKeyFingerprint(line: string): string {
  const key = parseSshPublicKey(line);
  if (!key) throw new Error('No es una clave pública SSH');
  const digest = createHash('sha256')
    .update(Buffer.from(key.blob, 'base64'))
    .digest('base64')
    .replace(/=+$/, '');
  return `SHA256:${digest}`;
}

function encodePrivateKey(
  seed: Buffer,
  pub: Buffer,
  publicBlob: Buffer,
  comment: string,
): string {
  const check = randomBytes(4);
  const secret = Buffer.concat([seed, pub]);
  const body = Buffer.concat([
    check,
    check,
    sshString(Buffer.from(KEY_TYPE)),
    sshString(pub),
    sshString(secret),
    sshString(Buffer.from(comment)),
  ]);
  // Relleno 1, 2, 3… hasta múltiplo del tamaño de bloque (8 sin cifrado).
  const padding = Buffer.from(
    Array.from({ length: (8 - (body.length % 8)) % 8 }, (_, i) => i + 1),
  );
  const blob = Buffer.concat([
    Buffer.from('openssh-key-v1\0'),
    sshString(Buffer.from('none')),
    sshString(Buffer.from('none')),
    sshString(Buffer.alloc(0)),
    uint32(1),
    sshString(publicBlob),
    sshString(Buffer.concat([body, padding])),
  ]);
  secret.fill(0);
  body.fill(0);
  const lines = blob.toString('base64').match(/.{1,70}/g)!;
  blob.fill(0);
  return [
    '-----BEGIN OPENSSH PRIVATE KEY-----',
    ...lines,
    '-----END OPENSSH PRIVATE KEY-----',
    '',
  ].join('\n');
}

/** `string` del protocolo SSH (RFC 4251): longitud uint32 + bytes. */
function sshString(data: Buffer): Buffer {
  return Buffer.concat([uint32(data.length), data]);
}

function uint32(value: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(value);
  return buf;
}
