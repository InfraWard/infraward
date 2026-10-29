import {
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from 'node:crypto';

/** RFC 6238 con los parámetros que entiende cualquier app de autenticación. */
export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
/** Pasos de tolerancia a cada lado (desfase de reloj del móvil). */
export const TOTP_WINDOW = 1;
/** 160 bits, el tamaño de HMAC-SHA1 (RFC 4226 §4). */
const SECRET_BYTES = 20;

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.replace(/[\s=-]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index < 0) throw new TypeError('Base32 no válido');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Secreto TOTP nuevo, en base32 (lo que se guarda cifrado y lo que enseña el alta). */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(SECRET_BYTES));
}

export function totpStep(nowMs: number): number {
  return Math.floor(nowMs / 1000 / TOTP_PERIOD_SECONDS);
}

/** Código HOTP (RFC 4226) del contador `step`, con `digits` cifras. */
export function hotp(
  secret: Buffer,
  step: number,
  digits = TOTP_DIGITS,
  algorithm: 'sha1' | 'sha256' | 'sha512' = 'sha1',
): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac(algorithm, secret).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

/**
 * Comprueba un código TOTP en la ventana de ±TOTP_WINDOW pasos y devuelve el paso con el que
 * coincide, o null. Solo valen los pasos posteriores a `lastStep` (anti-replay: un código
 * aceptado no vuelve a valer). Recorre siempre toda la ventana (tiempo constante).
 */
export function verifyTotp(
  secretBase32: string,
  code: string,
  options: { nowMs?: number; lastStep?: number | null } = {},
): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const secret = base32Decode(secretBase32);
  const current = totpStep(options.nowMs ?? Date.now());
  const given = Buffer.from(code);
  let matched: number | null = null;
  for (let step = current - TOTP_WINDOW; step <= current + TOTP_WINDOW; step++) {
    const expected = Buffer.from(hotp(secret, step));
    if (timingSafeEqual(expected, given) && matched === null) matched = step;
  }
  if (matched === null) return null;
  if (options.lastStep !== null && options.lastStep !== undefined && matched <= options.lastStep)
    return null;
  return matched;
}

/** URI `otpauth://totp/…` del QR (formato de Google Authenticator, que entienden todas). */
export function otpauthUri(secretBase32: string, account: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/** Alfabeto de los códigos de recuperación: base32 sin 0/O ni 1/I/L (se leen y teclean bien). */
const RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

/** Código de recuperación de 16 caracteres (≈ 79 bits) como `xxxx-xxxx-xxxx-xxxx`. */
export function generateRecoveryCode(): string {
  let raw = '';
  for (let i = 0; i < 16; i++)
    raw += RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)];
  return raw.match(/.{4}/g)!.join('-').toLowerCase();
}

/** Forma canónica de un código de recuperación tecleado (sin guiones ni espacios, mayúsculas). */
export function normalizeRecoveryCode(code: string): string | null {
  const clean = code.replace(/[\s-]/g, '').toUpperCase();
  if (clean.length !== 16) return null;
  for (const char of clean) if (!RECOVERY_ALPHABET.includes(char)) return null;
  return clean;
}

export function hashRecoveryCode(normalized: string): Buffer {
  return createHash('sha256').update(normalized, 'utf8').digest();
}
