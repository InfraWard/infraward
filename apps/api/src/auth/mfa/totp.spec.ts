import { describe, expect, it } from 'vitest';
import {
  base32Decode,
  base32Encode,
  generateRecoveryCode,
  generateTotpSecret,
  hashRecoveryCode,
  hotp,
  normalizeRecoveryCode,
  otpauthUri,
  totpStep,
  verifyTotp,
} from './totp.js';

// Secretos de los vectores de prueba del RFC 6238 (apéndice B).
const SHA1 = Buffer.from('12345678901234567890');
const SHA256 = Buffer.from('12345678901234567890123456789012');
const SHA512 = Buffer.from(
  '1234567890123456789012345678901234567890123456789012345678901234',
);

describe('TOTP (RFC 6238)', () => {
  it.each([
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ])('vector del RFC en T=%i', (t, sha1, sha256, sha512) => {
    const step = totpStep(t * 1000);
    expect(hotp(SHA1, step, 8, 'sha1')).toBe(sha1);
    expect(hotp(SHA256, step, 8, 'sha256')).toBe(sha256);
    expect(hotp(SHA512, step, 8, 'sha512')).toBe(sha512);
  });

  it('base32 de ida y vuelta (y el del RFC 4648)', () => {
    expect(base32Encode(Buffer.from('foobar'))).toBe('MZXW6YTBOI');
    expect(base32Decode('MZXW6YTBOI').toString()).toBe('foobar');
    expect(base32Decode('mzxw 6ytb-oi======').toString()).toBe('foobar');
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Decode(secret)).toHaveLength(20);
  });

  it('acepta ±1 paso y devuelve el paso usado', () => {
    const secret = base32Encode(SHA1);
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    for (const delta of [-1, 0, 1]) {
      const code = hotp(SHA1, step + delta);
      expect(verifyTotp(secret, code, { nowMs: now })).toBe(step + delta);
    }
    expect(verifyTotp(secret, hotp(SHA1, step + 2), { nowMs: now })).toBeNull();
    expect(verifyTotp(secret, hotp(SHA1, step - 2), { nowMs: now })).toBeNull();
  });

  it('rechaza un código ya usado (mismo paso o anterior) y los mal formados', () => {
    const secret = base32Encode(SHA1);
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    const code = hotp(SHA1, step);
    expect(verifyTotp(secret, code, { nowMs: now, lastStep: step })).toBeNull();
    expect(verifyTotp(secret, code, { nowMs: now, lastStep: step + 1 })).toBeNull();
    expect(verifyTotp(secret, code, { nowMs: now, lastStep: step - 1 })).toBe(step);
    expect(verifyTotp(secret, hotp(SHA1, step - 1), { nowMs: now, lastStep: step })).toBeNull();
    for (const bad of ['', '12345', '1234567', 'abcdef', ' 123456', '12345a'])
      expect(verifyTotp(secret, bad, { nowMs: now })).toBeNull();
  });

  it('URI otpauth con issuer, cuenta y parámetros', () => {
    const uri = otpauthUri('JBSWY3DPEHPK3PXP', 'ana@example.com', 'InfraWard');
    expect(uri).toBe(
      'otpauth://totp/InfraWard%3Aana%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=InfraWard&algorithm=SHA1&digits=6&period=30',
    );
  });
});

describe('códigos de recuperación', () => {
  it('formato, normalización y hash estable', () => {
    const code = generateRecoveryCode();
    expect(code).toMatch(/^[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}$/);
    const normalized = normalizeRecoveryCode(code)!;
    expect(normalizeRecoveryCode(code.toUpperCase().replace(/-/g, ' '))).toBe(normalized);
    expect(hashRecoveryCode(normalized).equals(hashRecoveryCode(normalized))).toBe(true);
    expect(new Set(Array.from({ length: 200 }, generateRecoveryCode)).size).toBe(200);
  });

  it('rechaza longitudes o caracteres que no son del alfabeto', () => {
    expect(normalizeRecoveryCode('abcd-efgh-jkmn')).toBeNull();
    expect(normalizeRecoveryCode('abcd-efgh-jkmn-pq01')).toBeNull();
    expect(normalizeRecoveryCode('123456')).toBeNull();
  });
});
