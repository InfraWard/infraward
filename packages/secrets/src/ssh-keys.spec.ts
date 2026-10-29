import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateSshKeyPair,
  parseSshPublicKey,
  sshPublicKeyFingerprint,
} from './ssh-keys.js';

const COMMENT = 'inventory@infraward:3f1c2a9e-0000-4000-8000-000000000001';

describe('ssh-keys', () => {
  it('genera una ed25519 en formato OpenSSH con la pública como línea de authorized_keys', () => {
    const { privateKey, publicKey } = generateSshKeyPair(COMMENT);
    expect(privateKey).toMatch(
      /^-----BEGIN OPENSSH PRIVATE KEY-----\n([A-Za-z0-9+/=]{1,70}\n)+-----END OPENSSH PRIVATE KEY-----\n$/,
    );
    expect(publicKey).toMatch(
      new RegExp(
        `^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5[A-Za-z0-9+/]+=* ${COMMENT}$`,
      ),
    );
  });

  it('cada llamada genera un par distinto', () => {
    const a = generateSshKeyPair(COMMENT);
    const b = generateSshKeyPair(COMMENT);
    expect(a.publicKey).not.toBe(b.publicKey);
    expect(a.privateKey).not.toBe(b.privateKey);
  });

  it('ssh-keygen lee la privada y deriva la misma pública', () => {
    const { privateKey, publicKey } = generateSshKeyPair(COMMENT);
    const dir = mkdtempSync(join(tmpdir(), 'ssh-keys-'));
    try {
      const file = join(dir, 'id');
      writeFileSync(file, privateKey, { mode: 0o600 });
      const derived = execFileSync('ssh-keygen', ['-y', '-f', file])
        .toString()
        .trim();
      expect(derived).toBe(publicKey);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it('la huella coincide con la de ssh-keygen -lf', () => {
    const { publicKey } = generateSshKeyPair(COMMENT);
    const dir = mkdtempSync(join(tmpdir(), 'ssh-keys-'));
    try {
      const file = join(dir, 'id.pub');
      writeFileSync(file, publicKey);
      const expected = execFileSync('ssh-keygen', ['-lf', file])
        .toString()
        .split(' ')[1];
      expect(sshPublicKeyFingerprint(publicKey)).toBe(expected);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it('parseSshPublicKey rechaza líneas con el tipo cambiado o mal formadas', () => {
    const { publicKey } = generateSshKeyPair(COMMENT);
    const [, blob] = publicKey.split(' ');
    expect(parseSshPublicKey(publicKey)).toEqual({
      type: 'ssh-ed25519',
      blob,
      comment: COMMENT,
    });
    expect(parseSshPublicKey(`ssh-rsa ${blob}`)).toBeNull();
    expect(parseSshPublicKey('ssh-ed25519 no es base64!')).toBeNull();
    expect(parseSshPublicKey('')).toBeNull();
    expect(() => sshPublicKeyFingerprint('basura')).toThrow();
  });
});
