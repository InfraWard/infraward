import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  fingerprintOf,
  HostKeyMismatchError,
  hostKeyAlgorithms,
  knownHostsLine,
  parseKeyscan,
  selectHostKey,
  type ScannedHostKey,
} from './host-keys.js';

/** Blob SSH (`string tipo` + `string clave`) de una ed25519 aleatoria. */
function ed25519Blob(): string {
  const { publicKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url');
  const str = (b: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    return Buffer.concat([len, b]);
  };
  return Buffer.concat([str(Buffer.from('ssh-ed25519')), str(raw)]).toString(
    'base64',
  );
}

/** Blob con el tipo embebido correcto pero contenido falso (para RSA/ECDSA basta). */
function fakeBlob(keyType: string, seed: string): string {
  const type = Buffer.from(keyType);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(type.length);
  return Buffer.concat([len, type, Buffer.from(seed)]).toString('base64');
}

const ED = ed25519Blob();
const RSA = fakeBlob('ssh-rsa', 'rsa');
const ECDSA = fakeBlob('ecdsa-sha2-nistp256', 'ecdsa');
const KEYSCAN = [
  '# 127.0.0.1:22 SSH-2.0-OpenSSH_9.6',
  `127.0.0.1 ssh-rsa ${RSA}`,
  `127.0.0.1 ecdsa-sha2-nistp256 ${ECDSA}`,
  `127.0.0.1 ssh-ed25519 ${ED}`,
  '127.0.0.1 ssh-dss AAAAB3NzaC1kc3M=',
  `127.0.0.1 ssh-ed25519 ${RSA}`,
  'basura',
  '',
].join('\n');

describe('host keys', () => {
  const scanned = parseKeyscan(KEYSCAN);
  const byType = (t: string) => scanned.find((k) => k.type === t)!;

  it('la huella coincide con la de ssh-keygen -lf', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hk-'));
    try {
      const file = join(dir, 'key.pub');
      writeFileSync(file, `ssh-ed25519 ${ED} test\n`);
      const out = execFileSync('ssh-keygen', ['-lf', file]).toString();
      expect(out.split(' ')[1]).toBe(fingerprintOf(ED));
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it('parseKeyscan ignora comentarios, tipos no admitidos y blobs que no casan con su tipo', () => {
    expect(scanned.map((k) => [k.keyType, k.type])).toEqual([
      ['ssh-rsa', 'RSA'],
      ['ecdsa-sha2-nistp256', 'ECDSA'],
      ['ssh-ed25519', 'ED25519'],
    ]);
    expect(
      scanned.every((k) => /^SHA256:[A-Za-z0-9+/]{43}$/.test(k.fingerprint)),
    ).toBe(true);
  });

  it('con huella fijada solo vale esa; si cambió, aborta', () => {
    const pinned = byType('RSA').fingerprint;
    expect(selectHostKey(scanned, pinned, []).type).toBe('RSA');
    // La fijada manda aunque el script reporte otras.
    expect(
      selectHostKey(scanned, pinned, [
        { type: 'ED25519', fingerprint: byType('ED25519').fingerprint },
      ]).type,
    ).toBe('RSA');
    expect(() =>
      selectHostKey(scanned, `SHA256:${'x'.repeat(43)}`, []),
    ).toThrow(/ha cambiado/);
  });

  it('sin huella fijada exige una de las reportadas por el script (preferencia ed25519)', () => {
    const reported = [
      { type: 'RSA' as const, fingerprint: byType('RSA').fingerprint },
      { type: 'ECDSA' as const, fingerprint: byType('ECDSA').fingerprint },
    ];
    expect(selectHostKey(scanned, null, reported).type).toBe('ECDSA');
    const intruder = parseKeyscan(`h ssh-ed25519 ${ed25519Blob()}`);
    expect(() => selectHostKey(intruder, null, reported)).toThrow(
      HostKeyMismatchError,
    );
  });

  it('camino manual (sin reportadas): TOFU con preferencia ed25519', () => {
    expect(selectHostKey(scanned, null, []).type).toBe('ED25519');
    expect(() => selectHostKey([], null, [])).toThrow(/ninguna host key/);
  });

  it('known_hosts y algoritmos', () => {
    const ed = byType('ED25519');
    expect(knownHostsLine('10.0.0.1', 22, ed)).toBe(
      `10.0.0.1 ssh-ed25519 ${ED}\n`,
    );
    expect(knownHostsLine('10.0.0.1', 2222, ed)).toBe(
      `[10.0.0.1]:2222 ssh-ed25519 ${ED}\n`,
    );
    expect(hostKeyAlgorithms(ed)).toBe('ssh-ed25519');
    expect(hostKeyAlgorithms(byType('RSA'))).toBe('rsa-sha2-512,rsa-sha2-256');
    expect(hostKeyAlgorithms(byType('ECDSA') as ScannedHostKey)).toBe(
      'ecdsa-sha2-nistp256',
    );
  });
});
