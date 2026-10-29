import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { loadMasterKey, MasterKey } from './master-key.js';

const b64 = (n: number) => randomBytes(n).toString('base64');

function errorOf(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error('no lanzó');
}

describe('loadMasterKey', () => {
  it('carga una clave de 32 bytes en base64', () => {
    const key = loadMasterKey({ key: b64(32) });
    expect(key.bytes()).toHaveLength(32);
    expect(key.id).toMatch(/^[0-9a-f]{16}$/);
  });

  it('carga la clave desde un fichero, con salto de línea final', () => {
    const encoded = b64(32);
    const dir = mkdtempSync(join(tmpdir(), 'iw-key-'));
    const file = join(dir, 'master.key');
    writeFileSync(file, `${encoded}\n`, { mode: 0o600 });
    expect(loadMasterKey({ file }).id).toBe(loadMasterKey({ key: encoded }).id);
  });

  it('falla si no hay ninguna fuente', () => {
    expect(() => loadMasterKey({})).toThrow(
      /falta SECRETS_LOCAL_MASTER_KEY o SECRETS_LOCAL_MASTER_KEY_FILE/,
    );
    expect(() => loadMasterKey({ key: '', file: '' })).toThrow(/falta/);
  });

  it('falla si están las dos', () => {
    expect(() => loadMasterKey({ key: b64(32), file: '/x' })).toThrow(
      /solo una/,
    );
  });

  it.each([31, 33, 16, 64])('rechaza %i bytes sin mostrar el valor', (n) => {
    const value = b64(n);
    const error = errorOf(() => loadMasterKey({ key: value }));
    expect(error.message).toMatch(
      new RegExp(
        `SECRETS_LOCAL_MASTER_KEY: .*32 bytes \\(decodifica a ${n}\\)`,
      ),
    );
    expect(error.message).not.toContain(value);
  });

  it.each(['no es base64!', 'aGVsbG8', `${b64(32)}%`, `${b64(30)} ${b64(1)}`])(
    'rechaza base64 inválido sin mostrar el valor: %j',
    (value) => {
      const error = errorOf(() => loadMasterKey({ key: value }));
      expect(error.message).toBe(
        'SECRETS_LOCAL_MASTER_KEY: no es base64 válido',
      );
    },
  );

  it('dice de qué variable viene el error del fichero', () => {
    const dir = mkdtempSync(join(tmpdir(), 'iw-key-'));
    const file = join(dir, 'short.key');
    const value = b64(31);
    writeFileSync(file, value);
    const error = errorOf(() => loadMasterKey({ file }));
    expect(error.message).toMatch(/^SECRETS_LOCAL_MASTER_KEY_FILE: /);
    expect(error.message).not.toContain(value);
    expect(() => loadMasterKey({ file: join(dir, 'no-existe') })).toThrow(
      'SECRETS_LOCAL_MASTER_KEY_FILE: no se puede leer el fichero (ENOENT)',
    );
  });

  it('el id es estable para la misma clave y distinto entre claves', () => {
    const encoded = b64(32);
    expect(loadMasterKey({ key: encoded }).id).toBe(
      loadMasterKey({ key: encoded }).id,
    );
    expect(loadMasterKey({ key: b64(32) }).id).not.toBe(
      loadMasterKey({ key: encoded }).id,
    );
  });

  it('el id no es un prefijo del SHA-256 de la clave sin separación de dominio', async () => {
    const { createHash } = await import('node:crypto');
    const bytes = randomBytes(32);
    const key = new MasterKey(bytes);
    expect(createHash('sha256').update(bytes).digest('hex')).not.toContain(
      key.id,
    );
  });

  it('el material de la clave no sale al serializar ni inspeccionar', () => {
    const bytes = randomBytes(32);
    const key = new MasterKey(bytes);
    const outputs = [
      String(key),
      JSON.stringify(key),
      JSON.stringify({ key }),
      inspect(key),
      inspect({ nested: { key } }, { depth: 5, showHidden: true }),
    ];
    for (const out of outputs) {
      expect(out).toContain(key.id);
      expect(out).not.toContain(bytes.toString('base64'));
      expect(out).not.toContain(bytes.toString('hex'));
    }
  });
});
