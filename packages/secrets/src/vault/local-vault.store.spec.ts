import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { beforeEach, describe, expect, it } from 'vitest';
import { SecretError } from '../errors.js';
import { LocalSecretProvider } from '../local/local.provider.js';
import { MasterKey } from '../local/master-key.js';
import { MemoryLocalSecretStore } from '../testing.js';
import {
  LocalVaultStore,
  type EncryptedVaultVersion,
  type VaultRowStore,
} from './local-vault.store.js';
import { createVaultStore } from './vault-config.js';
import { vaultEntryPath, vaultRefPath, vaultSecretRef } from './vault-store.js';

class MemoryVaultRows implements VaultRowStore {
  readonly rows: EncryptedVaultVersion[] = [];

  async find(path: string, version?: number) {
    const mine = this.rows.filter((r) => r.path === path);
    if (version !== undefined) return mine.find((r) => r.version === version) ?? null;
    return mine.sort((a, b) => b.version - a.version)[0] ?? null;
  }
  async list(path: string) {
    return this.rows
      .filter((r) => r.path === path)
      .map((r) => ({ version: r.version, createdAt: r.createdAt ?? new Date() }));
  }
  async append(path: string, build: (v: number) => EncryptedVaultVersion, keep: number) {
    const max = Math.max(0, ...this.rows.filter((r) => r.path === path).map((r) => r.version));
    this.rows.push({ ...build(max + 1), createdAt: new Date() });
    for (let i = this.rows.length - 1; i >= 0; i--) {
      if (this.rows[i].path === path && this.rows[i].version <= max + 1 - keep)
        this.rows.splice(i, 1);
    }
    return max + 1;
  }
  async deleteAll(path: string) {
    const before = this.rows.length;
    for (let i = this.rows.length - 1; i >= 0; i--) {
      if (this.rows[i].path === path) this.rows.splice(i, 1);
    }
    return this.rows.length < before;
  }
  async ping() {}
}

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(SecretError);
    return (e as SecretError).code;
  }
  throw new Error('no falló');
}

const SECRET = `contraseña-centinela-${randomBytes(6).toString('hex')}-ñ`;
const PATH = vaultEntryPath('0b9d6f3e-8a5c-4d1e-9f2a-3c4b5d6e7f80');

describe('LocalVaultStore', () => {
  let rows: MemoryVaultRows;
  let key: MasterKey;
  let store: LocalVaultStore;

  beforeEach(() => {
    rows = new MemoryVaultRows();
    key = new MasterKey(randomBytes(32));
    store = new LocalVaultStore(rows, key, 3);
  });

  it('guarda versiones, lee la actual o una concreta', async () => {
    expect(await store.put(PATH, `${SECRET}-1`)).toBe(1);
    expect(await store.put(PATH, `${SECRET}-2`)).toBe(2);
    expect(await store.get(PATH)).toEqual({ value: `${SECRET}-2`, version: 2 });
    expect(await store.get(PATH, 1)).toEqual({ value: `${SECRET}-1`, version: 1 });
    expect((await store.versions(PATH)).map((v) => v.version)).toEqual([2, 1]);
  });

  it('conserva solo las últimas maxVersions', async () => {
    for (let i = 1; i <= 5; i++) await store.put(PATH, `${SECRET}-${i}`);
    expect((await store.versions(PATH)).map((v) => v.version)).toEqual([5, 4, 3]);
    expect(await code(store.get(PATH, 2))).toBe('not_found');
  });

  it('solo texto cifrado en las filas, con el id de la clave', async () => {
    await store.put(PATH, SECRET);
    const row = rows.rows[0];
    expect(row.keyId).toBe(key.id);
    const raw = Buffer.concat([row.iv, row.ciphertext, row.authTag]).toString('latin1');
    expect(raw).not.toContain('centinela');
  });

  it('una fila movida a otra ruta o versión no descifra (AAD)', async () => {
    await store.put(PATH, SECRET);
    await store.put(PATH, 'otra');
    // Cambiar el número de versión de la fila 1 a la 2 (y quitar la 2): debe fallar.
    rows.rows.splice(1, 1);
    rows.rows[0].version = 2;
    expect(await code(store.get(PATH))).toBe('decryption_failed');
    const other = vaultEntryPath('1b9d6f3e-8a5c-4d1e-9f2a-3c4b5d6e7f80');
    rows.rows[0] = { ...rows.rows[0], path: other, version: 1 };
    expect(await code(store.get(other))).toBe('decryption_failed');
  });

  it('con otra clave: key_mismatch; destroy borra todo', async () => {
    await store.put(PATH, SECRET);
    const other = new LocalVaultStore(rows, new MasterKey(randomBytes(32)), 3);
    expect(await code(other.get(PATH))).toBe('key_mismatch');
    expect(await store.destroy(PATH)).toBe(true);
    expect(await store.destroy(PATH)).toBe(false);
    expect(await code(store.get(PATH))).toBe('not_found');
  });

  it('el texto cifrado del proveedor local de la app no descifra aquí aunque se use la misma clave', async () => {
    // Defensa en profundidad: AAD distinta (`infraward:local:v1` frente a `infraward:vault:v1`).
    const appStore = new MemoryLocalSecretStore();
    await new LocalSecretProvider(appStore, key).set(PATH, { password: SECRET });
    const row = appStore.rows.get(PATH)!;
    rows.rows.push({ ...row, version: 1 } as EncryptedVaultVersion);
    expect(await code(store.get(PATH))).toBe('decryption_failed');
  });

  it('no enseña la clave al inspeccionarlo ni serializarlo', () => {
    const text = `${inspect(store)} ${JSON.stringify(store)}`;
    expect(text).not.toContain(key.bytes().toString('base64'));
  });
});

describe('referencias de la caja fuerte', () => {
  it('ruta por id y referencia con su proveedor', () => {
    const ref = vaultSecretRef('vault-local', PATH);
    expect(ref).toBe(`secret://vault-local/${PATH}#password`);
    expect(vaultRefPath(ref, 'vault-local')).toBe(PATH);
    expect(() => vaultRefPath(ref, 'vault-openbao')).toThrow(/vault-openbao/);
    expect(() => vaultEntryPath('../x')).toThrow();
  });
});

describe('createVaultStore', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vault-'));
  const keyFile = (name: string, bytes = randomBytes(32)) => {
    const file = join(dir, name);
    writeFileSync(file, bytes.toString('base64'));
    return file;
  };
  const noDb = () => {
    throw new Error('sin BD');
  };

  it('none: sin almacén', () => {
    expect(createVaultStore({ kind: 'none' }, noDb)).toBeNull();
  });

  it('local: exige su clave y que no sea la de la app', () => {
    expect(() => createVaultStore({ kind: 'local' }, noDb)).toThrow(
      /VAULT_LOCAL_MASTER_KEY/,
    );
    const shared = randomBytes(32);
    const a = keyFile('a.key', shared);
    const b = keyFile('b.key', shared);
    expect(() =>
      createVaultStore({ kind: 'local', localKey: { file: a }, appLocalKey: { file: b } }, noDb),
    ).toThrow(/distinta de la de SECRETS_LOCAL_MASTER_KEY/);
    const store = createVaultStore(
      { kind: 'local', localKey: { file: keyFile('c.key') }, appLocalKey: { file: a } },
      noDb,
    );
    expect(store?.provider).toBe('vault-local');
    expect(store?.maxVersions).toBe(10);
  });

  it('openbao: su AppRole y un prefijo fuera del de la app', () => {
    const openbao = { addr: 'http://127.0.0.1:8200', roleId: 'vault-role', secretId: 's' };
    expect(() => createVaultStore({ kind: 'openbao', openbao: { ...openbao, roleId: '' } }, noDb)).toThrow(
      /VAULT_OPENBAO_ROLE_ID/,
    );
    expect(() =>
      createVaultStore(
        { kind: 'openbao', openbao, appOpenbao: { roleId: 'vault-role' } },
        noDb,
      ),
    ).toThrow(/su propia AppRole/);
    for (const kvPrefix of ['infraward', 'infraward/vault']) {
      expect(() =>
        createVaultStore({ kind: 'openbao', openbao: { ...openbao, kvPrefix } }, noDb),
      ).toThrow(/fuera del prefijo de la app/);
    }
    expect(() =>
      createVaultStore(
        { kind: 'openbao', openbao, appOpenbao: { kvPrefix: 'infraward-vault/app' } },
        noDb,
      ),
    ).toThrow(/fuera del prefijo/);
    const store = createVaultStore(
      { kind: 'openbao', openbao, appOpenbao: { roleId: 'app-role', kvPrefix: 'infraward' } },
      noDb,
    );
    expect(store?.provider).toBe('vault-openbao');
    expect(JSON.stringify(store)).not.toContain('"s"');
  });

  it('maxVersions fuera de rango', () => {
    expect(() =>
      createVaultStore({ kind: 'local', maxVersions: 0, localKey: { file: keyFile('d.key') } }, noDb),
    ).toThrow(/VAULT_MAX_VERSIONS/);
  });
});
