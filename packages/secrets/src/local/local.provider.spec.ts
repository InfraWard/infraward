import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { MemoryLocalSecretStore } from '../testing.js';
import { LocalSecretProvider } from './local.provider.js';
import { MasterKey } from './master-key.js';

const PRIVATE_KEY =
  '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA-centinela-ñ\n-----END OPENSSH PRIVATE KEY-----\n';

describe('LocalSecretProvider', () => {
  let store: MemoryLocalSecretStore;
  let key: MasterKey;
  let provider: LocalSecretProvider;

  beforeEach(() => {
    store = new MemoryLocalSecretStore();
    key = new MasterKey(randomBytes(32));
    provider = new LocalSecretProvider(store, key);
  });

  it('cifra y descifra (ida y vuelta) con varios campos', async () => {
    await provider.set('assets/a1/ssh', {
      private_key: PRIVATE_KEY,
      public_key: 'ssh-ed25519 AAAA',
    });
    expect(await provider.get('assets/a1/ssh', 'private_key')).toBe(
      PRIVATE_KEY,
    );
    expect(await provider.get('assets/a1/ssh', 'public_key')).toBe(
      'ssh-ed25519 AAAA',
    );
  });

  it('guarda solo texto cifrado, con el id de la clave', async () => {
    await provider.set('a', { v: PRIVATE_KEY });
    const row = store.rows.get('a')!;
    expect(row.keyId).toBe(key.id);
    expect(row.iv).toHaveLength(12);
    expect(row.authTag).toHaveLength(16);
    const raw = Buffer.from(row.ciphertext).toString('latin1');
    expect(raw).not.toContain('centinela');
    expect(raw).not.toContain('PRIVATE KEY');
  });

  it('usa un IV distinto en cada escritura', async () => {
    await provider.set('a', { v: 'x' });
    const first = store.rows.get('a')!;
    await provider.set('a', { v: 'x' });
    const second = store.rows.get('a')!;
    expect(Buffer.from(second.iv).equals(Buffer.from(first.iv))).toBe(false);
    expect(
      Buffer.from(second.ciphertext).equals(Buffer.from(first.ciphertext)),
    ).toBe(false);
  });

  it('sin campo devuelve el único campo; con varios exige indicarlo', async () => {
    await provider.set('one', { token: 't' });
    await provider.set('two', { a: '1', b: '2' });
    expect(await provider.get('one')).toBe('t');
    await expect(provider.get('two')).rejects.toMatchObject({
      code: 'field_not_found',
    });
  });

  it('campo o ruta inexistentes', async () => {
    await provider.set('a', { v: 'x' });
    await expect(provider.get('a', 'otro')).rejects.toMatchObject({
      code: 'field_not_found',
      message: 'El secreto local/a no tiene el campo otro',
    });
    await expect(provider.get('a', 'constructor')).rejects.toMatchObject({
      code: 'field_not_found',
    });
    await expect(provider.get('nada')).rejects.toMatchObject({
      code: 'not_found',
    });
  });

  it('con otra clave cargada dice con cuál se cifró y cuál está cargada', async () => {
    await provider.set('a', { v: 'x' });
    const other = new MasterKey(randomBytes(32));
    await expect(
      new LocalSecretProvider(store, other).get('a', 'v'),
    ).rejects.toMatchObject({
      code: 'key_mismatch',
      message: `El secreto local/a se cifró con la clave ${key.id} y está cargada la ${other.id}`,
    });
  });

  it.each(['ciphertext', 'authTag', 'iv'] as const)(
    'detecta la manipulación de %s',
    async (column) => {
      await provider.set('a', { v: PRIVATE_KEY });
      store.rows.get('a')![column][0] ^= 0x01;
      await expect(provider.get('a', 'v')).rejects.toMatchObject({
        code: 'decryption_failed',
      });
    },
  );

  it('si se intercambian dos filas, falla en lugar de devolver el secreto de otra ruta (AAD)', async () => {
    await provider.set('assets/server-a/ssh', { private_key: 'clave-de-A' });
    await provider.set('assets/server-b/ssh', { private_key: 'clave-de-B' });
    const a = store.rows.get('assets/server-a/ssh')!;
    const b = store.rows.get('assets/server-b/ssh')!;
    store.rows.set('assets/server-a/ssh', { ...b, path: a.path });
    store.rows.set('assets/server-b/ssh', { ...a, path: b.path });
    await expect(
      provider.get('assets/server-a/ssh', 'private_key'),
    ).rejects.toMatchObject({ code: 'decryption_failed' });
    await expect(
      provider.get('assets/server-b/ssh', 'private_key'),
    ).rejects.toMatchObject({ code: 'decryption_failed' });
  });

  it('rechaza secretos vacíos o con valores que no son texto', async () => {
    await expect(provider.set('a', {})).rejects.toThrow(TypeError);
    await expect(
      provider.set('a', { v: 1 as unknown as string }),
    ).rejects.toThrow(TypeError);
  });

  it('delete borra la ruta entera y dice si existía', async () => {
    await provider.set('a', { v: 'x', w: 'y' });
    expect(await provider.delete('a')).toBe(true);
    await expect(provider.get('a', 'v')).rejects.toMatchObject({
      code: 'not_found',
    });
    expect(await provider.delete('a')).toBe(false);
  });

  it('healthCheck refleja el almacén', async () => {
    expect(await provider.healthCheck()).toBe(true);
    store.failPing = true;
    expect(await provider.healthCheck()).toBe(false);
  });
});
