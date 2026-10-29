import 'reflect-metadata';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretError } from '../errors.js';
import { FakeOpenBao } from '../testing.js';
import { generateSshKeyPair } from '../ssh-keys.js';
import { loadOpenBaoConfig, type OpenBaoSource } from './openbao-config.js';
import { OpenBaoSecretProvider } from './openbao.provider.js';

const ADDR = 'http://127.0.0.1:8200';

function provider(bao: FakeOpenBao, extra: OpenBaoSource = {}) {
  return new OpenBaoSecretProvider(
    loadOpenBaoConfig({
      addr: ADDR,
      roleId: bao.roleId,
      secretId: bao.secretId,
      ...extra,
    }),
    bao.fetch,
  );
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

describe('loadOpenBaoConfig', () => {
  const base = { addr: ADDR, roleId: 'r', secretId: 's' };

  it('aplica valores por defecto', () => {
    const c = loadOpenBaoConfig({ ...base, addr: 'https://bao.example:8200/' });
    expect(c).toMatchObject({
      addr: 'https://bao.example:8200',
      kvMount: 'secret',
      kvPrefix: 'infraward',
      approleMount: 'approle',
      timeoutMs: 5000,
      sshMount: 'infraward-ssh',
      sshRole: 'inventory',
      insecureTransport: false,
    });
    expect(c.credentials.secretId()).toBe('s');
  });

  it('marca http:// hacia un host que no es loopback', () => {
    expect(
      loadOpenBaoConfig({ ...base, addr: 'http://bao:8200' }).insecureTransport,
    ).toBe(true);
    expect(
      loadOpenBaoConfig({ ...base, addr: 'http://localhost:8200' })
        .insecureTransport,
    ).toBe(false);
  });

  it('admite prefijo vacío y monta rutas sin barras sobrantes', () => {
    const c = loadOpenBaoConfig({ ...base, kvPrefix: '', kvMount: '/kv/' });
    expect(c.kvPrefix).toBe('');
    expect(c.kvMount).toBe('kv');
  });

  it.each([
    [{ addr: undefined }, /falta OPENBAO_ADDR/],
    [{ addr: 'no url' }, /OPENBAO_ADDR: no es una URL/],
    [{ addr: 'ftp://x' }, /http:\/\/ o https/],
    [{ addr: 'https://u:p@x' }, /sin usuario/],
    [{ roleId: '' }, /falta OPENBAO_ROLE_ID/],
    [
      { secretId: undefined },
      /falta OPENBAO_SECRET_ID_FILE o OPENBAO_SECRET_ID/,
    ],
    [{ secretIdFile: '/x' }, /solo una/],
    [{ kvPrefix: '../x' }, /OPENBAO_KV_PREFIX/],
    [{ approleMount: 'a b' }, /OPENBAO_APPROLE_MOUNT/],
    [{ timeoutMs: 10 }, /OPENBAO_TIMEOUT_MS/],
  ])('rechaza %j', (patch, error) => {
    expect(() => loadOpenBaoConfig({ ...base, ...patch })).toThrow(error);
  });

  it('lee el secret_id de un fichero y nunca lo muestra', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bao-'));
    const file = join(dir, 'secret-id');
    writeFileSync(file, 'sid-centinela\n');
    const c = loadOpenBaoConfig({
      addr: ADDR,
      roleId: 'r',
      secretIdFile: file,
    });
    expect(c.credentials.secretId()).toBe('sid-centinela');
    expect(String(c.credentials)).not.toContain('sid-centinela');
    expect(JSON.stringify(c)).not.toContain('sid-centinela');
    expect(inspect(c)).not.toContain('sid-centinela');

    writeFileSync(file, '  \n');
    expect(() =>
      loadOpenBaoConfig({ addr: ADDR, roleId: 'r', secretIdFile: file }),
    ).toThrow(/vacío/);
    expect(() =>
      loadOpenBaoConfig({
        addr: ADDR,
        roleId: 'r',
        secretIdFile: join(dir, 'no'),
      }),
    ).toThrow(/no se puede leer el fichero \(ENOENT\)/);
  });
});

describe('OpenBaoSecretProvider', () => {
  let bao: FakeOpenBao;

  beforeEach(() => {
    bao = new FakeOpenBao();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('guarda y lee bajo el prefijo, con y sin campo', async () => {
    const p = provider(bao);
    await p.set('assets/a/ssh', { private_key: 'k', public_key: 'pub' });
    expect([...bao.kv.keys()]).toEqual(['infraward/assets/a/ssh']);
    expect(await p.get('assets/a/ssh', 'private_key')).toBe('k');
    expect(await code(p.get('assets/a/ssh'))).toBe('field_not_found');
    expect(await code(p.get('assets/a/ssh', 'otro'))).toBe('field_not_found');

    await p.set('solo', { token: 't' });
    expect(await p.get('solo')).toBe('t');
  });

  it('sin prefijo usa la ruta tal cual', async () => {
    const p = provider(bao, { kvPrefix: '' });
    await p.set('infra/pve1', { api_token: 'x' });
    expect(bao.kv.has('infra/pve1')).toBe(true);
    expect(await p.get('infra/pve1', 'api_token')).toBe('x');
  });

  it('no encontrado, versión borrada y campo que no es texto', async () => {
    const p = provider(bao);
    expect(await code(p.get('nada', 'x'))).toBe('not_found');
    bao.kv.set('infraward/borrado', { data: null });
    expect(await code(p.get('borrado', 'x'))).toBe('not_found');
    bao.kv.set('infraward/num', { data: { n: 1 } });
    expect(await code(p.get('num', 'n'))).toBe('provider_error');
  });

  it('borra la ruta entera y dice si existía', async () => {
    const p = provider(bao);
    await p.set('a', { x: '1' });
    expect(await p.delete('a')).toBe(true);
    expect(bao.kv.size).toBe(0);
    expect(await p.delete('a')).toBe(false);
  });

  it('rechaza secretos vacíos o con valores que no son texto', async () => {
    const p = provider(bao);
    await expect(p.set('a', {})).rejects.toThrow(TypeError);
    await expect(p.set('a', { x: 1 as unknown as string })).rejects.toThrow(
      TypeError,
    );
  });

  it('hace un único login para peticiones concurrentes', async () => {
    const p = provider(bao);
    await p.set('a', { x: '1' });
    bao.logins = 0;
    const q = provider(bao);
    await Promise.all([q.get('a'), q.get('a'), q.get('a')]);
    expect(bao.logins).toBe(1);
  });

  it('renueva antes de caducar y vuelve a hacer login cerca de token_max_ttl', async () => {
    vi.useFakeTimers();
    bao.tokenTtl = 60;
    bao.tokenMaxTtl = 100;
    const p = provider(bao);
    await p.set('a', { x: '1' });
    expect(bao.logins).toBe(1);

    await vi.advanceTimersByTimeAsync(41_000); // 2/3 de 60 s
    expect(bao.renewals).toBe(1);
    expect(bao.logins).toBe(1);

    // En t=80 la renovación ya solo llega a t=100 (20 s < 30 s): nuevo login.
    await vi.advanceTimersByTimeAsync(40_000);
    expect(bao.renewals).toBe(2);
    expect(bao.logins).toBe(2);

    // Pasado el max TTL del primer token se sigue leyendo sin logins de más.
    await vi.advanceTimersByTimeAsync(30_000);
    expect(await p.get('a')).toBe('1');
    expect(bao.logins).toBe(2);
    await p.close();
  });

  it('con un token no renovable hace login de nuevo', async () => {
    vi.useFakeTimers();
    bao.renewable = false;
    const p = provider(bao);
    await p.healthCheck();
    await vi.advanceTimersByTimeAsync(41_000);
    expect(bao.renewals).toBe(0);
    expect(bao.logins).toBe(2);
    await p.close();
  });

  it('si la renovación falla descarta el token y el siguiente uso entra de nuevo', async () => {
    vi.useFakeTimers();
    const p = provider(bao);
    await p.set('a', { x: '1' });
    bao.down = true;
    await vi.advanceTimersByTimeAsync(41_000);
    expect(p.tokenAccessor).toBeUndefined();
    bao.down = false;
    expect(await p.get('a')).toBe('1');
    expect(bao.logins).toBe(2);
    await p.close();
  });

  it('se recupera de un token revocado desde fuera', async () => {
    const p = provider(bao);
    await p.set('a', { x: '1' });
    bao.revokeAll();
    expect(await p.get('a')).toBe('1');
    expect(bao.logins).toBe(2);
  });

  it('permiso denegado tras reintentar, sellado y sin red ⇒ provider_error', async () => {
    const p = provider(bao);
    bao.kvStatus = 403;
    await expect(p.get('a')).rejects.toThrow(/permiso denegado/);
    expect(bao.logins).toBe(2);
    bao.kvStatus = 503;
    await expect(p.get('a')).rejects.toThrow(/sellado/);
    bao.kvStatus = undefined;
    bao.down = true;
    expect(await code(p.get('a'))).toBe('provider_error');
    expect(await p.healthCheck()).toBe(false);
  });

  it('secret_id inválido: salud false y login rechazado', async () => {
    const p = new OpenBaoSecretProvider(
      loadOpenBaoConfig({ addr: ADDR, roleId: bao.roleId, secretId: 'malo' }),
      bao.fetch,
    );
    expect(await p.healthCheck()).toBe(false);
    await expect(p.get('a')).rejects.toThrow(
      /login AppRole rechazado \(HTTP 400\)/,
    );
  });

  it('salud true con login válido', async () => {
    expect(await provider(bao).healthCheck()).toBe(true);
  });

  it('close revoca el token, para la renovación y deja de responder', async () => {
    vi.useFakeTimers();
    const p = provider(bao);
    await p.healthCheck();
    expect(bao.tokens.size).toBe(1);
    await p.close();
    expect(bao.tokens.size).toBe(0);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(bao.renewals).toBe(0);
    expect(await code(p.get('a'))).toBe('provider_error');
  });

  it('ni inspect ni JSON muestran el token ni el secret_id', async () => {
    const p = provider(bao);
    await p.healthCheck();
    const [token] = [...bao.tokens.keys()];
    for (const text of [
      inspect(p, { depth: 10, showHidden: true }),
      JSON.stringify(p),
    ]) {
      expect(text).not.toContain(token);
      expect(text).not.toContain(bao.secretId);
    }
  });

  describe('CA SSH', () => {
    const KEY = generateSshKeyPair('efimera').publicKey;
    const request = {
      publicKey: KEY,
      principal: 'inventory',
      keyId: 'infraward:asset=a1:job=j1',
      ttlSeconds: 300,
    };

    it('firma la clave con un único principal, key_id y TTL', async () => {
      const bao = new FakeOpenBao();
      const cert = await provider(bao).signSshKey(request);
      expect(cert).toMatch(
        /^ssh-ed25519-cert-v01@openssh\.com [A-Za-z0-9+/]+=*$/,
      );
      expect(bao.sshSignRequests).toEqual([
        {
          // Sin el comentario de la clave: solo tipo y blob.
          public_key: KEY.split(' ').slice(0, 2).join(' '),
          valid_principals: 'inventory',
          key_id: 'infraward:asset=a1:job=j1',
          ttl: '300s',
          cert_type: 'user',
        },
      ]);
    });

    it('valida la petición antes de enviarla', async () => {
      const bao = new FakeOpenBao();
      const p = provider(bao);
      await expect(
        p.signSshKey({ ...request, publicKey: 'ssh-rsa AAAA' }),
      ).rejects.toThrow(TypeError);
      await expect(
        p.signSshKey({ ...request, principal: 'root,inventory' }),
      ).rejects.toThrow(/Principal/);
      await expect(
        p.signSshKey({ ...request, keyId: 'id con espacios' }),
      ).rejects.toThrow(/key_id/);
      await expect(
        p.signSshKey({ ...request, ttlSeconds: 86400 }),
      ).rejects.toThrow(/TTL/);
      expect(bao.sshSignRequests).toEqual([]);
    });

    it('firma rechazada por el rol ⇒ provider_error sin el cuerpo de la respuesta', async () => {
      const bao = new FakeOpenBao();
      bao.sshSignStatus = 400;
      const p = provider(bao);
      expect(await code(p.signSshKey(request))).toBe('provider_error');
      await expect(p.signSshKey(request)).rejects.not.toThrow(/rechazado/);
    });

    it('claves de las CA vigentes, la activa primero, con su huella', async () => {
      const bao = new FakeOpenBao();
      const p = provider(bao);
      expect(await p.sshCaPublicKeys()).toEqual([]);
      const current = generateSshKeyPair('x')
        .publicKey.split(' ')
        .slice(0, 2)
        .join(' ');
      const next = generateSshKeyPair('y')
        .publicKey.split(' ')
        .slice(0, 2)
        .join(' ');
      bao.sshIssuers = [
        { publicKey: next, isDefault: false },
        { publicKey: current, isDefault: true },
      ];
      const keys = await p.sshCaPublicKeys();
      expect(keys.map((k) => [k.publicKey, k.active])).toEqual([
        [current, true],
        [next, false],
      ]);
      expect(keys[0].fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    });
  });
});
