import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { LocalSecretProvider } from './local/local.provider.js';
import { loadMasterKey, MasterKey } from './local/master-key.js';
import { loadOpenBaoConfig } from './openbao/openbao-config.js';
import { OpenBaoSecretProvider } from './openbao/openbao.provider.js';
import { SecretsService } from './secrets.service.js';
import { FakeOpenBao, MemoryLocalSecretStore } from './testing.js';

/**
 * Garantía transversal: en ningún flujo (éxito o error) el valor de un secreto ni la clave
 * maestra llegan a stdout/stderr, al Logger de Nest o al texto de un error.
 */
describe('ningún valor sale a logs ni errores', () => {
  const VALUE = `valor-centinela-${randomBytes(8).toString('hex')}`;
  const keyBytes = randomBytes(32);
  const KEY_B64 = keyBytes.toString('base64');
  const output: string[] = [];
  const errors: unknown[] = [];

  beforeAll(async () => {
    for (const stream of [process.stdout, process.stderr]) {
      vi.spyOn(stream, 'write').mockImplementation((chunk: unknown) => {
        output.push(String(chunk));
        return true;
      });
    }
    for (const level of [
      'log',
      'error',
      'warn',
      'debug',
      'verbose',
      'fatal',
    ] as const) {
      vi.spyOn(Logger.prototype, level).mockImplementation(
        (...args: unknown[]) => {
          output.push(JSON.stringify(args));
        },
      );
      vi.spyOn(Logger, level).mockImplementation((...args: unknown[]) => {
        output.push(JSON.stringify(args));
      });
    }

    const capture = async (fn: () => unknown) => {
      try {
        await fn();
      } catch (e) {
        errors.push(e);
      }
    };

    const store = new MemoryLocalSecretStore();
    const key = loadMasterKey({ key: KEY_B64 });
    const provider = new LocalSecretProvider(store, key);
    const service = new SecretsService([provider], 60);

    // Éxito: guardar, resolver (también desde caché).
    await service.store('secret://local/assets/a/ssh', {
      private_key: VALUE,
      public_key: `pub-${VALUE}`,
    });
    expect(
      await service.resolve('secret://local/assets/a/ssh#private_key'),
    ).toBe(VALUE);
    await service.resolve('secret://local/assets/a/ssh#private_key');
    await service.describeProviders();

    // Errores: todos los códigos.
    await capture(() => service.resolve('no-es-ref'));
    await capture(() => service.resolve('secret://openbao/x#y'));
    await capture(() => service.resolve('secret://local/nada#y'));
    await capture(() => service.resolve('secret://local/assets/a/ssh#otro'));
    await capture(() => service.resolve('secret://local/assets/a/ssh'));
    await capture(() =>
      new LocalSecretProvider(store, new MasterKey(randomBytes(32))).get(
        'assets/a/ssh',
        'private_key',
      ),
    );
    store.rows.get('assets/a/ssh')!.authTag[0] ^= 1;
    service.clearCache();
    await capture(() =>
      service.resolve('secret://local/assets/a/ssh#private_key'),
    );
    await capture(() =>
      loadMasterKey({ key: randomBytes(31).toString('base64') }),
    );
    await capture(() => provider.set('x', { v: 1 as unknown as string }));

    // Y además, lo que alguien podría loguear por descuido.
    console.log(key, provider, service);
    console.error(errors);
    new Logger('Test').log({ key, provider });
  });

  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('se han producido los errores esperados', () => {
    expect(
      errors.map((e) => (e as { code?: string }).code ?? (e as Error).name),
    ).toEqual([
      'invalid_ref',
      'provider_not_configured',
      'not_found',
      'field_not_found',
      'field_not_found',
      'key_mismatch',
      'decryption_failed',
      'Error',
      'TypeError',
    ]);
  });

  it('stdout, stderr y el Logger no contienen el valor ni la clave maestra', () => {
    const all = output.join('\n');
    expect(all.length).toBeGreaterThan(0);
    expect(all).not.toContain(VALUE);
    expect(all).not.toContain(KEY_B64);
    expect(all).not.toContain(keyBytes.toString('hex'));
  });

  it('los mensajes y pilas de los errores no contienen el valor ni la clave', () => {
    for (const e of errors as Error[]) {
      const text = `${e.message}\n${e.stack}\n${JSON.stringify(e)}`;
      expect(text).not.toContain(VALUE);
      expect(text).not.toContain(KEY_B64);
    }
  });
});

/** Lo mismo con OpenBao: ni el valor, ni el token de la app, ni el secret_id de AppRole. */
describe('OpenBao: ningún valor ni credencial sale a logs ni errores', () => {
  const VALUE = `valor-centinela-${randomBytes(8).toString('hex')}`;
  const bao = new FakeOpenBao();
  const tokens = new Set<string>();
  const output: string[] = [];
  const errors: unknown[] = [];

  beforeAll(async () => {
    vi.useFakeTimers();
    for (const stream of [process.stdout, process.stderr]) {
      vi.spyOn(stream, 'write').mockImplementation((chunk: unknown) => {
        output.push(String(chunk));
        return true;
      });
    }
    for (const level of ['log', 'error', 'warn', 'debug', 'verbose'] as const) {
      vi.spyOn(Logger.prototype, level).mockImplementation(
        (...args: unknown[]) => {
          output.push(JSON.stringify(args));
        },
      );
    }
    const capture = async (fn: () => unknown) => {
      try {
        await fn();
      } catch (e) {
        errors.push(e);
      }
    };

    // http:// a un host remoto: también provoca el aviso de transporte inseguro.
    const config = loadOpenBaoConfig({
      addr: 'http://bao.remoto:8200',
      roleId: bao.roleId,
      secretId: bao.secretId,
    });
    const provider = new OpenBaoSecretProvider(config, bao.fetch);
    const service = new SecretsService([provider], 60);

    await service.store('secret://openbao/assets/a/ssh', {
      private_key: VALUE,
    });
    expect(await service.resolve('secret://openbao/assets/a/ssh')).toBe(VALUE);
    await service.describeProviders();
    for (const t of bao.tokens.keys()) tokens.add(t);

    await capture(() => service.resolve('secret://openbao/nada#x'));
    await capture(() => service.resolve('secret://openbao/assets/a/ssh#otro'));
    bao.kvStatus = 403;
    await capture(() => provider.get('assets/a/ssh'));
    for (const t of bao.tokens.keys()) tokens.add(t);
    bao.kvStatus = 503;
    await capture(() => provider.get('assets/a/ssh'));
    bao.kvStatus = undefined;
    // Renovación fallida (sin red): se loguea un aviso.
    bao.down = true;
    await vi.advanceTimersByTimeAsync(41_000);
    await capture(() => provider.get('assets/a/ssh'));
    bao.down = false;
    await capture(() =>
      new OpenBaoSecretProvider(
        loadOpenBaoConfig({
          addr: 'http://127.0.0.1:8200',
          roleId: bao.roleId,
          secretId: 'malo',
        }),
        bao.fetch,
      ).get('a'),
    );
    await capture(() =>
      loadOpenBaoConfig({ addr: 'x', roleId: 'r', secretId: bao.secretId }),
    );
    for (const t of bao.tokens.keys()) tokens.add(t);

    console.log(config, provider, service);
    console.error(errors);
    new Logger('Test').log({ config, provider });
    await service.onModuleDestroy();
  });

  afterAll(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('se han producido los errores y avisos esperados', () => {
    expect(tokens.size).toBeGreaterThanOrEqual(2);
    expect(
      errors.map((e) => (e as { code?: string }).code ?? (e as Error).name),
    ).toEqual([
      'not_found',
      'field_not_found',
      'provider_error',
      'provider_error',
      'provider_error',
      'provider_error',
      'Error',
    ]);
    const all = output.join('\n');
    expect(all).toContain('http://');
    expect(all).toContain('No se pudo renovar el token');
  });

  it('ni la salida ni los errores contienen el valor, los tokens o el secret_id', () => {
    const texts = [
      output.join('\n'),
      ...(errors as Error[]).map(
        (e) => `${e.message}\n${e.stack}\n${JSON.stringify(e)}`,
      ),
    ];
    for (const text of texts) {
      expect(text).not.toContain(VALUE);
      expect(text).not.toContain(bao.secretId);
      for (const t of tokens) expect(text).not.toContain(t);
    }
  });
});
