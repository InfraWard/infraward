import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import { Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { DataSource } from 'typeorm';
import { describe, expect, it, vi } from 'vitest';
import { SECRET_PROVIDERS, type SecretProvider } from './secret-provider.js';
import { SecretsModule, type SecretsModuleOptions } from './secrets.module.js';
import { SECRETS_CACHE_TTL, SecretsService } from './secrets.service.js';

/** DataSource ficticio: el proveedor local solo lo usa al leer o escribir. */
const fakeDataSource = { provide: DataSource, useValue: {} };

async function compile(options: SecretsModuleOptions) {
  return Test.createTestingModule({
    imports: [SecretsModule.forRoot({ useFactory: () => options })],
    providers: [fakeDataSource],
  }).compile();
}

describe('SecretsModule.forRoot', () => {
  it('registra solo los proveedores habilitados', async () => {
    const moduleRef = await compile({
      enabled: ['local'],
      local: { key: randomBytes(32).toString('base64') },
    });
    const providers = moduleRef.get<SecretProvider[]>(SECRET_PROVIDERS);
    expect(providers.map((p) => p.id)).toEqual(['local']);
    expect(moduleRef.get(SecretsService)).toBeInstanceOf(SecretsService);
    await moduleRef.close();
  });

  it('recibe la configuración de una factoría con dependencias', async () => {
    const CONFIG = 'CONFIG';
    @Module({
      providers: [
        {
          provide: CONFIG,
          useValue: {
            enabled: ['local'],
            local: { key: randomBytes(32).toString('base64') },
            cacheTtlSeconds: 5,
          },
        },
      ],
      exports: [CONFIG],
    })
    class ConfigModule {}

    const moduleRef = await Test.createTestingModule({
      imports: [
        SecretsModule.forRoot({
          imports: [ConfigModule],
          inject: [CONFIG],
          useFactory: (config: SecretsModuleOptions) => config,
        }),
      ],
      providers: [fakeDataSource],
    }).compile();
    expect(
      moduleRef.get<SecretProvider[]>(SECRET_PROVIDERS).map((p) => p.id),
    ).toEqual(['local']);
    expect(moduleRef.get(SECRETS_CACHE_TTL)).toBe(5);
    await moduleRef.close();
  });

  it('conviven openbao y local, en el orden de SECRETS_PROVIDERS, y se cierran con la app', async () => {
    const moduleRef = await compile({
      enabled: ['openbao', 'local'],
      local: { key: randomBytes(32).toString('base64') },
      openbao: { addr: 'http://127.0.0.1:1', roleId: 'r', secretId: 's' },
    });
    const providers = moduleRef.get<SecretProvider[]>(SECRET_PROVIDERS);
    expect(providers.map((p) => p.id)).toEqual(['openbao', 'local']);
    const close = vi.spyOn(providers[0], 'close');
    await moduleRef.close();
    expect(close).toHaveBeenCalledOnce();
  });

  it.each([
    [
      { enabled: ['vaultwarden'] },
      /proveedor desconocido "vaultwarden" \(disponibles: local, openbao\)/,
    ],
    [{ enabled: ['openbao'] }, /OpenBao: falta OPENBAO_ADDR/],
    [{ enabled: ['constructor'] }, /proveedor desconocido "constructor"/],
    [{ enabled: [] }, /al menos un proveedor/],
    [
      {
        enabled: ['local', 'local'],
        local: { key: randomBytes(32).toString('base64') },
      },
      /repetido "local"/,
    ],
    [{ enabled: ['local'] }, /falta SECRETS_LOCAL_MASTER_KEY/],
    [
      {
        enabled: ['local'],
        local: { key: randomBytes(31).toString('base64') },
      },
      /32 bytes/,
    ],
  ] as [SecretsModuleOptions, RegExp][])(
    'no arranca con una configuración inválida (%j)',
    async (options, error) => {
      await expect(compile(options)).rejects.toThrow(error);
    },
  );
});
