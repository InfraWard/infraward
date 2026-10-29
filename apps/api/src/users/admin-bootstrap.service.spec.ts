import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { QueryFailedError } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { AdminBootstrapService } from './admin-bootstrap.service.js';
import type { User } from './user.entity.js';
import type { UsersService } from './users.service.js';

const PASSWORD = 'contraseña-muy-secreta-del-admin';

function setup(userCount: number, env: Partial<EnvironmentVariables>) {
  const users = {
    count: vi.fn(async () => userCount),
    create: vi.fn(async (email: string) => ({ email }) as User),
  };
  const config = {
    get: (key: keyof EnvironmentVariables) => env[key],
  } as unknown as ConfigService<EnvironmentVariables, true>;
  const service = new AdminBootstrapService(
    users as unknown as UsersService,
    config,
  );
  return { users, service };
}

describe('AdminBootstrapService', () => {
  const env = { ADMIN_EMAIL: 'admin@example.com', ADMIN_PASSWORD: PASSWORD };
  let logged: string[];

  beforeEach(() => {
    logged = [];
    for (const level of [
      'log',
      'warn',
      'error',
      'debug',
      'verbose',
      'fatal',
    ] as const) {
      vi.spyOn(Logger.prototype, level).mockImplementation(
        (...args: unknown[]) => {
          logged.push(JSON.stringify(args));
        },
      );
    }
  });

  afterEach(() => vi.restoreAllMocks());

  it('crea el admin solo si la tabla de usuarios está vacía', async () => {
    const empty = setup(0, env);
    await empty.service.onApplicationBootstrap();
    expect(empty.users.create).toHaveBeenCalledWith(
      env.ADMIN_EMAIL,
      PASSWORD,
      'admin',
    );

    const withUsers = setup(1, env);
    await withUsers.service.onApplicationBootstrap();
    expect(withUsers.users.create).not.toHaveBeenCalled();
  });

  it('no crea nada sin ADMIN_EMAIL/ADMIN_PASSWORD', async () => {
    const { users, service } = setup(0, {});
    await service.onApplicationBootstrap();
    expect(users.create).not.toHaveBeenCalled();
    expect(logged.join()).toMatch(/ADMIN_EMAIL/);
  });

  it('tolera que otra réplica cree el admin a la vez', async () => {
    const { users, service } = setup(0, env);
    users.create.mockRejectedValueOnce(
      new QueryFailedError(
        'INSERT',
        [],
        Object.assign(new Error('duplicate'), { code: '23505' }),
      ),
    );
    await expect(service.onApplicationBootstrap()).resolves.toBeUndefined();
  });

  it('nunca escribe ADMIN_PASSWORD en los logs', async () => {
    await setup(0, env).service.onApplicationBootstrap();
    await setup(1, env).service.onApplicationBootstrap();
    expect(logged.length).toBeGreaterThan(0);
    expect(logged.join('\n')).not.toContain(PASSWORD);
  });
});
