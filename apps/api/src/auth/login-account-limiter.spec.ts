import type { ConfigService } from '@nestjs/config';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EnvironmentVariables } from '../config/env.validation.js';
import {
  KNOWN_CLIENT_TTL_MS,
  LoginAccountLimiter,
} from './login-account-limiter.js';
import type { RedisThrottlerStorage } from './redis-throttler.storage.js';

const LIMIT = 3;
const TTL = 300;

function limiter(): LoginAccountLimiter {
  const values: Record<string, unknown> = {
    LOGIN_ACCOUNT_THROTTLE_LIMIT: LIMIT,
    LOGIN_ACCOUNT_THROTTLE_TTL: TTL,
    THROTTLE_STORAGE: 'memory',
  };
  const config = { get: (key: string) => values[key] };
  return new LoginAccountLimiter(
    config as unknown as ConfigService<EnvironmentVariables, true>,
    {} as RedisThrottlerStorage,
  );
}

describe('LoginAccountLimiter', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('bloquea la cuenta tras LIMIT fallos desde cualquier IP, sin distinguir mayúsculas', async () => {
    const l = limiter();
    for (let i = 0; i < LIMIT; i++) {
      expect(await l.retryAfter('ana@example.com', `203.0.113.${i}`)).toBeNull();
      await l.failed('ana@example.com');
    }
    expect(await l.retryAfter('ANA@example.com ', '198.51.100.1')).toBe(TTL);
    // Otras cuentas, no.
    expect(await l.retryAfter('beto@example.com', '198.51.100.1')).toBeNull();
  });

  it('el bloqueo dura TTL desde el fallo que llega al límite', async () => {
    const l = limiter();
    await l.failed('ana@example.com');
    vi.advanceTimersByTime(200_000);
    await l.failed('ana@example.com');
    await l.failed('ana@example.com');
    vi.advanceTimersByTime(250_000);
    expect(await l.retryAfter('ana@example.com', '198.51.100.1')).toBe(50);
    vi.advanceTimersByTime(50_000);
    expect(await l.retryAfter('ana@example.com', '198.51.100.1')).toBeNull();
  });

  it('los logins correctos no cuentan y ponen el contador a cero', async () => {
    const l = limiter();
    for (let i = 0; i < LIMIT - 1; i++) await l.failed('ana@example.com');
    await l.succeeded('ana@example.com', '192.0.2.10');
    for (let i = 0; i < LIMIT - 1; i++) await l.failed('ana@example.com');
    expect(await l.retryAfter('ana@example.com', '198.51.100.1')).toBeNull();
  });

  it('una cuenta bloqueada sigue entrando desde las redes donde ya entró bien (IPv6 por /64)', async () => {
    const l = limiter();
    await l.succeeded('ana@example.com', '192.0.2.10');
    await l.succeeded('ana@example.com', '2001:db8:1:2::10');
    for (let i = 0; i < LIMIT; i++) await l.failed('ana@example.com');
    expect(await l.retryAfter('ana@example.com', '192.0.2.10')).toBeNull();
    expect(await l.retryAfter('ana@example.com', '2001:db8:1:2:abcd::99')).toBeNull();
    expect(await l.retryAfter('ana@example.com', '::ffff:192.0.2.10')).toBeNull();
    expect(await l.retryAfter('ana@example.com', '192.0.2.11')).toBe(TTL);
    expect(await l.retryAfter('ana@example.com', '2001:db8:1:3::10')).toBe(TTL);
    // Conocida para esa cuenta, no para otras.
    for (let i = 0; i < LIMIT; i++) await l.failed('beto@example.com');
    expect(await l.retryAfter('beto@example.com', '192.0.2.10')).toBe(TTL);
  });

  it('la red conocida caduca a los KNOWN_CLIENT_TTL_MS', async () => {
    const l = limiter();
    await l.succeeded('ana@example.com', '192.0.2.10');
    vi.advanceTimersByTime(KNOWN_CLIENT_TTL_MS);
    for (let i = 0; i < LIMIT; i++) await l.failed('ana@example.com');
    expect(await l.retryAfter('ana@example.com', '192.0.2.10')).toBe(TTL);
  });
});
