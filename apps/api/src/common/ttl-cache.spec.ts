import { describe, expect, it, vi } from 'vitest';
import { TtlCache } from './ttl-cache.js';

describe('TtlCache', () => {
  it('devuelve lo guardado mientras dura y vuelve a cargar al caducar', async () => {
    let now = 0;
    const cache = new TtlCache<number>(10, () => now);
    const load = vi.fn().mockResolvedValueOnce(1).mockResolvedValueOnce(2);
    expect(await cache.get('k', 1000, load)).toBe(1);
    now = 999;
    expect(await cache.get('k', 1000, load)).toBe(1);
    now = 1000;
    expect(await cache.get('k', 1000, load)).toBe(2);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('dos peticiones iguales a la vez hacen una sola carga', async () => {
    const cache = new TtlCache<string>(10);
    let resolve!: (v: string) => void;
    const load = vi.fn(() => new Promise<string>((r) => (resolve = r)));
    const a = cache.get('k', 1000, load);
    const b = cache.get('k', 1000, load);
    resolve('x');
    expect(await Promise.all([a, b])).toEqual(['x', 'x']);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it('no guarda un fallo', async () => {
    const cache = new TtlCache<number>(10);
    const load = vi
      .fn()
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(3);
    await expect(cache.get('k', 1000, load)).rejects.toThrow('boom');
    expect(await cache.get('k', 1000, load)).toBe(3);
  });

  it('con el máximo lleno saca la más antigua; con ttl 0 no guarda', async () => {
    const cache = new TtlCache<number>(2);
    await cache.get('a', 1000, async () => 1);
    await cache.get('b', 1000, async () => 2);
    await cache.get('c', 1000, async () => 3);
    expect(cache.size).toBe(2);
    const load = vi.fn().mockResolvedValue(9);
    await cache.get('a', 1000, load);
    expect(load).toHaveBeenCalledTimes(1);
    await cache.get('z', 0, load);
    await cache.get('z', 0, load);
    expect(load).toHaveBeenCalledTimes(3);
  });
});
