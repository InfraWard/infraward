import { describe, expect, it } from 'vitest';
import { globMatch, scanExclusionMatch } from './inventory.js';

describe('globMatch', () => {
  it.each([
    ['bitnami/*', 'bitnami/redis', true],
    ['BITNAMI/*', 'bitnami/redis', true],
    ['*redis*', 'docker.io/library/redis:7', true],
    ['redis', 'redis:7', false],
    ['red?s', 'redis', true],
    ['red?s', 'reds', false],
    ['*', '', true],
    ['?', '', false],
    ['a**b', 'ab', true],
    ['a*b*c', 'abxbc', true],
    ['a*b*c', 'abxbd', false],
    ['*.example.com', 'web.example.com', true],
    ['*.example.com', 'example.com', false],
    ['ñandú-*', 'ÑANDÚ-01', true],
    // `.` y `+` son literales, no de regex.
    ['a.b', 'axb', false],
    ['a+', 'aa', false],
  ])('%s ~ %s → %s', (pattern, name, expected) => {
    expect(globMatch(pattern, name)).toBe(expected);
  });

  it('no hace backtracking exponencial (A1 de la revisión #3)', () => {
    // Con la regex anterior (`^.*a.*a…b$`) esto no terminaba: ~50 estrellas y 255 caracteres.
    const pattern = '*a'.repeat(49) + '*b';
    const name = 'a'.repeat(255);
    const started = performance.now();
    expect(globMatch(pattern, name)).toBe(false);
    expect(performance.now() - started).toBeLessThan(200);
  });
});

describe('scanExclusionMatch', () => {
  const asset = {
    id: 'a1',
    type: 'image' as const,
    name: 'nginx:1.27',
    discoveredName: 'docker.io/library/nginx:1.27',
  };

  it('casa por el nombre visible o el descubierto', () => {
    expect(
      scanExclusionMatch(asset, { namePatterns: ['docker.io/*'] }),
    ).toEqual({
      kind: 'pattern',
      pattern: 'docker.io/*',
    });
    expect(scanExclusionMatch(asset, { namePatterns: ['NGINX:*'] })).toEqual({
      kind: 'pattern',
      pattern: 'NGINX:*',
    });
    expect(scanExclusionMatch(asset, { namePatterns: ['redis*'] })).toBeNull();
  });
});
