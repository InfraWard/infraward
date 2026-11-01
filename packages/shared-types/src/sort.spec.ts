import { describe, expect, it } from 'vitest';
import { byCodeUnit } from './sort.js';

describe('byCodeUnit', () => {
  it('ordena igual que sort() sin argumentos', () => {
    const values = ['b', 'B', 'a', 'á', '10', '9', 'a', '', 'Z', 'ñ', 'n'];
    expect([...values].sort(byCodeUnit)).toEqual([...values].sort());
  });
});
