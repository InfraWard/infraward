import { sanitizeDetails } from './sanitize.js';

describe('sanitizeDetails', () => {
  it('quita las claves que podrían llevar secretos', () => {
    expect(
      sanitizeDetails({
        role: 'admin',
        password: 'x',
        temporaryPassword: 'y',
        passwordHash: 'z',
        csrfToken: 't',
        privateKey: 'k',
        secretRef: 'secret://local/a#b',
        credentials: 'c',
      }),
    ).toEqual({ role: 'admin' });
  });

  it('nunca deja pasar una clave privada ni una referencia a un secreto como valor', () => {
    expect(
      sanitizeDetails({
        note: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc',
        ref: 'secret://openbao/ssh/x#private',
        ok: 'sí',
      }),
    ).toEqual({ ok: 'sí' });
  });

  it('solo valores planos, textos cortados y listas acotadas', () => {
    const res = sanitizeDetails({
      nested: { a: 1 },
      fn: () => 1,
      n: 3,
      nan: Number.NaN,
      flag: false,
      none: null,
      long: 'a'.repeat(500),
      list: Array.from({ length: 80 }, (_, i) => `x${i}`),
      when: new Date('2026-10-13T00:00:00Z'),
    });
    expect(res).toMatchObject({ n: 3, flag: false, none: null, when: '2026-10-13T00:00:00.000Z' });
    expect(res).not.toHaveProperty('nested');
    expect(res).not.toHaveProperty('fn');
    expect(res).not.toHaveProperty('nan');
    expect((res.long as string).length).toBe(201);
    expect(res.list).toHaveLength(50);
  });
});
