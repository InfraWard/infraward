import { generateTemporaryPassword } from './temporary-password.js';

describe('generateTemporaryPassword', () => {
  it('20 caracteres sin ambiguos, en grupos de 5', () => {
    for (let i = 0; i < 200; i++) {
      const pwd = generateTemporaryPassword();
      expect(pwd).toMatch(/^[A-HJ-NP-Za-km-z2-9]{5}(-[A-HJ-NP-Za-km-z2-9]{5}){3}$/);
      expect(pwd).not.toMatch(/[0O1lI]/);
    }
  });

  it('no se repite', () => {
    const seen = new Set(Array.from({ length: 1000 }, generateTemporaryPassword));
    expect(seen.size).toBe(1000);
  });
});
