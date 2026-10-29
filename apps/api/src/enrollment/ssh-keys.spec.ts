import { secretBaseRef, sshKeySecretPath } from './ssh-keys.js';

describe('ssh-keys', () => {
  it('referencias del secreto', () => {
    expect(sshKeySecretPath('local', 'a1')).toBe(
      'secret://local/assets/a1/ssh',
    );
    expect(secretBaseRef('secret://local/assets/a1/ssh#privateKey')).toBe(
      'secret://local/assets/a1/ssh',
    );
    expect(() => secretBaseRef('local/a1')).toThrow();
  });
});
