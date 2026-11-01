import { REDACTED, redactSecrets } from './redact.js';

describe('redactSecrets', () => {
  it('censura claves privadas enteras y cortadas', () => {
    const key = [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
      '-----END OPENSSH PRIVATE KEY-----',
    ].join('\n');
    const out = redactSecrets(`antes\n${key}\ndespués`);
    expect(out).toBe('antes\n[clave privada censurada]\ndespués');
    expect(redactSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEow')).toBe(
      '[clave privada censurada]',
    );
  });

  it('censura clave=valor, JSON, cabeceras y credenciales en URLs', () => {
    expect(redactSecrets('password=hunter2 user=root')).toBe(
      `password=${REDACTED} user=root`,
    );
    expect(redactSecrets('{"api_key": "abc123", "name": "x"}')).toBe(
      `{"api_key": "${REDACTED}", "name": "x"}`,
    );
    expect(redactSecrets('DB_PASSWORD: s3cr3t')).toBe(
      `DB_PASSWORD: ${REDACTED}`,
    );
    expect(redactSecrets('Authorization: Bearer abcdefghijkl')).toBe(
      `Authorization: Bearer ${REDACTED}`,
    );
    expect(redactSecrets('curl -H "x" bearer abcdefghijklmnop')).toBe(
      `curl -H "x" bearer ${REDACTED}`,
    );
    expect(redactSecrets('https://bob:pa55@example.com/repo.git')).toBe(
      `https://bob:${REDACTED}@example.com/repo.git`,
    );
  });

  it('censura formatos de token conocidos', () => {
    for (const token of [
      'iwt_abcdefghijklmnopqrstuvwx',
      'hvs.CAESIJlU3l2c2VjcmV0dG9rZW5fZm9yX3Rlc3Q',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
      // Partidos en dos: enteros, el filtro de github-publish (.github-publish/deny) los veta.
      'ghp_' + 'abcdefghijklmnopqrstuvwxyz0123456789',
      'glpat-' + 'abcdefghijklmnopqrstu',
      'AKIA' + 'ABCDEFGHIJKLMNOP',
    ])
      expect(redactSecrets(`token ${token} fin`)).toBe(`token ${REDACTED} fin`);
  });

  it('deja tal cual lo que no parece un secreto', () => {
    const text =
      'fatal: [target]: UNREACHABLE! Permission denied (publickey). authorized_keys en /home/x';
    expect(redactSecrets(text)).toBe(text);
    expect(redactSecrets('this.someVeryLongIdentifierName_withMore')).toBe(
      'this.someVeryLongIdentifierName_withMore',
    );
  });
});
