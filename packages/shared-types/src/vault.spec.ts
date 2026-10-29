import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { sshdAuthRisk, sshdRiskLevel } from './collection.js';
import {
  generatePassword,
  PASSWORD_CLASSES,
  rotationCommand,
  VAULT_ENTRY_KINDS,
  vaultRotationState,
} from './vault.js';

const rng = (n: number) => new Uint8Array(randomBytes(n));

describe('generatePassword', () => {
  it('respeta la longitud y lleva al menos un carácter de cada clase', () => {
    for (let i = 0; i < 500; i++) {
      const length = 12 + (i % 50);
      const p = generatePassword(rng, { length });
      expect(p).toHaveLength(length);
      for (const chars of Object.values(PASSWORD_CLASSES)) {
        expect([...p].some((c) => chars.includes(c))).toBe(true);
      }
    }
  });

  it('sin símbolos, solo letras y dígitos', () => {
    for (let i = 0; i < 200; i++) {
      expect(generatePassword(rng, { symbols: false })).toMatch(/^[A-Za-z0-9]{24}$/);
    }
  });

  it('nunca usa caracteres ambiguos, comillas ni barras', () => {
    const all = Array.from({ length: 300 }, () => generatePassword(rng)).join('');
    expect(all).not.toMatch(/[0O1lI'"`\\/ $]/);
  });

  it('rechaza longitudes fuera de rango', () => {
    expect(() => generatePassword(rng, { length: 8 })).toThrow(RangeError);
    expect(() => generatePassword(rng, { length: 500 })).toThrow(RangeError);
    expect(() => generatePassword(rng, { length: 20.5 })).toThrow(RangeError);
  });

  it('sin sesgo apreciable: cada carácter sale con una frecuencia parecida', () => {
    const alphabet = Object.values(PASSWORD_CLASSES).join('');
    const counts = new Map<string, number>();
    const text = Array.from({ length: 2000 }, () => generatePassword(rng, { length: 64 })).join('');
    for (const c of text) counts.set(c, (counts.get(c) ?? 0) + 1);
    expect(counts.size).toBe(alphabet.length);
    const expected = text.length / alphabet.length;
    for (const n of counts.values()) {
      expect(Math.abs(n - expected) / expected).toBeLessThan(0.15);
    }
  });

  it('con una fuente que solo da bytes altos (rechazo) sigue terminando bien', () => {
    let k = 0;
    const skewed = (n: number) =>
      Uint8Array.from({ length: n }, () => (k++ % 3 === 0 ? 255 : (k * 37) % 256));
    expect(generatePassword(skewed, { length: 32 })).toHaveLength(32);
  });
});

describe('rotationCommand', () => {
  const secret = generatePassword(rng);

  it('nunca lleva la contraseña: los comandos la piden', () => {
    for (const kind of VAULT_ENTRY_KINDS) {
      for (const roles of [[], ['proxmox-node'], ['plesk']]) {
        const cmd = rotationCommand(kind, 'root', { roles });
        expect(JSON.stringify(cmd)).not.toContain(secret);
      }
    }
  });

  it('elige el comando por tipo y roles', () => {
    expect(rotationCommand('console', 'root').commands).toEqual(['sudo passwd root']);
    expect(rotationCommand('console', 'admin').commands).toEqual(['sudo passwd admin']);
    expect(rotationCommand('web', 'root', { roles: ['proxmox-node'] }).commands).toEqual([
      'pveum passwd root@pam',
    ]);
    expect(rotationCommand('web', 'ops@pve', { roles: ['proxmox-node'] }).commands).toEqual([
      'pveum passwd ops@pve',
    ]);
    expect(rotationCommand('web', 'admin', { roles: ['plesk'] }).commands.join('\n')).toContain(
      'plesk bin admin --set-admin-password',
    );
    expect(rotationCommand('ipmi', 'ADMIN').commands[1]).toContain('ipmitool user set password');
    expect(rotationCommand('other', null).commands).toEqual([]);
  });

  it('un usuario raro no se mete en el comando', () => {
    expect(rotationCommand('console', 'x; rm -rf /').commands).toEqual(['sudo passwd root']);
    expect(rotationCommand('console', '$(id)').commands).toEqual(['sudo passwd root']);
  });
});

describe('vaultRotationState', () => {
  const now = new Date('2026-10-20T12:00:00Z');
  it('al día, vencida o sin fecha', () => {
    expect(vaultRotationState(null, 90, now)).toEqual({ state: 'unknown', dueAt: null });
    expect(vaultRotationState('2026-10-01T12:00:00Z', 90, now).state).toBe('ok');
    const old = vaultRotationState('2026-01-01T00:00:00Z', 90, now);
    expect(old.state).toBe('overdue');
    expect(old.dueAt?.toISOString()).toBe('2026-04-01T00:00:00.000Z');
  });
});

describe('sshdAuthRisk', () => {
  const base = {
    permitRootLogin: 'prohibit-password',
    passwordAuthentication: false,
    kbdInteractiveAuthentication: false,
  };
  it('sin riesgo con la configuración recomendada', () => {
    expect(sshdAuthRisk(base)).toBeNull();
    expect(sshdAuthRisk(null)).toBeNull();
    expect(sshdRiskLevel(base)).toBeNull();
  });
  it('PermitRootLogin yes, contraseñas o las dos', () => {
    expect(sshdRiskLevel({ ...base, permitRootLogin: 'yes' })).toBe('root');
    expect(sshdRiskLevel({ ...base, passwordAuthentication: true })).toBe('password');
    expect(sshdRiskLevel({ ...base, kbdInteractiveAuthentication: true })).toBe('password');
    expect(
      sshdAuthRisk({ ...base, permitRootLogin: 'yes', passwordAuthentication: true }),
    ).toEqual({ rootLogin: true, passwordLogin: true, rootPassword: true });
  });
});
