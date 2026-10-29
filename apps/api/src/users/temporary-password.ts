import { randomInt } from 'node:crypto';

/** Sin caracteres que se confunden al leerlos o dictarlos (0/O, 1/l/I). */
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const GROUPS = 4;
const GROUP_LENGTH = 5;

/**
 * Contraseña temporal: 20 caracteres aleatorios (≈ 117 bits) en grupos de 5 separados por guiones
 * para leerla y copiarla con facilidad. Se devuelve una sola vez; solo se guarda su hash.
 */
export function generateTemporaryPassword(): string {
  const groups: string[] = [];
  for (let g = 0; g < GROUPS; g++) {
    let group = '';
    for (let i = 0; i < GROUP_LENGTH; i++)
      group += ALPHABET[randomInt(ALPHABET.length)];
    groups.push(group);
  }
  return groups.join('-');
}

/**
 * Valor de `password_hash` que ninguna contraseña verifica (no es un hash argon2 válido): deja
 * gastada la temporal tras su único uso y es el de las cuentas creadas por OIDC (sin contraseña).
 */
export const UNUSABLE_PASSWORD_HASH = '!consumed';
