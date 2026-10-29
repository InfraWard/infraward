import type { MachineIdClone } from '@infraward/shared-types';

/**
 * Separador de la clave natural de un clon: `<machine-id>+<huella de su host key>`. Un
 * machine-id son 32 hex, así que `+` nunca aparece en uno normal.
 */
export const CLONE_KEY_SEPARATOR = '+';

/** Clave natural de un servidor que comparte machine-id con otro (§8, clones). */
export function cloneNaturalKey(machineId: string, fingerprint: string): string {
  return `${machineId}${CLONE_KEY_SEPARATOR}${fingerprint}`;
}

/** Machine-id de una clave natural de servidor (normal o de clon). */
export function machineIdOfKey(key: string): string {
  const i = key.indexOf(CLONE_KEY_SEPARATOR);
  return i < 0 ? key : key.slice(0, i);
}

export function isCloneKey(key: string): boolean {
  return key.includes(CLONE_KEY_SEPARATOR);
}

/** Asset del mismo tipo cuya clave natural es el machine-id (o un clon de él). */
export interface IdentityCandidate {
  id: string;
  name: string;
  status: string;
  naturalKey: string | null;
  hostKeyFingerprint: string | null;
}

export interface IdentityInput {
  assetId: string;
  /** Clave natural actual del asset que se recoge. */
  currentKey: string | null;
  /** Machine-id que reporta ahora. */
  machineId: string | null;
  /** Huella fijada (o la que se fijará ahora por TOFU) de este asset. */
  fingerprint: string;
  /** Huellas de todas las host keys que presenta este servidor (`ssh-keyscan`). */
  scanned: readonly string[];
  candidates: readonly IdentityCandidate[];
}

export type IdentityDecision =
  | { duplicateOf: { id: string; name: string } }
  | {
      duplicateOf?: undefined;
      naturalKey: string | null;
      clone: MachineIdClone | null;
      warnings: string[];
    };

/**
 * Identidad de un servidor recogido por SSH (DESIGN §8):
 * - machine-id de otro asset vivo y alguna de sus host keys coincide ⇒ la misma máquina dada
 *   de alta dos veces: duplicado, no se guarda nada (un candidato sin huella fijada cuenta como
 *   la misma máquina, que es lo conservador).
 * - machine-id de otro asset vivo con host keys distintas ⇒ clon (VM, CT o plantilla copiados):
 *   se guarda con la clave `<machine-id>+<huella>` y `clone` (aviso «machine-id clonado»).
 * - Un clon que regenera su machine-id pasa a tener ese machine-id como clave (mismo asset).
 * - Nunca se pisa una clave normal distinta (reinstalación o máquina distinta en la misma IP) ni
 *   se roba la de un retirado: aviso.
 */
export function decideMachineIdentity(input: IdentityInput): IdentityDecision {
  const { machineId, currentKey } = input;
  if (!machineId)
    return { naturalKey: currentKey, clone: null, warnings: [] };
  const others = input.candidates.filter(
    (c) =>
      c.id !== input.assetId &&
      c.naturalKey !== null &&
      machineIdOfKey(c.naturalKey) === machineId,
  );
  const live = others.filter((c) => c.status !== 'retired');

  if (currentKey && machineIdOfKey(currentKey) === machineId) {
    // Ya registrado con este machine-id: la clave no cambia (la de un clon es estable aunque
    // se purgue el original); el aviso, solo mientras otro lo comparta.
    if (!isCloneKey(currentKey))
      return { naturalKey: currentKey, clone: null, warnings: [] };
    return cloneDecision(currentKey, machineId, live);
  }
  if (currentKey && !isCloneKey(currentKey))
    return {
      naturalKey: currentKey,
      clone: null,
      warnings: [
        `machine-id distinto del registrado (${currentKey} → ${machineId}): ¿reinstalado o es otra máquina?`,
      ],
    };

  // Sin clave, o clon que ha regenerado su machine-id.
  const same = live.find(
    (c) => !c.hostKeyFingerprint || input.scanned.includes(c.hostKeyFingerprint),
  );
  if (same) return { duplicateOf: { id: same.id, name: same.name } };
  if (live.length > 0)
    return cloneDecision(
      cloneNaturalKey(machineId, input.fingerprint),
      machineId,
      live,
    );
  const retired = others.find((c) => c.naturalKey === machineId);
  if (retired)
    return {
      naturalKey: currentKey,
      clone: null,
      warnings: [
        `machine-id ${machineId} ya pertenece a un asset retirado (${retired.id}): no se asigna como clave natural`,
      ],
    };
  return { naturalKey: machineId, clone: null, warnings: [] };
}

function cloneDecision(
  naturalKey: string,
  machineId: string,
  live: readonly IdentityCandidate[],
): IdentityDecision {
  if (live.length === 0) return { naturalKey, clone: null, warnings: [] };
  const sharedWith = live
    .map(({ id, name }) => ({ id, name }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  // No es una recolección parcial: el aviso va en su propio campo (`machineIdClone`).
  return { naturalKey, clone: { machineId, sharedWith }, warnings: [] };
}
