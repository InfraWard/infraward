import { describe, expect, it } from 'vitest';
import {
  cloneNaturalKey,
  decideMachineIdentity,
  machineIdOfKey,
  type IdentityCandidate,
  type IdentityInput,
} from './machine-identity.js';

const MID = 'eb57e19d4b83a685907fc4121c8af3a3';
const MINE = 'SHA256:mine';
const OTHER = 'SHA256:other';

const candidate = (c: Partial<IdentityCandidate>): IdentityCandidate => ({
  id: 'orig',
  name: 'original',
  status: 'active',
  naturalKey: MID,
  hostKeyFingerprint: OTHER,
  ...c,
});

const decide = (input: Partial<IdentityInput>) =>
  decideMachineIdentity({
    assetId: 'me',
    currentKey: null,
    machineId: MID,
    fingerprint: MINE,
    scanned: [MINE],
    candidates: [],
    ...input,
  });

describe('decideMachineIdentity', () => {
  it('sin nadie con el machine-id: la clave es el machine-id', () => {
    expect(decide({})).toEqual({ naturalKey: MID, clone: null, warnings: [] });
  });

  it('host key en común con el dueño: la misma máquina (duplicado)', () => {
    expect(
      decide({
        scanned: [MINE, OTHER],
        candidates: [candidate({})],
      }),
    ).toEqual({ duplicateOf: { id: 'orig', name: 'original' } });
  });

  it('dueño sin huella fijada: duplicado (conservador)', () => {
    expect(
      decide({ candidates: [candidate({ hostKeyFingerprint: null })] })
        .duplicateOf,
    ).toEqual({ id: 'orig', name: 'original' });
  });

  it('host keys distintas: clon con clave compuesta y aviso', () => {
    const d = decide({ candidates: [candidate({})] });
    expect(d).toMatchObject({
      naturalKey: cloneNaturalKey(MID, MINE),
      clone: { machineId: MID, sharedWith: [{ id: 'orig', name: 'original' }] },
    });
    expect(d.duplicateOf).toBeUndefined();
    // No es una recolección parcial: el aviso es `clone`.
    expect(!d.duplicateOf && d.warnings).toEqual([]);
  });

  it('tercer clon: compara también con las claves de los clones y los lista a todos', () => {
    const clone2 = candidate({
      id: 'c2',
      name: 'clon-2',
      naturalKey: cloneNaturalKey(MID, 'SHA256:c2'),
      hostKeyFingerprint: 'SHA256:c2',
    });
    expect(
      decide({ candidates: [candidate({}), clone2] }),
    ).toMatchObject({
      naturalKey: cloneNaturalKey(MID, MINE),
      clone: { sharedWith: [{ id: 'c2' }, { id: 'orig' }] },
    });
    // Si comparte host key con el segundo clon, es ese clon dado de alta dos veces.
    expect(
      decide({
        scanned: ['SHA256:c2'],
        candidates: [candidate({}), clone2],
      }).duplicateOf,
    ).toEqual({ id: 'c2', name: 'clon-2' });
  });

  it('clon ya registrado: conserva su clave y el aviso mientras otro comparta el machine-id', () => {
    const key = cloneNaturalKey(MID, MINE);
    expect(
      decide({ currentKey: key, candidates: [candidate({})] }),
    ).toMatchObject({ naturalKey: key, clone: { machineId: MID } });
    // Purgado el original: la clave no cambia (estable) y el aviso desaparece.
    expect(decide({ currentKey: key })).toEqual({
      naturalKey: key,
      clone: null,
      warnings: [],
    });
  });

  it('clon que regenera su machine-id: pasa a la clave normal', () => {
    expect(
      decide({
        currentKey: cloneNaturalKey('viejo', MINE),
        candidates: [],
      }),
    ).toEqual({ naturalKey: MID, clone: null, warnings: [] });
  });

  it('el original (clave normal) no cambia ni recibe aviso por tener clones', () => {
    expect(
      decide({
        currentKey: MID,
        candidates: [
          candidate({
            id: 'c',
            naturalKey: cloneNaturalKey(MID, OTHER),
          }),
        ],
      }),
    ).toEqual({ naturalKey: MID, clone: null, warnings: [] });
  });

  it('clave normal distinta: aviso y se conserva', () => {
    const d = decide({ currentKey: 'anterior' });
    expect(d).toMatchObject({ naturalKey: 'anterior' });
    expect(!d.duplicateOf && d.warnings[0]).toMatch(/distinto del registrado/);
  });

  it('machine-id de un retirado: aviso y sin clave', () => {
    const d = decide({ candidates: [candidate({ status: 'retired' })] });
    expect(d).toMatchObject({ naturalKey: null, clone: null });
    expect(!d.duplicateOf && d.warnings[0]).toMatch(/asset retirado \(orig\)/);
  });

  it('un clon retirado no cuenta como dueño', () => {
    expect(
      decide({
        candidates: [
          candidate({
            status: 'retired',
            naturalKey: cloneNaturalKey(MID, OTHER),
          }),
        ],
      }),
    ).toEqual({ naturalKey: MID, clone: null, warnings: [] });
  });

  it('machineIdOfKey', () => {
    expect(machineIdOfKey(MID)).toBe(MID);
    expect(machineIdOfKey(cloneNaturalKey(MID, 'SHA256:a+b'))).toBe(MID);
  });
});
