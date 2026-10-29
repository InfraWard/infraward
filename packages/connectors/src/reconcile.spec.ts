import { describe, expect, it } from 'vitest';
import {
  seenKey,
  type DiscoveredAsset,
  type DiscoveryListing,
} from './discoverer.js';
import { planReconcile, type ExistingChild } from './reconcile.js';

const PARENT = 'node-a';
const TYPES = ['lxc', 'vm'] as const;

const guest = (
  vmid: number,
  extra: Partial<DiscoveredAsset> = {},
): DiscoveredAsset => ({
  type: 'lxc',
  name: `ct-${vmid}`,
  naturalKey: `proxmox:cluster:lab:${vmid}`,
  aliases: [],
  facts: { proxmox: { vmid } },
  collect: true,
  ...extra,
});

const existing = (
  id: string,
  vmid: number,
  extra: Partial<ExistingChild> = {},
): ExistingChild => ({
  id,
  type: 'lxc',
  naturalKey: `proxmox:cluster:lab:${vmid}`,
  status: 'active',
  parentId: PARENT,
  ...extra,
});

function listing(
  children: DiscoveredAsset[],
  extra: Partial<DiscoveryListing> = {},
): DiscoveryListing {
  return {
    children,
    seen: new Set(children.map((c) => seenKey(c.type, c.naturalKey))),
    complete: true,
    warnings: [],
    ...extra,
  };
}

const plan = (l: DiscoveryListing, e: ExistingChild[]) =>
  planReconcile({
    parentId: PARENT,
    childTypes: TYPES,
    listing: l,
    existing: e,
  });

describe('planReconcile', () => {
  it('crea lo nuevo y actualiza lo conocido sin duplicar', () => {
    const p = plan(listing([guest(100), guest(101)]), [existing('a1', 100)]);
    expect(p.create.map((c) => c.naturalKey)).toEqual([
      'proxmox:cluster:lab:101',
    ]);
    expect(p.update).toEqual([
      expect.objectContaining({
        id: 'a1',
        rename: null,
        attach: false,
        reactivate: false,
      }),
    ]);
    expect(p.missing).toEqual([]);
  });

  it('la misma clave con otro tipo es otro asset', () => {
    const p = plan(listing([guest(100, { type: 'vm' })]), [
      existing('a1', 100),
    ]);
    expect(p.create).toHaveLength(1);
    // El lxc 100 ya no existe como lxc: desaparece.
    expect(p.missing).toEqual(['a1']);
  });

  it('migración: un CT que estaba en otro nodo cambia de padre', () => {
    const p = plan(listing([guest(100)]), [
      existing('a1', 100, { parentId: 'node-b' }),
    ]);
    expect(p.update[0]).toMatchObject({
      attach: true,
      previousParentId: 'node-b',
    });
  });

  it('un hijo sin padre se cuelga de este', () => {
    const p = plan(listing([guest(100)]), [
      existing('a1', 100, { parentId: null }),
    ]);
    expect(p.update[0]).toMatchObject({ attach: true, previousParentId: null });
  });

  it('un CT que ahora está en otro nodo del clúster no ha desaparecido', () => {
    const other = guest(300);
    const l = listing([guest(100)]);
    l.seen.add(seenKey(other.type, other.naturalKey));
    const p = plan(l, [existing('a1', 100), existing('a3', 300)]);
    expect(p.missing).toEqual([]);
  });

  it('lo que ya no existe pasa a missing', () => {
    const p = plan(listing([guest(100)]), [
      existing('a1', 100),
      existing('a2', 101),
      existing('vm', 200, { type: 'vm' }),
    ]);
    expect(p.missing.sort()).toEqual(['a2', 'vm']);
  });

  it('con el listado incompleto no se marca nada como missing', () => {
    const p = plan(listing([guest(100)], { complete: false }), [
      existing('a1', 100),
      existing('a2', 101),
    ]);
    expect(p.missing).toEqual([]);
    expect(p.update).toHaveLength(1);
  });

  it('no toca hijos de otros padres, de otros tipos, sin clave natural ni ya missing/retired', () => {
    const p = plan(listing([]), [
      existing('otro-padre', 101, { parentId: 'node-b' }),
      existing('docker', 102, { type: 'container' }),
      existing('manual', 103, { naturalKey: null }),
      existing('ya-missing', 104, { status: 'missing' }),
      existing('baja', 105, { status: 'retired' }),
    ]);
    expect(p.missing).toEqual([]);
    // El ya missing de este padre suma una ejecución sin verse; los demás, nada.
    expect(p.stillMissing).toEqual(['ya-missing']);
  });

  it('missing que sigue sin verse: solo con el listado completo y fuera de los tipos parciales', () => {
    const gone = [existing('m1', 100, { status: 'missing' })];
    expect(plan(listing([]), gone).stillMissing).toEqual(['m1']);
    expect(plan(listing([], { complete: false }), gone).stillMissing).toEqual([]);
    expect(
      plan(listing([], { partialTypes: ['lxc'] }), gone).stillMissing,
    ).toEqual([]);
  });

  it('retirado automáticamente que reaparece ⇒ vuelve a active', () => {
    const p = plan(listing([guest(100)]), [
      existing('a1', 100, { status: 'retired', retiredAuto: true }),
    ]);
    expect(p.update).toEqual([
      expect.objectContaining({ id: 'a1', reactivate: true }),
    ]);
    expect(p.warnings).toEqual([]);
  });

  it('reaparece ⇒ vuelve a active', () => {
    const p = plan(listing([guest(100)]), [
      existing('a1', 100, { status: 'missing' }),
    ]);
    expect(p.update[0].reactivate).toBe(true);
  });

  it('un retired no se reactiva ni se actualiza: aviso', () => {
    const p = plan(listing([guest(100)]), [
      existing('a1', 100, { status: 'retired' }),
    ]);
    expect(p.update).toEqual([]);
    expect(p.create).toEqual([]);
    expect(p.warnings[0]).toMatch(/dado de baja/);
  });

  it('nodo que se une a un clúster: renombra la clave antigua (conserva el asset)', () => {
    const old = 'proxmox:node:eb57e19d4b83a685907fc4121c8af3a3:100';
    const p = plan(listing([guest(100, { aliases: [old] })]), [
      existing('a1', 0, { naturalKey: old }),
    ]);
    expect(p.create).toEqual([]);
    expect(p.update[0]).toMatchObject({
      id: 'a1',
      rename: 'proxmox:cluster:lab:100',
    });
    expect(p.missing).toEqual([]);
  });

  it('si existen la clave nueva y la antigua, se usa la nueva y la antigua desaparece', () => {
    const old = 'proxmox:node:eb57e19d4b83a685907fc4121c8af3a3:100';
    const p = plan(listing([guest(100, { aliases: [old] })]), [
      existing('nuevo', 100),
      existing('viejo', 0, { naturalKey: old }),
    ]);
    expect(p.update.map((u) => [u.id, u.rename])).toEqual([['nuevo', null]]);
    expect(p.missing).toEqual(['viejo']);
    expect(p.warnings[0]).toMatch(/antigua/);
  });

  it('tipos con listado parcial: nunca pasan a missing, el resto sí', () => {
    const p = planReconcile({
      parentId: PARENT,
      childTypes: ['container', 'volume'],
      listing: listing([], { partialTypes: ['volume'] }),
      existing: [
        { ...existing('c1', 1), type: 'container', naturalKey: 'docker:c1' },
        { ...existing('v1', 2), type: 'volume', naturalKey: 'docker-volume:v1' },
      ],
    });
    expect(p.missing).toEqual(['c1']);
  });

  it('hijos anidados: cuelgan de otro hijo del listado; el ámbito es el subárbol', () => {
    const sub = {
      type: 'subscription' as const,
      name: 'ejemplo.com',
      naturalKey: 'plesk:s:ejemplo.com',
      aliases: [],
      facts: {},
      collect: false,
    };
    const dom = {
      ...sub,
      type: 'domain' as const,
      naturalKey: 'plesk:d:ejemplo.com',
      parent: { type: sub.type, naturalKey: sub.naturalKey },
    };
    const types = ['subscription', 'domain'] as const;
    // Nuevo: se crean en orden y el dominio lleva su padre.
    const fresh = planReconcile({
      parentId: PARENT,
      childTypes: types,
      listing: listing([sub, dom]),
      existing: [],
    });
    expect(fresh.create.map((c) => c.parent ?? null)).toEqual([
      null,
      { type: 'subscription', naturalKey: 'plesk:s:ejemplo.com' },
    ]);
    // Ya colgado de su suscripción: no se mueve. Colgado de otra: se mueve.
    const known = (domParent: string): ExistingChild[] => [
      { id: 's1', type: 'subscription', naturalKey: sub.naturalKey, status: 'active', parentId: PARENT, inScope: true },
      { id: 'd1', type: 'domain', naturalKey: dom.naturalKey, status: 'active', parentId: domParent, inScope: true },
    ];
    const same = planReconcile({ parentId: PARENT, childTypes: types, listing: listing([sub, dom]), existing: known('s1') });
    expect(same.update.map((u) => [u.id, u.attach])).toEqual([['s1', false], ['d1', false]]);
    const moved = planReconcile({ parentId: PARENT, childTypes: types, listing: listing([sub, dom]), existing: known('otra') });
    expect(moved.update.find((u) => u.id === 'd1')).toMatchObject({ attach: true, parent: dom.parent });
    // Un dominio del subárbol que ya no está desaparece aunque no cuelgue directamente del padre.
    const gone = planReconcile({ parentId: PARENT, childTypes: types, listing: listing([sub]), existing: known('s1') });
    expect(gone.missing).toEqual(['d1']);
    // Fuera del ámbito (otro subárbol): no.
    const outside = planReconcile({
      parentId: PARENT,
      childTypes: types,
      listing: listing([sub]),
      existing: [known('s1')[0]!, { ...known('x')[1]!, inScope: false }],
    });
    expect(outside.missing).toEqual([]);
  });
});
