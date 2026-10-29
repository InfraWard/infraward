/* eslint-disable @typescript-eslint/no-explicit-any -- facts de prueba mutados a mano */
import { describe, expect, it } from 'vitest';
import { SAMPLE_FACTS, collected, proxmox } from './fixtures/facts.js';
import {
  MAX_SNAPSHOT_CHANGES,
  VOLATILE_FACT_PATHS,
  VOLATILE_LIST_ITEMS,
  diffSnapshots,
  hasChanges,
  stripVolatile,
} from './snapshot-diff.js';

const clone = <T>(v: T): T => structuredClone(v);

/** ¿Existe la ruta (con `*`) en algún valor? */
function exists(value: unknown, path: string[]): boolean {
  if (path.length === 0) return value !== undefined;
  const [head, ...rest] = path;
  if (head === '*') {
    const values = Array.isArray(value)
      ? value
      : value && typeof value === 'object'
        ? Object.values(value)
        : [];
    return values.some((v) => exists(v, rest));
  }
  return (
    !!value &&
    typeof value === 'object' &&
    exists((value as Record<string, unknown>)[head], rest)
  );
}

/** Rutas de todas las hojas (valores simples) de un valor, con índices concretos. */
function leaves(
  value: unknown,
  path: (string | number)[] = [],
): (string | number)[][] {
  if (Array.isArray(value))
    return value.flatMap((v, i) => leaves(v, [...path, i]));
  if (value && typeof value === 'object')
    return Object.entries(value).flatMap(([k, v]) => leaves(v, [...path, k]));
  return [path];
}

function setAt(
  target: unknown,
  path: (string | number)[],
  value: unknown,
): void {
  let cur = target as Record<string | number, unknown>;
  for (const p of path.slice(0, -1))
    cur = cur[p] as Record<string | number, unknown>;
  cur[path[path.length - 1]] = value;
}

describe('VOLATILE_FACT_PATHS', () => {
  it.each(VOLATILE_FACT_PATHS.map((v) => [v.path, v.why]))(
    '%s existe en los facts de algún tipo (%s)',
    (path) => {
      expect(
        Object.values(SAMPLE_FACTS).some((f) => exists(f, path.split('.'))),
      ).toBe(true);
    },
  );

  it.each(VOLATILE_LIST_ITEMS.map((v) => [v.path, v.why]))(
    'elementos de %s que no cuentan (%s): existen en los ejemplos y se ignoran',
    (path) => {
      const owner = Object.values(SAMPLE_FACTS).find((f) => {
        const list = path.split('.').reduce<any>((v, k) => v?.[k], f);
        return (
          Array.isArray(list) &&
          list.some((i) =>
            VOLATILE_LIST_ITEMS.find((v) => v.path === path)!.match(i),
          )
        );
      });
      expect(owner).toBeDefined();
      const next = clone(owner!) as Record<string, any>;
      const list = path.split('.').reduce<any>((v, k) => v[k], next) as Record<
        string,
        unknown
      >[];
      const rule = VOLATILE_LIST_ITEMS.find((v) => v.path === path)!;
      // Cambia, desaparece o aparece: no cuenta.
      const index = list.findIndex((item) => rule.match(item));
      const [removed] = list.splice(index, 1);
      list.push({ ...removed, mac: 'zz:zz', state: 'inactive' });
      const extra =
        path === 'services'
          ? 'dbus-org.freedesktop.hostname1.service'
          : 'veth9999aaa';
      list.push({ ...removed, name: extra });
      expect(
        hasChanges({ facts: owner!, roles: [] }, { facts: next, roles: [] }),
      ).toBe(false);
    },
  );

  it('cambiar solo lo volátil no es un cambio', () => {
    for (const facts of Object.values(SAMPLE_FACTS)) {
      const next = clone(facts) as Record<string, any>;
      if (next.infraward) next.infraward.collectedAt = '2030-01-01T00:00:00Z';
      if (next.mounts) next.mounts[0].availableBytes = 1;
      if (next.ports) next.ports[0].pid = 9999;
      if (next.proxmox) {
        next.proxmox.uptime = 1;
        next.proxmox.discoveredAt = 'x';
        next.proxmox.config.lock = 'migrate';
      }
      for (const k of ['docker', 'plesk', 'certificate'])
        if (next[k]) next[k].discoveredAt = 'x';
      if (next.docker?.startedAt) next.docker.startedAt = 'x';
      expect(
        hasChanges({ facts, roles: ['a'] }, { facts: next, roles: ['a'] }),
      ).toBe(false);
    }
  });

  it('cualquier otra hoja de los facts cuenta como cambio (nada se ignora sin estar en la lista)', () => {
    for (const [type, facts] of Object.entries(SAMPLE_FACTS)) {
      const stripped = stripVolatile(facts);
      for (const leaf of leaves(stripped)) {
        const next = clone(stripped) as Record<string, unknown>;
        const before = leaf.reduce<any>((v, k) => v[k], next);
        setAt(
          next,
          leaf,
          typeof before === 'number' ? before + 1 : `${String(before)}-x`,
        );
        expect(
          hasChanges({ facts, roles: [] }, { facts: next, roles: [] }),
          `${type}: ${leaf.join('.')}`,
        ).toBe(true);
      }
    }
  });
});

describe('diffSnapshots', () => {
  const base = {
    facts: collected as unknown as Record<string, unknown>,
    roles: ['proxmox-node'],
  };

  it('sin cambios: vacío', () => {
    expect(diffSnapshots(base, clone(base))).toEqual({
      changes: [],
      summary: [],
      truncated: false,
    });
  });

  it('paquetes por clave: añadido, quitado y versión cambiada', () => {
    const next = clone(base) as any;
    next.facts.packages = [
      { name: 'openssl', version: '3.0.12-1', arch: 'amd64', manager: 'dpkg' },
      { name: 'nginx', version: '1.25', arch: 'amd64', manager: 'dpkg' },
    ];
    const diff = diffSnapshots(base, next);
    expect(diff.changes).toEqual([
      {
        path: 'packages[curl:amd64]',
        kind: 'removed',
        before: expect.objectContaining({ name: 'curl' }),
      },
      {
        path: 'packages[nginx:amd64]',
        kind: 'added',
        after: expect.objectContaining({ name: 'nginx' }),
      },
      {
        path: 'packages[openssl:amd64].version',
        kind: 'changed',
        before: '3.0.11-1',
        after: '3.0.12-1',
      },
    ]);
    expect(diff.summary).toEqual([
      { section: 'packages', added: 1, removed: 1, changed: 1 },
    ]);
  });

  it('puertos, roles y listas simples', () => {
    const next = clone(base) as any;
    next.roles = ['proxmox-node', 'docker-host'];
    next.facts.ports.push({
      proto: 'tcp',
      address: '0.0.0.0',
      port: 8006,
      process: 'pveproxy',
      pid: 1,
    });
    next.facts.network.interfaces[0].ipv4 = ['172.20.10.191'];
    const paths = diffSnapshots(base, next).changes.map(
      (c) => `${c.kind} ${c.path}`,
    );
    expect(paths).toEqual([
      'added roles',
      'removed network.interfaces[vmbr0].ipv4',
      'added network.interfaces[vmbr0].ipv4',
      'added ports[tcp 0.0.0.0:8006]',
    ]);
  });

  it('config de Proxmox de un CT', () => {
    const prev = { facts: { proxmox }, roles: [] };
    const next = clone(prev) as any;
    next.facts.proxmox.config.memory = 4096;
    next.facts.proxmox.maxMemBytes = 4096;
    expect(diffSnapshots(prev, next).changes).toEqual([
      {
        path: 'proxmox.config.memory',
        kind: 'changed',
        before: 2048,
        after: 4096,
      },
      {
        path: 'proxmox.maxMemBytes',
        kind: 'changed',
        before: 2048,
        after: 4096,
      },
    ]);
  });

  it('claves repetidas (dos versiones del mismo paquete) no se pisan', () => {
    const prev = {
      facts: {
        packages: [
          { name: 'k', arch: 'x', version: '1' },
          { name: 'k', arch: 'x', version: '2' },
        ],
      },
      roles: [],
    };
    const next = clone(prev) as any;
    next.facts.packages.pop();
    expect(diffSnapshots(prev, next).changes).toEqual([
      {
        path: 'packages[k:x#2]',
        kind: 'removed',
        before: { name: 'k', arch: 'x', version: '2' },
      },
    ]);
  });

  it('corta la lista de cambios pero el resumen cuenta todos', () => {
    const many = (n: number) =>
      Array.from({ length: n }, (_, i) => ({
        name: `p${i}`,
        version: '1',
        arch: null,
      }));
    const diff = diffSnapshots(
      { facts: { packages: [] }, roles: [] },
      { facts: { packages: many(MAX_SNAPSHOT_CHANGES + 5) }, roles: [] },
    );
    expect(diff.truncated).toBe(true);
    expect(diff.changes).toHaveLength(MAX_SNAPSHOT_CHANGES);
    expect(diff.summary[0].added).toBe(MAX_SNAPSHOT_CHANGES + 5);
  });
});
