import type { ProxmoxGuestFacts } from '@infraward/shared-types';
import { DISCOVERABLE_ROLES } from '@infraward/shared-types';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DiscoveryError,
  type HostCommandResult,
  type HostExec,
} from '../discoverer.js';
import { createDiscoverers } from '../index.js';
import { expandQuery } from '../privileged.js';
import {
  parseClusterResources,
  parseClusterStatus,
  parseInterfaces,
  proxmoxNaturalKey,
  ProxmoxDiscoverer,
  sanitizeGuestConfig,
} from './proxmox.js';

const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

const MACHINE_ID = 'eb57e19d4b83a685907fc4121c8af3a3';
const NOW = new Date('2026-10-09T12:00:00Z');
const PARENT = { id: 'node-1', name: 'pve', facts: { machineId: MACHINE_ID } };

/** Host simulado: responde a cada ruta de pvesh con un fixture o un fallo. */
function host(
  overrides: Record<string, HostCommandResult | string> = {},
  status = 'cluster-status-standalone.json',
) {
  const calls: { argv: string[]; sudo?: boolean }[] = [];
  const routes: Record<string, HostCommandResult | string> = {
    '/cluster/status': fixture(status),
    '/cluster/resources': fixture('cluster-resources.json'),
    '/nodes/pve/lxc/100/config': fixture('lxc-config.json'),
    '/nodes/pve/lxc/101/config': fixture('lxc-config.json'),
    '/nodes/pve/lxc/900/config': fixture('lxc-config.json'),
    '/nodes/pve/qemu/200/config': fixture('qemu-config.json'),
    '/nodes/pve/lxc/100/interfaces': fixture('lxc-interfaces.json'),
    ...overrides,
  };
  const exec: HostExec = {
    run: (argv) => {
      throw new Error(`comando sin el ayudante: ${argv.join(' ')}`);
    },
    query: (q) => {
      const argv = expandQuery(q);
      calls.push({ argv, sudo: true });
      const route = routes[argv[2]];
      if (route === undefined)
        return Promise.resolve({ code: 2, stdout: '', stderr: 'no route' });
      return Promise.resolve(
        typeof route === 'string'
          ? { code: 0, stdout: route, stderr: '' }
          : route,
      );
    },
  };
  return { exec, calls };
}

const proxmoxOf = (facts: Record<string, unknown>) =>
  facts.proxmox as ProxmoxGuestFacts;

describe('parseo de pvesh', () => {
  it('nodo local sin clúster y con clúster', () => {
    expect(
      parseClusterStatus(fixture('cluster-status-standalone.json')),
    ).toEqual({ localNode: 'pve', cluster: null });
    expect(parseClusterStatus(fixture('cluster-status-cluster.json'))).toEqual({
      localNode: 'pve',
      cluster: 'lab',
    });
  });

  it('rechaza un estado sin nodo local, con nombres peligrosos o que no es JSON', () => {
    expect(() =>
      parseClusterStatus('[{"type":"node","name":"pve","local":0}]'),
    ).toThrow(DiscoveryError);
    expect(() =>
      parseClusterStatus('[{"type":"node","name":"../etc","local":1}]'),
    ).toThrow(DiscoveryError);
    expect(() =>
      parseClusterStatus(
        '[{"type":"node","name":"pve","local":1},{"type":"cluster","name":"a b;rm"}]',
      ),
    ).toThrow(DiscoveryError);
    expect(() => parseClusterStatus('no json')).toThrow(DiscoveryError);
    expect(() => parseClusterStatus('{}')).toThrow(DiscoveryError);
  });

  it('solo CT y VMs, con sus datos', () => {
    const { resources, invalid } = parseClusterResources(
      fixture('cluster-resources.json'),
    );
    expect(invalid).toBe(0);
    expect(resources.map((r) => `${r.kind}/${r.vmid}@${r.node}`)).toEqual([
      'lxc/100@pve',
      'lxc/101@pve',
      'qemu/200@pve',
      'lxc/900@pve',
      'lxc/300@pve2',
    ]);
    expect(resources[0]).toMatchObject({
      name: 'debian',
      status: 'running',
      template: false,
      maxmem: 536870912,
      tags: ['web', 'prod'],
    });
    expect(resources[3].template).toBe(true);
  });

  it('descarta vmid y nodos no válidos y los cuenta', () => {
    const { resources, invalid } = parseClusterResources(
      JSON.stringify([
        { type: 'lxc', vmid: 100, node: 'pve' },
        { type: 'lxc', vmid: '101', node: 'pve' },
        { type: 'lxc', vmid: 99, node: 'pve' },
        { type: 'qemu', vmid: 102, node: 'pve;reboot' },
      ]),
    );
    expect(resources).toHaveLength(1);
    expect(invalid).toBe(3);
  });

  it('la configuración pierde contraseñas, claves, notas y ruido', () => {
    const lxc = sanitizeGuestConfig(JSON.parse(fixture('lxc-config.json')));
    expect(lxc).not.toHaveProperty('description');
    expect(lxc).not.toHaveProperty('digest');
    expect(JSON.stringify(lxc)).not.toContain('hunter2');
    expect(lxc).toMatchObject({ hostname: 'debian', memory: 512 });

    const qemu = sanitizeGuestConfig(JSON.parse(fixture('qemu-config.json')));
    expect(qemu).not.toHaveProperty('cipassword');
    expect(qemu).not.toHaveProperty('sshkeys');
    expect(qemu).not.toHaveProperty('meta');
    expect(JSON.stringify(qemu)).not.toContain('$5$');
    expect(qemu).toMatchObject({ ciuser: 'admin', cores: 4 });
  });

  it('interfaces sin loopback, en los dos formatos', () => {
    expect(parseInterfaces(fixture('lxc-interfaces.json'))).toEqual([
      {
        name: 'eth0',
        mac: 'bc:24:11:aa:bb:cc',
        ipv4: ['192.168.1.50/24'],
        ipv6: [
          'fe80::be24:11ff:feaa:bbcc/64',
          '2a0c:5a85:a004:cb00:be24:11ff:feaa:bbcc/64',
        ],
      },
    ]);
    expect(
      parseInterfaces(
        JSON.stringify([
          {
            name: 'eth0',
            hwaddr: 'aa',
            'ip-addresses': [
              {
                'ip-address': '10.0.0.5',
                'ip-address-type': 'ipv4',
                prefix: 24,
              },
              {
                'ip-address': 'fd00::5',
                'ip-address-type': 'ipv6',
                prefix: 64,
              },
            ],
          },
        ]),
      ),
    ).toEqual([
      { name: 'eth0', mac: 'aa', ipv4: ['10.0.0.5/24'], ipv6: ['fd00::5/64'] },
    ]);
  });

  it('clave natural: clúster + vmid, o machine-id del nodo sin clúster', () => {
    expect(
      proxmoxNaturalKey({ cluster: 'lab', machineId: MACHINE_ID }, 100),
    ).toBe('proxmox:cluster:lab:100');
    expect(
      proxmoxNaturalKey({ cluster: null, machineId: MACHINE_ID }, 100),
    ).toBe(`proxmox:node:${MACHINE_ID}:100`);
  });
});

describe('ProxmoxDiscoverer.discover', () => {
  const discoverer = new ProxmoxDiscoverer(() => NOW);

  it('nodo sin clúster: hijos del nodo con claves, facts saneados y qué recoger', async () => {
    const { exec, calls } = host();
    const listing = await discoverer.discover(PARENT, exec);

    expect(listing.complete).toBe(true);
    expect(listing.warnings).toEqual([]);
    expect(
      listing.children.map((c) => [c.type, c.name, c.naturalKey, c.collect]),
    ).toEqual([
      ['lxc', 'debian', `proxmox:node:${MACHINE_ID}:100`, true],
      ['lxc', 'docker', `proxmox:node:${MACHINE_ID}:101`, false],
      ['vm', 'win', `proxmox:node:${MACHINE_ID}:200`, false],
      ['lxc', 'tpl', `proxmox:node:${MACHINE_ID}:900`, false],
    ]);
    expect(listing.children.every((c) => c.aliases.length === 0)).toBe(true);
    // El CT del otro nodo existe (no ha desaparecido) aunque no sea hijo de este.
    expect(listing.seen.has(`lxc|proxmox:node:${MACHINE_ID}:300`)).toBe(true);

    const ct = proxmoxOf(listing.children[0].facts);
    expect(ct).toMatchObject({
      vmid: 100,
      kind: 'lxc',
      node: 'pve',
      cluster: null,
      status: 'running',
      cpus: 1,
      maxMemBytes: 536870912,
      tags: ['web', 'prod'],
      discoveredAt: NOW.toISOString(),
    });
    expect(ct.interfaces?.[0].ipv4).toEqual(['192.168.1.50/24']);
    expect(ct.config).not.toHaveProperty('description');
    const vm = proxmoxOf(listing.children[2].facts);
    expect(vm.config).not.toHaveProperty('cipassword');
    expect(vm.interfaces).toBeNull();

    // Solo `pvesh get` por el ayudante, con rutas que compone él.
    for (const c of calls) {
      expect(c.sudo).toBe(true);
      expect(c.argv.slice(0, 2)).toEqual(['pvesh', 'get']);
      expect(c.argv.slice(-2)).toEqual(['--output-format', 'json']);
    }
    // Interfaces solo de los CT en marcha.
    expect(calls.filter((c) => c.argv[2].endsWith('/interfaces'))).toHaveLength(
      1,
    );
  });

  it('con clúster: clave de clúster y la del nodo como alias', async () => {
    const { exec } = host({}, 'cluster-status-cluster.json');
    const listing = await discoverer.discover(PARENT, exec);
    expect(listing.children[0].naturalKey).toBe('proxmox:cluster:lab:100');
    expect(listing.children[0].aliases).toEqual([
      `proxmox:node:${MACHINE_ID}:100`,
    ]);
    expect(proxmoxOf(listing.children[0].facts).cluster).toBe('lab');
    expect(listing.seen.has('lxc|proxmox:cluster:lab:300')).toBe(true);
  });

  it('si falla el listado, falla entero (no devuelve un listado parcial)', async () => {
    const failing = { code: 255, stdout: '', stderr: 'ipcc_send_rec failed' };
    await expect(
      discoverer.discover(PARENT, host({ '/cluster/resources': failing }).exec),
    ).rejects.toThrow(
      'No se pudo listar Proxmox: pvesh get /cluster/resources falló (código 255): ipcc_send_rec failed',
    );
    await expect(
      discoverer.discover(
        PARENT,
        host({ '/cluster/status': { code: null, stdout: '', stderr: '' } })
          .exec,
      ),
    ).rejects.toThrow(/tiempo agotado/);
    await expect(
      discoverer.discover(PARENT, host({ '/cluster/resources': '[{' }).exec),
    ).rejects.toThrow(DiscoveryError);
  });

  it('un fallo de config o interfaces es un aviso; el listado sigue completo', async () => {
    const failing = { code: 1, stdout: '', stderr: 'permission denied' };
    const listing = await discoverer.discover(
      PARENT,
      host({
        '/nodes/pve/qemu/200/config': failing,
        '/nodes/pve/lxc/100/interfaces': failing,
      }).exec,
    );
    expect(listing.complete).toBe(true);
    expect(listing.warnings).toHaveLength(2);
    expect(proxmoxOf(listing.children[2].facts).config).toBeNull();
    expect(proxmoxOf(listing.children[0].facts).interfaces).toBeNull();
  });

  it('entradas no válidas: aviso y listado incompleto', async () => {
    const resources = JSON.parse(
      fixture('cluster-resources.json'),
    ) as unknown[];
    resources.push({ type: 'lxc', vmid: 'x', node: 'pve' });
    const listing = await discoverer.discover(
      PARENT,
      host({ '/cluster/resources': JSON.stringify(resources) }).exec,
    );
    expect(listing.complete).toBe(false);
    expect(listing.warnings[0]).toMatch(/no se marca nada como desaparecido/);
  });

  it('sin machine-id del nodo no descubre nada', async () => {
    const { exec, calls } = host();
    await expect(
      discoverer.discover({ ...PARENT, facts: {} }, exec),
    ).rejects.toThrow(/machine-id/);
    expect(calls).toHaveLength(0);
  });
});

describe('ProxmoxDiscoverer.collectTarget', () => {
  const discoverer = new ProxmoxDiscoverer();
  const ct = (proxmox: Partial<ProxmoxGuestFacts>) => ({
    type: 'lxc' as const,
    facts: {
      proxmox: { vmid: 100, status: 'running', template: false, ...proxmox },
    },
  });

  it('CT en marcha ⇒ pct exec con su vmid', () => {
    expect(discoverer.collectTarget(ct({}))).toEqual({
      target: { kind: 'pct', vmid: 100 },
    });
  });

  it('VMs, CT parados, plantillas y assets ajenos no se recogen', () => {
    expect(
      discoverer.collectTarget({ type: 'vm', facts: {} }).target,
    ).toBeNull();
    expect(discoverer.collectTarget(ct({ status: 'stopped' }))).toMatchObject({
      target: null,
      reason: expect.stringMatching(/no está en marcha/),
    });
    expect(discoverer.collectTarget(ct({ template: true })).target).toBeNull();
    expect(
      discoverer.collectTarget({ type: 'lxc', facts: {} }).target,
    ).toBeNull();
    expect(
      discoverer.collectTarget(ct({ vmid: '100; reboot' as unknown as number }))
        .target,
    ).toBeNull();
  });
});

describe('registro', () => {
  it('hay un descubridor por cada rol descubrible de shared-types', () => {
    expect([...createDiscoverers().keys()].sort()).toEqual(
      [...DISCOVERABLE_ROLES].sort(),
    );
  });
});
