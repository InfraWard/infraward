import type { JobQueues } from './job-queues.js';
import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import {
  createDiscoverers,
  expandQuery,
  helperArgv,
  type HostCommandResult,
  type HostExec,
} from '@infraward/connectors';
import { AssetRelation } from '@infraward/domain';
import type { SecretsService } from '@infraward/secrets';
import type {
  AssetCollectJobResult,
  CollectedFacts,
  JobProgressEvent,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { readFileSync } from 'node:fs';
import type { DataSource } from 'typeorm';
import type { AnsibleRunner } from '../collect/ansible-runner.js';
import type { RawCollection } from '../collect/normalize.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { ScannedHostKey } from '../ssh/host-keys.js';
import type { SshClient } from '../ssh/ssh-client.js';
import type { DomainSync } from '../domains/domain-sync.js';
import { ListingReconciler } from '../inventory/listing-reconciler.js';
import type { InventoryReconciler } from '../inventory/reconciler.js';
import type { ScanScheduler } from '../scan/scan-scheduler.js';
import { AssetRoutes } from './asset-routes.js';
import { DiscoveryProcessor } from './discovery.processor.js';
import { SshIdentities } from '../ssh/ssh-identity.js';

const FP_GOOD = `SHA256:${'g'.repeat(43)}`;
const FP_EVIL = `SHA256:${'e'.repeat(43)}`;
const PRIVATE_KEY = 'clave-privada-centinela';
const REF = 'secret://local/assets/a1/ssh#privateKey';
const MACHINE_ID = 'eb57e19d4b83a685907fc4121c8af3a3';

const hostKey = (fingerprint: string): ScannedHostKey => ({
  keyType: 'ssh-ed25519',
  blob: 'AAAA',
  type: 'ED25519',
  fingerprint,
});

function raw(): RawCollection {
  const data = JSON.parse(
    readFileSync(
      new URL('../collect/fixtures/debian.json', import.meta.url),
      'utf8',
    ),
  ) as RawCollection;
  // Un nodo Proxmox con Docker.
  data.which.push('pveversion=/usr/bin/pveversion', 'docker=/usr/bin/docker');
  data.sudo.push(
    { item: { key: 'pveversion' }, rc: 0, stdout: 'pve-manager/9.0.3' },
    { item: { key: 'docker' }, rc: 0, stdout: '28.3.1' },
  );
  return data;
}

function setup(
  options: {
    status?: string;
    lockedStatus?: string;
    pinned?: string | null;
    lockedPinned?: string | null;
    scanned?: string[];
    naturalKey?: string | null;
    /** Asset que ya tiene el machine-id como clave natural. */
    owner?: {
      id: string;
      name?: string;
      status?: string;
      naturalKey?: string;
      hostKeyFingerprint?: string | null;
    } | null;
    roles?: string[];
    collect?: () => Promise<RawCollection>;
    /** Sustituye campos del asset (p. ej. un CT sin conexión propia). */
    asset?: Record<string, unknown>;
    /** Padre `contains` del asset. */
    parent?: Record<string, unknown> | null;
    jobName?: string;
    /** Respuestas del host en `asset.discover` (ruta de pvesh → resultado). */
    pvesh?: (argv: string[]) => HostCommandResult;
  } = {},
) {
  const asset = () => ({
    id: 'a1',
    type: 'server',
    name: 'pve',
    status: options.status ?? 'active',
    roles: options.roles ?? ['plesk', 'web'],
    naturalKey: options.naturalKey ?? null,
    facts: {} as Record<string, unknown>,
    connection: { host: '192.0.2.10', port: 22, user: 'inventory' },
    credentials: { sshPrivateKey: REF } as Record<string, string>,
    hostKeyFingerprint: options.pinned === undefined ? FP_GOOD : options.pinned,
    ...options.asset,
  });
  const parent = options.parent
    ? {
        id: 'node-1',
        type: 'server',
        name: 'pve',
        status: 'active',
        roles: ['proxmox-node'],
        facts: { machineId: MACHINE_ID },
        connection: { host: '192.0.2.20', port: 2222, user: 'inventory' },
        credentials: {
          sshPrivateKey: 'secret://local/assets/node-1/ssh#privateKey',
        },
        hostKeyFingerprint: FP_GOOD,
        ...options.parent,
      }
    : null;
  const saved: Record<string, unknown>[] = [];
  const updated: Record<string, unknown>[] = [];
  let transactions = 0;
  const manager = {
    findOne: vi.fn((_entity: unknown, opts: { lock?: unknown }) => {
      if (opts.lock) {
        const locked = asset();
        if (options.lockedStatus) locked.status = options.lockedStatus;
        if (options.lockedPinned !== undefined)
          locked.hostKeyFingerprint = options.lockedPinned;
        return Promise.resolve(locked);
      }
      return Promise.resolve(null);
    }),
    find: vi.fn(() =>
      Promise.resolve(
        options.owner
          ? [
              {
                name: 'otro',
                status: 'active',
                naturalKey: MACHINE_ID,
                hostKeyFingerprint: null,
                ...options.owner,
              },
            ]
          : [],
      ),
    ),
    update: vi.fn((_entity: unknown, id: string, data: object) => {
      updated.push({ id, ...data });
      return Promise.resolve();
    }),
    create: (_entity: unknown, data: Record<string, unknown>) => ({
      ...data,
      __entity: 'Snapshot',
    }),
    save: vi.fn((entity: Record<string, unknown>) => {
      saved.push(structuredClone(entity));
      return Promise.resolve(
        entity.__entity === 'Snapshot' ? { ...entity, id: 's1' } : entity,
      );
    }),
  };
  const db = {
    getRepository: (entity: unknown) => ({
      findOneBy: (where: { id?: string }) => {
        if (entity === AssetRelation)
          return Promise.resolve(
            parent ? { parentId: parent.id, childId: 'a1' } : null,
          );
        return Promise.resolve(where.id === 'node-1' ? parent : asset());
      },
      // La política se relee antes de decidir el SBOM del host.
      findOne: () => Promise.resolve(asset()),
    }),
    transaction: (cb: (m: unknown) => Promise<unknown>) => {
      transactions++;
      return cb(manager);
    },
  } as unknown as DataSource;
  const secrets = {
    resolve: vi.fn(() => Promise.resolve(PRIVATE_KEY)),
    sshCertificates: () => undefined,
  };
  const commands: string[][] = [];
  const ssh = {
    scanHostKeys: vi.fn(() =>
      Promise.resolve((options.scanned ?? [FP_GOOD]).map(hostKey)),
    ),
    session: vi.fn(
      (
        _target: unknown,
        _key: string,
        _hostKey: unknown,
        fn: (host: HostExec) => Promise<unknown>,
      ) =>
        fn({
          run: (argv) => {
            commands.push(argv);
            return Promise.resolve({ code: 1, stdout: '', stderr: 'x' });
          },
          // Como el SshClient real: `sudo -n <ayudante> <consulta> <args…>`.
          query: (q) => {
            commands.push(['sudo', '-n', ...helperArgv(q)]);
            return Promise.resolve(
              options.pvesh?.(expandQuery(q)) ?? {
                code: 1,
                stdout: '',
                stderr: 'x',
              },
            );
          },
        }),
    ),
  };
  const queue = {
    add: vi.fn((name: string) => Promise.resolve({ id: `queued-${name}` })),
  };
  const ansible = {
    collect: vi.fn(options.collect ?? (() => Promise.resolve(raw()))),
  };
  const scans = {
    afterDiscovery: vi.fn(() => Promise.resolve([] as string[])),
    enqueueHostScan: vi.fn((assetId: string) =>
      Promise.resolve(`host-scan-${assetId}`),
    ),
  };
  const config = { get: () => 1 } as unknown as ConfigService<
    EnvironmentVariables,
    true
  >;
  const processor = new DiscoveryProcessor(
    config,
    db,
    secrets as unknown as SecretsService,
    ssh as unknown as SshClient,
    ansible as unknown as AnsibleRunner,
    { ...queue, get: () => queue } as unknown as JobQueues,
    new AssetRoutes(db, createDiscoverers()),
    scans as unknown as ScanScheduler,
    new SshIdentities(secrets as unknown as SecretsService, config),
    { schedule: vi.fn(), run: vi.fn() } as unknown as InventoryReconciler,
    new ListingReconciler(config, db),
    {} as unknown as DomainSync,
  );
  const logs: string[] = [];
  const job = {
    id: 'job-1',
    name: options.jobName ?? 'asset.collect',
    data: { assetId: 'a1' },
    log: (line: string) => Promise.resolve(logs.push(line)),
    updateProgress: () => Promise.resolve(),
  } as unknown as Job;
  const events = () =>
    logs.map((l) => (JSON.parse(l) as JobProgressEvent).message);
  return {
    processor,
    job,
    ssh,
    secrets,
    ansible,
    queue,
    commands,
    saved,
    updated,
    events,
    transactions: () => transactions,
  };
}

const snapshotOf = (saved: Record<string, unknown>[]) =>
  saved.find((s) => s.__entity === 'Snapshot')!;
const assetOf = (saved: Record<string, unknown>[]) =>
  saved.find((s) => s.__entity !== 'Snapshot')!;

describe('DiscoveryProcessor', () => {
  it('recoge con la host key fijada: snapshot, facts, roles y machine-id', async () => {
    const t = setup({ scanned: [FP_EVIL, FP_GOOD] });
    const result = await t.processor.process(t.job);

    expect(t.secrets.resolve).toHaveBeenCalledWith(REF, { fresh: true });
    expect(t.ansible.collect).toHaveBeenCalledWith(
      { host: '192.0.2.10', port: 22, user: 'inventory' },
      { kind: 'key', privateKey: PRIVATE_KEY },
      hostKey(FP_GOOD),
      undefined,
    );
    expect(result).toEqual({
      assetId: 'a1',
      snapshotId: 's1',
      unchanged: false,
      duplicateOf: null,
      // plesk ya no se detecta y se quita; web es manual y se conserva.
      roles: ['docker-host', 'proxmox-node', 'web'],
      hostKeyFingerprint: FP_GOOD,
      sudoersVersion: 4,
      via: 'ssh',
      // proxmox-node tiene descubridor: se encola el descubrimiento.
      discoveryJobId: 'queued-asset.discover',
      // SBOM del servidor tras recogerlo (§9).
      hostScanJobId: 'host-scan-a1',
      warnings: [],
    });
    expect(t.queue.add).toHaveBeenCalledWith(
      'asset.discover',
      { assetId: 'a1' },
      expect.objectContaining({ deduplication: { id: 'discover:a1' } }),
    );
    const snapshot = snapshotOf(t.saved);
    expect(snapshot).toMatchObject({
      assetId: 'a1',
      jobId: 'job-1',
      roles: ['docker-host', 'proxmox-node', 'web'],
    });
    const facts = snapshot.facts as CollectedFacts;
    expect(facts.machineId).toBe(MACHINE_ID);
    expect(facts.detected.proxmox).toBe('pve-manager/9.0.3');
    expect(assetOf(t.saved)).toMatchObject({
      status: 'active',
      naturalKey: MACHINE_ID,
      hostKeyFingerprint: FP_GOOD,
      roles: ['docker-host', 'proxmox-node', 'web'],
      facts,
    });
    expect(t.events().at(-1)).toBe('Recolección completada');
  });

  it('host key fijada que ha cambiado: falla sin resolver la clave ni conectar ni escribir', async () => {
    const t = setup({ scanned: [FP_EVIL] });
    await expect(t.processor.process(t.job)).rejects.toThrow(
      /posible suplantación/,
    );
    expect(t.secrets.resolve).not.toHaveBeenCalled();
    expect(t.ansible.collect).not.toHaveBeenCalled();
    expect(t.transactions()).toBe(0);
    expect(t.events().at(-1)).toMatch(
      /^Fallo: La host key del servidor ha cambiado/,
    );
  });

  it('sin huella fijada: TOFU y se fija con el snapshot', async () => {
    const t = setup({ pinned: null, scanned: [FP_EVIL] });
    await t.processor.process(t.job);
    expect(assetOf(t.saved).hostKeyFingerprint).toBe(FP_EVIL);
  });

  it('si la huella se fija en otro sitio durante la recolección, no escribe nada', async () => {
    const t = setup({
      pinned: null,
      lockedPinned: FP_GOOD,
      scanned: [FP_EVIL],
    });
    await expect(t.processor.process(t.job)).rejects.toThrow(/cambió durante/);
    expect(t.saved).toEqual([]);
  });

  it('machine-id de otro asset vivo: duplicado, sin escribir nada más', async () => {
    const t = setup({ owner: { id: 'otro', name: 'pve-viejo' } });
    const result = (await t.processor.process(t.job)) as AssetCollectJobResult;
    expect(result.duplicateOf).toEqual({ id: 'otro', name: 'pve-viejo' });
    expect(result.snapshotId).toBeNull();
    expect(result.discoveryJobId).toBeNull();
    // Ni snapshot ni facts, roles, clave natural o huella: solo la marca.
    expect(t.saved).toEqual([]);
    expect(t.updated).toEqual([{ id: 'a1', duplicateOfId: 'otro' }]);
    expect(t.queue.add).not.toHaveBeenCalled();
    expect(t.events().at(-1)).toBe(
      'Duplicado de pve-viejo: no se ha guardado nada',
    );
  });

  it('mismo machine-id y una host key en común: es la misma máquina (duplicado)', async () => {
    const t = setup({
      scanned: [FP_GOOD, FP_EVIL],
      owner: { id: 'otro', name: 'pve-viejo', hostKeyFingerprint: FP_EVIL },
    });
    const result = (await t.processor.process(t.job)) as AssetCollectJobResult;
    expect(result.duplicateOf).toEqual({ id: 'otro', name: 'pve-viejo' });
    expect(t.saved).toEqual([]);
  });

  it('mismo machine-id con host keys distintas: clon, se guarda con clave compuesta y aviso', async () => {
    const t = setup({
      owner: { id: 'otro', name: 'plantilla', hostKeyFingerprint: FP_EVIL },
    });
    const result = (await t.processor.process(t.job)) as AssetCollectJobResult;
    expect(result.duplicateOf).toBeNull();
    expect(result.snapshotId).toBe('s1');
    // No cuenta como recolección parcial: el aviso va en `machineIdClone`.
    expect(result.warnings).toEqual([]);
    expect(t.events().at(-1)).toBe(
      'Recolección completada (machine-id clonado: compartido con plantilla)',
    );
    const asset = assetOf(t.saved);
    expect(asset.naturalKey).toBe(`${MACHINE_ID}+${FP_GOOD}`);
    expect(asset.duplicateOfId).toBeNull();
    const facts = asset.facts as CollectedFacts;
    expect(facts.infraward.machineIdClone).toEqual({
      machineId: MACHINE_ID,
      sharedWith: [{ id: 'otro', name: 'plantilla' }],
    });
    // Un clon es otra máquina: su descubrimiento sigue.
    expect(result.discoveryJobId).toBe('queued-asset.discover');
  });

  it('clon que regenera su machine-id: la clave pasa a ser el nuevo y desaparece el aviso', async () => {
    const t = setup({ naturalKey: `otro-machine-id+${FP_GOOD}` });
    const result = (await t.processor.process(t.job)) as AssetCollectJobResult;
    expect(result.warnings).toEqual([]);
    const asset = assetOf(t.saved);
    expect(asset.id).toBe('a1');
    expect(asset.naturalKey).toBe(MACHINE_ID);
    expect((asset.facts as CollectedFacts).infraward.machineIdClone).toBeNull();
  });

  it('el duplicado de un asset missing también cuenta', async () => {
    const t = setup({ owner: { id: 'otro', status: 'missing' } });
    const result = (await t.processor.process(t.job)) as AssetCollectJobResult;
    expect(result.duplicateOf?.id).toBe('otro');
    expect(t.saved).toEqual([]);
  });

  it('machine-id de un asset retirado: aviso y sin clave natural', async () => {
    const t = setup({ owner: { id: 'otro', status: 'retired' } });
    const result = (await t.processor.process(t.job)) as AssetCollectJobResult;
    expect(result.duplicateOf).toBeNull();
    expect(result.warnings).toEqual([
      `machine-id ${MACHINE_ID} ya pertenece a un asset retirado (otro): no se asigna como clave natural`,
    ]);
    expect(assetOf(t.saved).naturalKey).toBeNull();
    // El aviso queda también en los facts guardados.
    const facts = snapshotOf(t.saved).facts as CollectedFacts;
    expect(facts.infraward.warnings).toEqual(result.warnings);
    expect(t.events().at(-1)).toBe('Recolección parcial (1 avisos)');
  });

  it('sin conflicto, una recolección normal quita la marca de duplicado', async () => {
    const t = setup({ asset: { duplicateOfId: 'otro' } });
    const result = (await t.processor.process(t.job)) as AssetCollectJobResult;
    expect(result.duplicateOf).toBeNull();
    expect(assetOf(t.saved).duplicateOfId).toBeNull();
    expect(assetOf(t.saved).naturalKey).toBe(MACHINE_ID);
  });

  it('machine-id distinto del registrado: aviso y se conserva el anterior', async () => {
    const t = setup({ naturalKey: 'anterior' });
    const result = (await t.processor.process(t.job)) as { warnings: string[] };
    expect(result.warnings[0]).toMatch(/machine-id distinto del registrado/);
    expect(assetOf(t.saved).naturalKey).toBe('anterior');
  });

  it('missing vuelve a active', async () => {
    const t = setup({ status: 'missing' });
    await t.processor.process(t.job);
    expect(assetOf(t.saved).status).toBe('active');
  });

  it.each(['pending_enrollment', 'retired'])(
    'no recoge un asset %s',
    async (status) => {
      const t = setup({ status });
      await expect(t.processor.process(t.job)).rejects.toThrow(
        /solo se recogen assets dados de alta/,
      );
      expect(t.ssh.scanHostKeys).not.toHaveBeenCalled();
    },
  );

  it('retirado durante la recolección: no escribe nada', async () => {
    const t = setup({ lockedStatus: 'retired' });
    await expect(t.processor.process(t.job)).rejects.toThrow(/se retiró/);
    expect(t.saved).toEqual([]);
  });

  it('un error inesperado no filtra su mensaje', async () => {
    const t = setup({
      collect: () => Promise.reject(new Error(`boom ${PRIVATE_KEY}`)),
    });
    const logged = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const error = (await t.processor
      .process(t.job)
      .catch((e: unknown) => e)) as Error;
    expect(error.message).toBe('Error interno durante la recolección');
    expect(t.events().join('\n')).not.toContain(PRIVATE_KEY);
    expect(JSON.stringify(logged.mock.calls)).not.toContain(PRIVATE_KEY);
    logged.mockRestore();
  });
});

describe('DiscoveryProcessor: CT de Proxmox (pct exec desde el nodo)', () => {
  const CT = {
    id: 'a1',
    type: 'lxc',
    name: 'debian',
    roles: [],
    naturalKey: `proxmox:node:${MACHINE_ID}:100`,
    connection: null,
    credentials: {},
    hostKeyFingerprint: null,
    facts: {
      proxmox: { vmid: 100, status: 'running', template: false },
      viejo: 'se sustituye',
    },
  };
  /** Un CT con Docker: sin pveversion (eso es del nodo). */
  const ctRaw = (): RawCollection => {
    const data = raw();
    return {
      ...data,
      via: 'pct',
      which: data.which.filter((w) => !w.startsWith('pveversion=')),
      sudo: data.sudo.filter((r) => r.item.key !== 'pveversion'),
    };
  };

  it('recoge con la conexión, la clave y la huella del nodo, y conserva lo de Proxmox', async () => {
    const t = setup({
      asset: CT,
      parent: {},
      collect: () => Promise.resolve(ctRaw()),
    });
    const result = (await t.processor.process(t.job)) as Record<
      string,
      unknown
    >;

    expect(t.ssh.scanHostKeys).toHaveBeenCalledWith('192.0.2.20', 2222);
    expect(t.secrets.resolve).toHaveBeenCalledWith(
      'secret://local/assets/node-1/ssh#privateKey',
      { fresh: true },
    );
    expect(t.ansible.collect).toHaveBeenCalledWith(
      { host: '192.0.2.20', port: 2222, user: 'inventory' },
      { kind: 'key', privateKey: PRIVATE_KEY },
      hostKey(FP_GOOD),
      { kind: 'pct', vmid: 100 },
    );
    expect(result).toMatchObject({ via: 'pct', hostKeyFingerprint: FP_GOOD });
    const saved = assetOf(t.saved);
    // Clave natural del descubridor (los CT clonados comparten machine-id) y sin huella propia.
    expect(saved.naturalKey).toBe(CT.naturalKey);
    expect(saved.hostKeyFingerprint).toBeNull();
    const facts = saved.facts as Record<string, unknown>;
    expect(facts.proxmox).toEqual(CT.facts.proxmox);
    expect(facts).not.toHaveProperty('viejo');
    expect((facts as unknown as CollectedFacts).infraward.via).toBe('pct');
    // El snapshot guarda lo mismo.
    expect(snapshotOf(t.saved).facts).toEqual(facts);
    expect((facts as unknown as CollectedFacts).infraward.warnings).toEqual([]);
  });

  it.each([
    [
      'un CT parado',
      { facts: { proxmox: { vmid: 100, status: 'stopped' } } },
      /no está en marcha/,
    ],
    ['una VM', { type: 'vm' }, /VMs solo tienen los datos de Proxmox/],
  ])('no recoge %s', async (_name, extra, message) => {
    const t = setup({ asset: { ...CT, ...extra }, parent: {} });
    await expect(t.processor.process(t.job)).rejects.toThrow(message);
    expect(t.ssh.scanHostKeys).not.toHaveBeenCalled();
    expect(t.secrets.resolve).not.toHaveBeenCalled();
  });

  it.each([
    ['sin padre', null, /ni un padre desde el que recogerlo/],
    ['con un padre sin rol proxmox-node', { roles: ['plesk'] }, /ni un padre/],
    [
      'con un nodo sin huella fijada (sin TOFU a través del nodo)',
      { hostKeyFingerprint: null },
      /host key fijada/,
    ],
    ['con un nodo retirado', { status: 'retired' }, /no está activo/],
  ])('no recoge un CT %s', async (_name, parent, message) => {
    const t = setup({ asset: CT, parent });
    await expect(t.processor.process(t.job)).rejects.toThrow(message);
    expect(t.ssh.scanHostKeys).not.toHaveBeenCalled();
  });

  it('un CT con Docker encola su descubrimiento (docker-host)', async () => {
    const t = setup({
      asset: CT,
      parent: {},
      collect: () => Promise.resolve(ctRaw()),
    });
    const result = (await t.processor.process(t.job)) as Record<
      string,
      unknown
    >;
    expect(result.roles).toContain('docker-host');
    expect(result.discoveryJobId).toBe('queued-asset.discover');
    expect(t.queue.add).toHaveBeenCalledWith(
      'asset.discover',
      { assetId: 'a1' },
      expect.objectContaining({ deduplication: { id: 'discover:a1' } }),
    );
  });

  it('descubre los contenedores de un CT desde el nodo con sudo -n pct exec', async () => {
    const t = setup({
      jobName: 'asset.discover',
      asset: { ...CT, roles: ['docker-host'] },
      parent: {},
      pvesh: () => ({
        code: 1,
        stdout: '',
        stderr: 'Cannot connect to the Docker daemon',
      }),
    });
    await expect(t.processor.process(t.job)).rejects.toThrow(
      /No se pudo listar Docker/,
    );
    // Con la conexión, la clave y la huella del nodo.
    expect(t.ssh.session.mock.calls[0][0]).toEqual({
      host: '192.0.2.20',
      port: 2222,
      user: 'inventory',
    });
    expect(t.secrets.resolve).toHaveBeenCalledWith(
      'secret://local/assets/node-1/ssh#privateKey',
      { fresh: true },
    );
    expect(t.commands).toEqual([
      [
        'sudo',
        '-n',
        '/usr/local/libexec/infraward/infraward-query',
        'pct-exec',
        '100',
        'docker',
        'ps',
        '-a',
        '-q',
        '--no-trunc',
      ],
    ]);
    expect(t.transactions()).toBe(0);
  });
});

describe('DiscoveryProcessor: asset.discover', () => {
  const NODE = { roles: ['proxmox-node'], facts: { machineId: MACHINE_ID } };

  it('si pvesh falla, el job falla sin tocar la BD ni encolar nada', async () => {
    const t = setup({
      jobName: 'asset.discover',
      asset: NODE,
      pvesh: () => ({ code: 255, stdout: '', stderr: 'ipcc_send_rec failed' }),
    });
    await expect(t.processor.process(t.job)).rejects.toThrow(
      /No se pudo listar Proxmox.*ipcc_send_rec failed/,
    );
    expect(t.transactions()).toBe(0);
    expect(t.queue.add).not.toHaveBeenCalled();
    // Solo `sudo -n <ayudante> pve-cluster-status`.
    expect(t.commands).toEqual([
      [
        'sudo',
        '-n',
        '/usr/local/libexec/infraward/infraward-query',
        'pve-cluster-status',
      ],
    ]);
    expect(t.events().at(-1)).toMatch(/^Fallo: No se pudo listar Proxmox/);
  });

  it('usa la huella fijada del nodo: si cambia, no conecta', async () => {
    const t = setup({
      jobName: 'asset.discover',
      asset: NODE,
      scanned: [FP_EVIL],
    });
    await expect(t.processor.process(t.job)).rejects.toThrow(
      /posible suplantación/,
    );
    expect(t.ssh.session).not.toHaveBeenCalled();
    expect(t.secrets.resolve).not.toHaveBeenCalled();
  });

  it.each([
    [
      'sin rol con descubridor',
      { roles: ['web'] },
      /ningún rol con descubridor/,
    ],
    [
      'sin huella fijada',
      { ...NODE, hostKeyFingerprint: null },
      /host key fijada/,
    ],
    [
      'sin conexión',
      { ...NODE, connection: null },
      /no tiene conexión SSH propia/,
    ],
  ])('no descubre un asset %s', async (_name, asset, message) => {
    const t = setup({ jobName: 'asset.discover', asset });
    await expect(t.processor.process(t.job)).rejects.toThrow(message);
    expect(t.ssh.scanHostKeys).not.toHaveBeenCalled();
  });

  it('no descubre desde un nodo missing', async () => {
    const t = setup({
      jobName: 'asset.discover',
      asset: NODE,
      status: 'missing',
    });
    await expect(t.processor.process(t.job)).rejects.toThrow(/asset activo/);
  });
});
