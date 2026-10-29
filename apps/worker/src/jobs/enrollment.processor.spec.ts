import type { JobQueues } from './job-queues.js';
import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { SecretsService } from '@infraward/secrets';
import type { JobProgressEvent } from '@infraward/shared-types';
import type { Job } from 'bullmq';
import type { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { ScannedHostKey } from '../ssh/host-keys.js';
import type { SshClient } from '../ssh/ssh-client.js';
import { EnrollmentProcessor, nextAdminAccess } from './enrollment.processor.js';
import { SshIdentities } from '../ssh/ssh-identity.js';

const FP_GOOD = `SHA256:${'g'.repeat(43)}`;
const FP_EVIL = `SHA256:${'e'.repeat(43)}`;
const PRIVATE_KEY = 'clave-privada-centinela';
const REF = 'secret://local/assets/a1/ssh#privateKey';

const hostKey = (fingerprint: string): ScannedHostKey => ({
  keyType: 'ssh-ed25519',
  blob: 'AAAA',
  type: 'ED25519',
  fingerprint,
});

function setup(
  options: {
    status?: string;
    reported?: string[];
    pinned?: string | null;
    scanned?: string[];
    output?: string;
    resolve?: () => Promise<string>;
    enqueue?: () => Promise<unknown>;
    /** Modo que instala el enrolamiento (por defecto, clave estática). */
    authMode?: 'static_key' | 'ca_certificate';
    /** Proveedor con CA SSH disponible. */
    ca?: boolean;
    /** Acceso de administración que pide el enrolamiento. */
    adminAccess?: 'operator' | 'none' | null;
    /** El que ya tiene el asset. */
    currentAdminAccess?: Record<string, unknown> | null;
  } = {},
) {
  const enrollment = {
    id: 'e1',
    assetId: 'a1',
    status: options.status ?? 'confirmed',
    authMode: options.authMode ?? 'static_key',
    adminAccess: options.adminAccess ?? null,
    sshUser: 'inventory',
    reportedHostKeys: (options.reported ?? [FP_GOOD]).map((fingerprint) => ({
      type: 'ED25519',
      fingerprint,
    })),
  };
  const asset = {
    id: 'a1',
    status: 'pending_enrollment',
    connection: { host: '192.0.2.10', port: 22, user: 'inventory' },
    credentials: { sshPrivateKey: REF } as Record<string, string>,
    sshAuth: 'static_key',
    hostKeyFingerprint: options.pinned ?? null,
    adminAccess: options.currentAdminAccess ?? null,
  };
  const assetUpdates: unknown[] = [];
  const enrollmentUpdates: unknown[][] = [];
  const qb = {
    update: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    setParameter: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    execute: vi.fn().mockResolvedValue({ affected: 1 }),
  };
  const repo = (entity: { name: string }) => ({
    findOneBy: () =>
      Promise.resolve(entity.name === 'Enrollment' ? enrollment : asset),
    update: (...args: unknown[]) => {
      enrollmentUpdates.push(args);
      return Promise.resolve({ affected: 1 });
    },
  });
  const db = {
    getRepository: repo,
    transaction: (cb: (m: unknown) => Promise<unknown>) =>
      cb({
        update: (e: { name: string }, ...args: unknown[]) => {
          (e.name === 'Asset' ? assetUpdates : enrollmentUpdates).push(args);
          return Promise.resolve({ affected: 1 });
        },
        findOne: () => Promise.resolve(asset),
        createQueryBuilder: () => qb,
        // recomputePolicies: sin assets ni reglas, no cambia nada.
        query: () => Promise.resolve([]),
      }),
  } as unknown as DataSource;
  const signSshKey = vi.fn(() =>
    Promise.resolve('ssh-ed25519-cert-v01@openssh.com AAAA'),
  );
  const secrets = {
    resolve: vi.fn(options.resolve ?? (() => Promise.resolve(PRIVATE_KEY))),
    remove: vi.fn(() => Promise.resolve(true)),
    sshCertificates: () =>
      options.ca ? { id: 'openbao', signSshKey } : undefined,
  };
  const ssh = {
    scanHostKeys: vi.fn(() =>
      Promise.resolve((options.scanned ?? [FP_GOOD]).map(hostKey)),
    ),
    exec: vi.fn(() => Promise.resolve(options.output ?? '1001\n1\n')),
  };
  const config = { get: () => 1 } as unknown as ConfigService<
    EnvironmentVariables,
    true
  >;
  const discovery = {
    add: vi.fn(options.enqueue ?? (() => Promise.resolve({ id: 'collect-1' }))),
  };
  const processor = new EnrollmentProcessor(
    config,
    db,
    secrets as unknown as SecretsService,
    ssh as unknown as SshClient,
    { ...discovery, get: () => discovery } as unknown as JobQueues,
    new SshIdentities(secrets as unknown as SecretsService, config),
  );
  const logs: string[] = [];
  const job = {
    id: 'job-1',
    name: 'enrollment.verify',
    data: { enrollmentId: 'e1' },
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
    qb,
    enrollmentUpdates,
    assetUpdates,
    events,
    discovery,
  };
}

describe('EnrollmentProcessor', () => {
  it('conecta con la host key reportada y marca verificado (asset activo, huella fijada)', async () => {
    const t = setup({ scanned: [FP_EVIL, FP_GOOD] });
    const result = await t.processor.process(t.job);
    expect(result).toEqual({
      assetId: 'a1',
      hostKeyFingerprint: FP_GOOD,
      sudoersVersion: 1,
      adminAccessVersion: null,
      collectJobId: 'collect-1',
    });
    expect(t.ssh.exec).toHaveBeenCalledWith(
      { host: '192.0.2.10', port: 22, user: 'inventory' },
      { kind: 'key', privateKey: PRIVATE_KEY },
      hostKey(FP_GOOD),
      expect.stringContaining('id -u'),
    );
    expect(t.secrets.resolve).toHaveBeenCalledWith(REF, { fresh: true });
    expect(t.enrollmentUpdates[0]).toEqual([
      { id: 'e1', status: 'confirmed' },
      expect.objectContaining({
        status: 'verified',
        sudoersVersion: 1,
        error: null,
      }),
    ]);
    expect(t.qb.setParameter).toHaveBeenCalledWith('fingerprint', FP_GOOD);
    expect(t.events().at(-1)).toBe('Conexión verificada');
    // Primera recolección encadenada, deduplicada por asset.
    expect(t.discovery.add).toHaveBeenCalledWith(
      'asset.collect',
      { assetId: 'a1' },
      expect.objectContaining({ deduplication: { id: 'a1' } }),
    );
  });

  it('si no se puede encolar la recolección, el alta sigue verificada', async () => {
    const t = setup({
      enqueue: () => Promise.reject(new Error('redis caído')),
    });
    const warned = vi
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => undefined);
    await expect(t.processor.process(t.job)).resolves.toMatchObject({
      assetId: 'a1',
      collectJobId: null,
    });
    expect(warned).toHaveBeenCalledWith(
      expect.stringContaining('No se pudo encolar la recolección de a1'),
    );
    warned.mockRestore();
  });

  it('si la verificación falla, no se encola la recolección', async () => {
    const t = setup({ scanned: [FP_EVIL] });
    await expect(t.processor.process(t.job)).rejects.toThrow();
    expect(t.discovery.add).not.toHaveBeenCalled();
  });

  it('sin fichero de versión, sudoersVersion es null', async () => {
    const t = setup({ output: '1001\n' });
    expect(await t.processor.process(t.job)).toMatchObject({
      sudoersVersion: null,
    });
  });

  it('host key que no coincide con las reportadas: falla sin resolver la clave ni conectar', async () => {
    const t = setup({ scanned: [FP_EVIL] });
    await expect(t.processor.process(t.job)).rejects.toThrow(
      /posible suplantación/,
    );
    expect(t.secrets.resolve).not.toHaveBeenCalled();
    expect(t.ssh.exec).not.toHaveBeenCalled();
    expect(t.enrollmentUpdates).toEqual([
      [
        { id: 'e1', status: 'confirmed' },
        { status: 'failed', error: expect.stringMatching(/no coincide/) },
      ],
    ]);
  });

  it('host key fijada que ha cambiado: falla aunque coincida con las reportadas', async () => {
    const t = setup({
      pinned: FP_GOOD,
      scanned: [FP_EVIL],
      reported: [FP_EVIL],
    });
    await expect(t.processor.process(t.job)).rejects.toThrow(/ha cambiado/);
    expect(t.ssh.exec).not.toHaveBeenCalled();
  });

  it('rechaza un usuario con uid 0', async () => {
    const t = setup({ output: '0\n1\n' });
    await expect(t.processor.process(t.job)).rejects.toThrow(/uid 0/);
    expect(t.enrollmentUpdates.at(-1)?.[1]).toMatchObject({ status: 'failed' });
  });

  it('un error inesperado no filtra su mensaje (podría llevar datos sensibles)', async () => {
    const t = setup({
      resolve: () => Promise.reject(new Error(`boom ${PRIVATE_KEY}`)),
    });
    const logged = vi
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const error = (await t.processor
      .process(t.job)
      .catch((e: unknown) => e)) as Error;
    expect(error.message).toBe('Error interno al verificar la conexión');
    expect(JSON.stringify(t.enrollmentUpdates)).not.toContain(PRIVATE_KEY);
    expect(t.events().join('\n')).not.toContain(PRIVATE_KEY);
    expect(logged).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(logged.mock.calls)).not.toContain(PRIVATE_KEY);
    logged.mockRestore();
  });

  it('no hace nada si el enrolamiento no está pendiente de verificación', async () => {
    const t = setup({ status: 'cancelled' });
    await expect(t.processor.process(t.job)).rejects.toThrow(
      /no está pendiente/,
    );
    expect(t.ssh.scanHostKeys).not.toHaveBeenCalled();
    expect(t.enrollmentUpdates).toEqual([]);
  });

  it('migración a CA: verifica con un certificado, pasa a modo CA y borra la clave estática', async () => {
    const t = setup({ authMode: 'ca_certificate', ca: true });
    await t.processor.process(t.job);
    const [, identity] = t.ssh.exec.mock.calls[0] as unknown as [
      unknown,
      { kind: string },
    ];
    expect(identity.kind).toBe('certificate');
    // Ni se lee la clave estática para conectar.
    expect(t.secrets.resolve).not.toHaveBeenCalled();
    expect(t.assetUpdates).toEqual([
      [{ id: 'a1' }, { adminAccess: null }],
      [{ id: 'a1' }, { sshAuth: 'ca_certificate', credentials: {} }],
    ]);
    expect(t.secrets.remove).toHaveBeenCalledWith(
      'secret://local/assets/a1/ssh',
    );
  });

  it('acceso de administración: se marca con la versión que tiene el servidor', async () => {
    const t = setup({
      authMode: 'ca_certificate',
      ca: true,
      adminAccess: 'operator',
      output: '1001\n7\n1\n',
    });
    const result = await t.processor.process(t.job);
    expect(result).toMatchObject({ sudoersVersion: 7, adminAccessVersion: 1 });
    expect(t.assetUpdates[0]).toEqual([
      { id: 'a1' },
      {
        adminAccess: {
          mode: 'operator',
          account: 'infraward-admin',
          version: 1,
          enabledAt: expect.any(String) as string,
        },
      },
    ]);
    // La sonda lee el fichero de versión que deja el script (sin sudo).
    expect((t.ssh.exec.mock.calls[0] as unknown as string[])[3]).toContain(
      '/etc/infraward/admin-access-version',
    );
  });

  it('acceso de administración pedido pero ausente en el servidor: la verificación falla', async () => {
    const t = setup({
      authMode: 'ca_certificate',
      ca: true,
      adminAccess: 'operator',
      output: '1001\n7\n\n',
    });
    await expect(t.processor.process(t.job)).rejects.toThrow(/acceso de administración/);
    expect(t.assetUpdates).toEqual([]);
  });

  it('alta en modo CA sin proveedor con CA: falla sin probar la clave estática ni borrarla', async () => {
    const t = setup({ authMode: 'ca_certificate', ca: false });
    await expect(t.processor.process(t.job)).rejects.toThrow(
      /ningún proveedor de secretos activo tiene CA SSH/,
    );
    expect(t.ssh.exec).not.toHaveBeenCalled();
    expect(t.assetUpdates).toEqual([]);
    expect(t.secrets.remove).not.toHaveBeenCalled();
  });

  it('migración a CA fallida (no conecta): la clave estática se conserva', async () => {
    const t = setup({ authMode: 'ca_certificate', ca: true });
    t.ssh.exec.mockRejectedValueOnce(new Error('x'));
    await expect(t.processor.process(t.job)).rejects.toThrow();
    expect(t.assetUpdates).toEqual([]);
    expect(t.secrets.remove).not.toHaveBeenCalled();
  });
});

describe('nextAdminAccess', () => {
  const current = { mode: 'operator', account: 'infraward-admin', version: 1, enabledAt: 'antes' } as const;

  it('operator con el fichero de versión: activo (conserva la fecha de alta si ya lo estaba)', () => {
    expect(nextAdminAccess('operator', 2, current)).toEqual({ ...current, version: 2 });
    expect(nextAdminAccess('operator', 1, null)).toMatchObject({ account: 'infraward-admin', version: 1 });
  });

  it('none o sin fichero: sin acceso; sin pedir nada, se conserva si sigue instalado', () => {
    expect(nextAdminAccess('none', 1, current)).toBeNull();
    expect(nextAdminAccess(null, null, current)).toBeNull();
    expect(nextAdminAccess(null, 1, current)).toEqual(current);
    // Sin pedirlo no se activa aunque el servidor lo tenga (lo activa solo un comando explícito).
    expect(nextAdminAccess(null, 1, null)).toBeNull();
  });
});
