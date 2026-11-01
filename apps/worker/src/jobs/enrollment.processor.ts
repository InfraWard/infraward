import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { Asset, Enrollment, recomputePolicies } from '@infraward/domain';
import {
  formatSecretRef,
  parseSecretRef,
  SecretError,
  SecretsService,
} from '@infraward/secrets';
import {
  ADMIN_ACCESS_USER,
  JOB_NAMES,
  type AdminAccess,
  type AdminAccessRequest,
  type EnrollmentVerifyJobData,
  type EnrollmentVerifyJobResult,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { HostKeyMismatchError, selectHostKey } from '../ssh/host-keys.js';
import { CollectionError } from '../collect/ansible-runner.js';
import { SshClient, SshError } from '../ssh/ssh-client.js';
import { SshIdentities } from '../ssh/ssh-identity.js';
import { recordQueued } from './job-runs.js';
import { reportProgress } from './progress.js';
import { assertFence } from './fence.js';
import { HostSlots } from './host-slots.js';
import { isInterruption } from './job-context.js';
import { JobQueues } from './job-queues.js';

/**
 * uid, versión del sudoers y del acceso de administración (ficheros legibles que deja el script
 * de alta; una línea vacía si faltan).
 */
const PROBE =
  'id -u; cat /etc/infraward/sudoers-version 2>/dev/null || echo; ' +
  'cat /etc/infraward/admin-access-version 2>/dev/null || echo';

/** Fallo de verificación con un mensaje apto para guardarse y mostrarse en la UI. */
class VerificationError extends Error {}

/**
 * Consumidor de la cola `enrollment`. `enrollment.verify` es la prueba real del alta: conectar
 * por SSH con la clave del asset o, en modo CA, con un certificado recién firmado, fijando la
 * host key (huellas reportadas por el script o TOFU en el camino manual). Solo si conecta pasa
 * el asset a `active`. Si el alta pasaba un servidor de clave estática a CA, al conectar con el
 * certificado la clave estática se borra del proveedor (el script ya la quitó del servidor).
 */
@Injectable()
export class EnrollmentProcessor {
  private readonly logger = new Logger(EnrollmentProcessor.name);

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly ssh: SshClient,
    private readonly queues: JobQueues,
    private readonly identities: SshIdentities,
    @Optional() private readonly slots?: HostSlots,
  ) {}

  async process(job: Job): Promise<unknown> {
    if (job.name === JOB_NAMES.enrollmentVerify)
      return this.verify(
        job as Job<EnrollmentVerifyJobData, EnrollmentVerifyJobResult>,
      );
    throw new Error(`Job desconocido en la cola ${job.queueName}: ${job.name}`);
  }

  private async verify(
    job: Job<EnrollmentVerifyJobData, EnrollmentVerifyJobResult>,
  ): Promise<EnrollmentVerifyJobResult> {
    const { enrollmentId } = job.data;
    const enrollment = await this.db
      .getRepository(Enrollment)
      .findOneBy({ id: enrollmentId });
    // Cancelado (asset retirado) o ya resuelto por otro job: nada que hacer.
    if (enrollment?.status !== 'confirmed') {
      throw new Error(
        `El enrolamiento ${enrollmentId} no está pendiente de verificación`,
      );
    }
    this.logger.log(
      `Verificando enrolamiento ${enrollmentId} del asset ${enrollment.assetId}`,
    );
    try {
      const result = await this.connect(job, enrollment);
      const staticKey = await this.markVerified(enrollment, result);
      if (staticKey) await this.removeStaticKey(result.assetId, staticKey);
      await reportProgress(job, 100, 'Conexión verificada');
      const collectJobId = await this.enqueueCollection(result.assetId, job.id);
      return { ...result, collectJobId };
    } catch (error) {
      if (isInterruption(error)) throw error;
      const message =
        error instanceof VerificationError ||
        error instanceof CollectionError ||
        error instanceof SshError ||
        error instanceof HostKeyMismatchError ||
        error instanceof SecretError
          ? error.message
          : 'Error interno al verificar la conexión';
      if (message.startsWith('Error interno')) {
        // Tipo y traza, nunca el mensaje: un error ajeno podría llevar datos sensibles.
        const { name, stack } = error as Error;
        const frames = stack?.split('\n').slice(1).join('\n') ?? '';
        this.logger.error(
          `Verificación de ${enrollmentId}: ${name}\n${frames}`,
        );
      }
      await this.markFailed(enrollmentId, message);
      await reportProgress(job, 100, `Fallo: ${message}`);
      throw new Error(message, { cause: error });
    }
  }

  private async connect(
    job: Job,
    enrollment: Enrollment,
  ): Promise<Omit<EnrollmentVerifyJobResult, 'collectJobId'>> {
    const asset = await this.db
      .getRepository(Asset)
      .findOneBy({ id: enrollment.assetId });
    const ref = asset?.credentials.sshPrivateKey ?? null;
    const ca = enrollment.authMode === 'ca_certificate';
    if (
      !asset ||
      asset.status === 'retired' ||
      !asset.connection ||
      (!ref && !ca)
    ) {
      throw new VerificationError(
        'El asset no existe, está retirado o no tiene conexión SSH',
      );
    }
    const target = { ...asset.connection, user: enrollment.sshUser };
    await this.slots?.acquire(asset.id, asset.name);

    await reportProgress(job, 10, `Leyendo la host key de ${target.host}`);
    const scanned = await this.ssh.scanHostKeys(target.host, target.port);
    const hostKey = selectHostKey(
      scanned,
      asset.hostKeyFingerprint,
      enrollment.reportedHostKeys,
    );

    await reportProgress(
      job,
      40,
      `Conectando como ${target.user}${ca ? ' con un certificado de la CA' : ''}`,
    );
    // Con clave estática, sin caché (un borrado en la API se ve al instante). En modo CA, solo
    // el certificado: la verificación tiene que probar justo eso.
    const identity = await this.identities.resolve(
      { auth: enrollment.authMode, keyRef: ref },
      { assetId: asset.id, jobId: job.id },
      { strict: true },
    );
    const output = await this.ssh.exec(target, identity, hostKey, PROBE);

    const [uidLine, versionLine, adminLine] = output
      .split('\n')
      .map((l) => l.trim());
    if (!/^\d+$/.test(uidLine ?? ''))
      throw new VerificationError('Respuesta inesperada del servidor');
    if (uidLine === '0')
      throw new VerificationError(
        `El usuario ${target.user} tiene uid 0: InfraWard nunca se conecta como root`,
      );
    const version = /^\d{1,6}$/.test(versionLine ?? '')
      ? Number(versionLine)
      : null;
    const adminAccessVersion = /^\d{1,6}$/.test(adminLine ?? '')
      ? Number(adminLine)
      : null;
    if (enrollment.adminAccess === 'operator' && adminAccessVersion === null)
      throw new VerificationError(
        'El servidor no tiene el acceso de administración que pedía el comando: vuelve a ejecutarlo',
      );
    return {
      assetId: asset.id,
      hostKeyFingerprint: hostKey.fingerprint,
      sudoersVersion: version,
      adminAccessVersion,
    };
  }

  /**
   * Éxito: enrolamiento `verified`, asset `active` y huella fijada (solo si no había: una
   * huella existente solo se cambia a mano). Condicionado al estado por si se retiró entretanto.
   * Si el enrolamiento era en modo CA y el asset tenía clave estática, pasa a modo CA y se quita
   * la referencia; devuelve la referencia para borrar la clave del proveedor tras el commit.
   */
  private markVerified(
    enrollment: Enrollment,
    result: Omit<EnrollmentVerifyJobResult, 'collectJobId'>,
  ): Promise<string | null> {
    return this.db.transaction(async (m) => {
      await assertFence(m);
      const { affected } = await m.update(
        Enrollment,
        { id: enrollment.id, status: 'confirmed' },
        {
          status: 'verified',
          verifiedAt: new Date(),
          sudoersVersion: result.sudoersVersion,
          error: null,
        },
      );
      if (!affected)
        throw new VerificationError(
          'El enrolamiento se canceló durante la verificación',
        );
      await m
        .createQueryBuilder()
        .update(Asset)
        .set({
          status: () =>
            `CASE WHEN "status" = 'pending_enrollment' THEN 'active'::asset_status ELSE "status" END`,
          hostKeyFingerprint: () =>
            `COALESCE("host_key_fingerprint", :fingerprint)`,
        })
        .setParameter('fingerprint', result.hostKeyFingerprint)
        .where('id = :id AND status <> :retired', {
          id: result.assetId,
          retired: 'retired',
        })
        .execute();
      const current = await m.findOne(Asset, {
        select: { id: true, adminAccess: true },
        where: { id: result.assetId },
      });
      if (current)
        await m.update(
          Asset,
          { id: current.id },
          {
            adminAccess: nextAdminAccess(
              enrollment.adminAccess,
              result.adminAccessVersion,
              current.adminAccess,
            ),
          },
        );
      // Activo ya: su política (la del alta, sus tags y proyectos) se recalcula antes de que la
      // primera recolección decida qué escanear (QoL-6b).
      await recomputePolicies(m);
      if (enrollment.authMode !== 'ca_certificate') return null;
      const asset = await m.findOne(Asset, {
        where: { id: result.assetId },
        lock: { mode: 'pessimistic_write' },
      });
      if (!asset || asset.status === 'retired') return null;
      const staticKey = asset.credentials.sshPrivateKey ?? null;
      const credentials = { ...asset.credentials };
      delete credentials.sshPrivateKey;
      await m.update(
        Asset,
        { id: asset.id },
        { sshAuth: 'ca_certificate', credentials },
      );
      return staticKey;
    });
  }

  /**
   * Migración a CA confirmada: la clave estática ya no se usa (el script la quitó del servidor
   * antes de que conectara el certificado). Si no se puede borrar, se avisa: la referencia ya no
   * está en el asset.
   */
  private async removeStaticKey(assetId: string, ref: string): Promise<void> {
    const { provider, path } = parseSecretRef(ref);
    const base = formatSecretRef({ provider, path });
    try {
      await this.secrets.remove(base);
      this.logger.log(
        `Asset ${assetId} en modo CA: clave estática ${base} borrada del proveedor`,
      );
    } catch (error) {
      this.logger.warn(
        `Asset ${assetId} en modo CA, pero no se pudo borrar su clave estática ${base}: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Primera recolección (DESIGN §7 paso 6). Si no se puede encolar, el alta sigue verificada:
   * la recolección se puede lanzar después con `POST /assets/:id/collect`.
   */
  private async enqueueCollection(
    assetId: string,
    parentJobId?: string,
  ): Promise<string | null> {
    try {
      // Con deduplicación, BullMQ devuelve el job que ya estaba en cola: el stepper lo sigue.
      const job = await this.queues.add(
        JOB_NAMES.assetCollect,
        { assetId },
        { jobId: randomUUID(), deduplication: { id: assetId } },
      );
      await recordQueued(this.db, job, parentJobId, this.logger);
      this.logger.log(`Recolección de ${assetId} encolada (job ${job.id})`);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar la recolección de ${assetId}: ${(error as Error).name}`,
      );
      return null;
    }
  }

  /** Fallo: el asset no cambia (sigue en `pending_enrollment`, o `active` si era una actualización). */
  private async markFailed(id: string, error: string): Promise<void> {
    await this.db
      .getRepository(Enrollment)
      .update({ id, status: 'confirmed' }, { status: 'failed', error });
  }
}

/**
 * Acceso de administración del asset tras verificar (DESIGN §7): lo que pedía el comando, según
 * lo que el servidor tiene de verdad (`/etc/infraward/admin-access-version`). Sin pedir nada
 * (`null`), se conserva si sigue instalado; si ya no lo está, se quita.
 */
export function nextAdminAccess(
  requested: AdminAccessRequest | null,
  installedVersion: number | null,
  current: AdminAccess | null,
): AdminAccess | null {
  if (requested === 'none' || installedVersion === null) return null;
  if (requested === 'operator')
    return {
      mode: 'operator',
      account: ADMIN_ACCESS_USER,
      version: installedVersion,
      enabledAt: current?.enabledAt ?? new Date().toISOString(),
    };
  return current ? { ...current, version: installedVersion } : null;
}
