import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  Asset,
  Enrollment,
  Project,
  recomputePolicies,
} from '@infraward/domain';
import { SecretsService } from '@infraward/secrets';
import {
  ENROLL_SSH_USER,
  JOB_NAMES,
  SSH_CA_CONFIG_VERSION,
  SUDOERS_VERSION,
  ADMIN_ACCESS_VERSION,
  hasPermission,
  type Enrollment as EnrollmentContract,
  type EnrollServerResponse,
  type HostKeyFingerprint,
  type IssuedEnrollment,
  type SshAuthMode,
  type UserRole,
  type AdminAccessRequest,
} from '@infraward/shared-types';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Subject, type Observable } from 'rxjs';
import { DataSource, In, type EntityManager } from 'typeorm';
import { toAsset } from '../assets/assets.mapper.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { InventoryService } from '../inventory/inventory.service.js';
import { JobsService } from '../jobs/jobs.service.js';
import { ProjectsService } from '../projects/projects.service.js';
import {
  embeddedCommand,
  installCommand,
  keyComment,
  manualCommand,
} from './commands.js';
import type { AuditActor } from '../audit/audit-context.decorator.js';
import { AuditService } from '../audit/audit.service.js';
import { writableSecretsProvider } from '../secrets/writable-provider.js';
import type { EnrollServerDto } from './enrollment.dto.js';
import { EnrollScriptTemplate } from './script-template.js';
import { generateSshKeyPair, sshKeySecretPath } from './ssh-keys.js';

/** Campo del secreto con la clave privada. */
const PRIVATE_KEY_FIELD = 'privateKey';
const OPEN_STATUSES = ['pending', 'confirmed'] as const;

/**
 * Alta de servidores (DESIGN §7): token de un solo uso (en la BD solo su hash), script de alta
 * y encolado de la verificación. Con clave estática, la privada va al proveedor de secretos; en
 * modo CA no hay clave permanente: el script configura sshd para confiar en la CA SSH del
 * proveedor (OpenBao). El asset solo pasa a `active` cuando el worker consigue conectarse; las
 * llamadas a /done no lo activan.
 */
@Injectable()
export class EnrollmentService {
  private readonly logger = new Logger(EnrollmentService.name);
  /** Asset cuyo enrolamiento acaba de cambiar desde la API (para el SSE del stepper). */
  private readonly changed = new Subject<string>();
  readonly changes$: Observable<string> = this.changed.asObservable();
  private readonly publicUrl: string;
  private readonly tokenTtlMs: number;

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly jobs: JobsService,
    @Inject(EnrollScriptTemplate)
    private readonly template: EnrollScriptTemplate,
    private readonly config: ConfigService<EnvironmentVariables, true>,
    private readonly audit: AuditService,
    private readonly inventory: InventoryService,
    private readonly projects: ProjectsService,
  ) {
    this.publicUrl = config
      .get('PUBLIC_URL', { infer: true })
      .replace(/\/+$/, '');
    this.tokenTtlMs =
      config.get('ENROLLMENT_TOKEN_TTL', { infer: true }) * 1000;
  }

  /**
   * "Añadir servidor": asset `pending_enrollment` y token. Con clave estática, además la clave
   * en el proveedor; en modo CA, ninguna.
   */
  async enrollServer(
    dto: EnrollServerDto,
    actor?: AuditActor,
    role?: UserRole,
  ): Promise<EnrollServerResponse> {
    // Organización y política desde el alta (QoL-6b): cada parte, con su permiso.
    const projectIds = [...new Set(dto.projectIds ?? [])];
    if (projectIds.length && !hasPermission(role, 'projects.write'))
      throw new ForbiddenException('Elegir proyectos requiere projects.write');
    if (dto.policy && !hasPermission(role, 'policy.write'))
      throw new ForbiddenException('Fijar la política requiere policy.write');
    // Dar a InfraWard una cuenta con sudo en el servidor es cosa de un admin (§7).
    if (dto.adminAccess && !hasPermission(role, 'users.manage'))
      throw new ForbiddenException(
        'Solo un admin puede activar el acceso interactivo de administración',
      );
    const assetId = randomUUID();
    const authMode = dto.authMode ?? (await this.defaultAuthMode());
    if (dto.adminAccess && authMode !== 'ca_certificate')
      throw new ConflictException(
        'El acceso interactivo de administración requiere el modo CA (certificados)',
      );
    const caKeys = authMode === 'ca_certificate' ? await this.caKeys() : [];
    let publicKey: string | null = null;
    let secretRef: string | null = null;
    if (authMode === 'static_key') {
      const pair = generateSshKeyPair(keyComment(assetId));
      publicKey = pair.publicKey;
      secretRef = await this.secrets.store(
        sshKeySecretPath(this.writableProvider(), assetId),
        { [PRIVATE_KEY_FIELD]: pair.privateKey },
      );
    }
    const token = newToken();
    try {
      const { asset, enrollment } = await this.db.transaction(async (m) => {
        const asset = await m.save(
          m.create(Asset, {
            id: assetId,
            type: 'server',
            discoveredName: dto.name ?? dto.host,
            status: 'pending_enrollment',
            connection: {
              host: dto.host,
              port: dto.port ?? 22,
              user: ENROLL_SSH_USER,
            },
            credentials: secretRef
              ? { sshPrivateKey: `${secretRef}#${PRIVATE_KEY_FIELD}` }
              : {},
            sshAuth: authMode,
            tags: [...new Set(dto.tags ?? [])],
          }),
        );
        const organization = await this.organize(m, assetId, projectIds, dto);
        const enrollment = await m.save(
          m.create(Enrollment, {
            assetId,
            method: 'script',
            purpose: 'initial',
            status: 'pending',
            tokenHash: hashToken(token),
            expiresAt: this.expiry(),
            authMode,
            publicKey,
            sshUser: ENROLL_SSH_USER,
            adminAccess: dto.adminAccess ?? null,
          }),
        );
        if (actor)
          await this.audit.record(actor, 'asset.created', {
            target: { type: asset.type, id: asset.id, label: asset.name },
            details: {
              via: 'enrollment',
              authMode,
              host: dto.host,
              ...organization,
            },
            manager: m,
          });
        if (actor && dto.adminAccess)
          await this.audit.record(actor, 'enrollment.admin_access_requested', {
            target: { type: asset.type, id: asset.id, label: asset.name },
            details: { adminAccess: dto.adminAccess, purpose: 'initial' },
            manager: m,
          });
        return { asset, enrollment };
      });
      return {
        asset: toAsset(asset),
        enrollment: this.issued(
          enrollment,
          token,
          dto.installSudo ?? false,
          caKeys,
        ),
      };
    } catch (error) {
      // Sin asset que la referencie, la clave no debe quedarse en el proveedor.
      if (secretRef) {
        const ref = secretRef;
        await this.secrets
          .remove(ref)
          .catch((e: Error) =>
            this.logger.error(`No se pudo borrar ${ref}: ${e.message}`),
          );
      }
      throw error;
    }
  }

  /**
   * Proyectos y regla propia del servidor recién creado, y la política efectiva recalculada en la
   * misma transacción: la primera recolección y su escaneo ya la respetan (QoL-6b).
   */
  private async organize(
    m: EntityManager,
    assetId: string,
    projectIds: string[],
    dto: EnrollServerDto,
  ): Promise<Record<string, unknown>> {
    const details: Record<string, unknown> = {};
    if (dto.tags?.length) details.tags = [...new Set(dto.tags)];
    if (projectIds.length) {
      const found = await m.find(Project, {
        where: { id: In(projectIds) },
        select: { id: true, name: true },
      });
      if (found.length !== projectIds.length)
        throw new NotFoundException('Proyecto no encontrado');
      for (const id of projectIds)
        await this.projects.applyMemberIn(m, id, assetId, 'include');
      details.projects = found.map((p) => p.name).sort();
    }
    if (dto.policy) {
      const change = await this.inventory.applyAssetPolicyIn(
        m,
        assetId,
        dto.policy,
      );
      if (change) details.policy = change.details;
    }
    await recomputePolicies(m);
    return details;
  }

  /** Último enrolamiento del asset (el que muestra el stepper). */
  async latest(assetId: string): Promise<EnrollmentContract> {
    await this.findAsset(this.db.manager, assetId);
    const enrollment = await this.db.getRepository(Enrollment).findOne({
      where: { assetId },
      order: { createdAt: 'DESC' },
    });
    if (!enrollment)
      throw new NotFoundException('El asset no tiene enrolamientos');
    return toEnrollment(enrollment);
  }

  /**
   * Emite un token nuevo. Con un enrolamiento `pending`, lo sustituye (el anterior deja de
   * valer). Si el asset ya está `active`, abre uno `sudoers_update` con las MISMAS credenciales:
   * volver a ejecutar el script actualiza el sudoers (y, en modo CA, las claves de la CA) sin
   * regenerar nada. Con `authMode: 'ca_certificate'` sobre un servidor con clave estática, el
   * script pasa a modo CA (`ca_migration` si ya estaba activo): al verificarse, la clave estática
   * se borra del proveedor y el script ya la habrá quitado de authorized_keys.
   */
  async issueToken(
    assetId: string,
    installSudo = false,
    requested?: SshAuthMode,
    actor?: AuditActor,
    adminAccess?: AdminAccessRequest,
  ): Promise<IssuedEnrollment> {
    // Las claves de la CA se piden fuera de la transacción (es una llamada a OpenBao).
    const current = await this.findAsset(this.db.manager, assetId);
    const authMode = requested ?? current.sshAuth;
    const caKeys = authMode === 'ca_certificate' ? await this.caKeys() : [];
    const issued = await this.db.transaction(async (m) => {
      const asset = await this.lockAsset(m, assetId);
      this.assertEnrollable(asset);
      if (asset.sshAuth === 'ca_certificate' && authMode === 'static_key')
        throw new ConflictException(
          'El servidor usa certificados de la CA: para volver a una clave estática, dalo de baja y de alta de nuevo',
        );
      // Acceso humano solo con certificados de la CA (§7) y solo en servidores con SSH propio.
      if (adminAccess === 'operator' && authMode !== 'ca_certificate')
        throw new ConflictException(
          'El acceso interactivo de administración requiere el modo CA (certificados)',
        );
      if (adminAccess === 'operator' && asset.type !== 'server')
        throw new ConflictException(
          'El acceso de administración se instala en el servidor; sus CT y contenedores se alcanzan a través de él',
        );
      const migrating =
        authMode === 'ca_certificate' && asset.sshAuth === 'static_key';
      const token = newToken();
      const open = await this.openEnrollment(m, assetId);
      if (open?.status === 'confirmed')
        throw new ConflictException('Hay una verificación en curso');
      const previous = await m.findOne(Enrollment, {
        where: { assetId },
        order: { createdAt: 'DESC' },
      });
      if (!previous)
        throw new ConflictException(
          'El asset no se dio de alta con enrolamiento',
        );
      // Con clave estática, la del asset (la última que se instaló); en modo CA, ninguna.
      const publicKey =
        authMode === 'static_key'
          ? (open?.publicKey ?? (await this.staticPublicKey(m, assetId)))
          : null;

      let enrollment: Enrollment;
      if (open) {
        Object.assign(open, {
          method: 'script',
          sshUser: ENROLL_SSH_USER,
          tokenHash: hashToken(token),
          expiresAt: this.expiry(),
          authMode,
          adminAccess: adminAccess ?? null,
          publicKey,
          purpose:
            open.purpose === 'initial'
              ? 'initial'
              : migrating
                ? 'ca_migration'
                : 'sudoers_update',
        } satisfies Partial<Enrollment>);
        enrollment = await m.save(open);
      } else {
        enrollment = await m.save(
          m.create(Enrollment, {
            assetId,
            method: 'script',
            purpose:
              asset.status !== 'active'
                ? 'initial'
                : migrating
                  ? 'ca_migration'
                  : 'sudoers_update',
            status: 'pending',
            tokenHash: hashToken(token),
            expiresAt: this.expiry(),
            authMode,
            adminAccess: adminAccess ?? null,
            publicKey,
            sshUser: ENROLL_SSH_USER,
          }),
        );
      }
      if (actor && adminAccess)
        await this.audit.record(actor, 'enrollment.admin_access_requested', {
          target: { type: asset.type, id: asset.id, label: asset.name },
          details: { adminAccess, purpose: enrollment.purpose },
          manager: m,
        });
      if (actor)
        await this.audit.record(
          actor,
          migrating ? 'enrollment.ca_requested' : 'enrollment.started',
          {
            target: { type: asset.type, id: asset.id, label: asset.name },
            details: { purpose: enrollment.purpose, authMode, installSudo },
            manager: m,
          },
        );
      return this.issued(enrollment, token, installSudo, caKeys);
    });
    this.changed.next(assetId);
    return issued;
  }

  /** Script de alta para un token vigente (se puede descargar varias veces hasta usarlo). */
  async script(token: string): Promise<string> {
    const enrollment = await this.db
      .getRepository(Enrollment)
      .createQueryBuilder('e')
      .where('e.tokenHash = :hash', { hash: hashToken(token) })
      .andWhere("e.status = 'pending'")
      .andWhere('e.expiresAt > now()')
      .getOne();
    if (!enrollment) throw new NotFoundException();
    const caKeys =
      enrollment.authMode === 'ca_certificate' ? await this.caKeys() : [];
    return this.template.render({
      mode: 'online',
      apiUrl: this.publicUrl,
      token,
      ...this.scriptAccess(enrollment, caKeys),
      sudoersVersion: SUDOERS_VERSION,
    });
  }

  /**
   * POST /enroll/<token>/done: consume el token (atómico: de dos llamadas a la vez solo gana
   * una) y encola la verificación. No activa el asset.
   */
  async consume(token: string, hostKeys: HostKeyFingerprint[]): Promise<void> {
    const { enrollmentId, assetId } = await this.db.transaction(async (m) => {
      const rows: [{ id: string; asset_id: string }[], number] = await m.query(
        `UPDATE "enrollments"
            SET "status" = 'confirmed', "method" = 'script', "token_hash" = NULL,
                "confirmed_at" = now(), "reported_host_keys" = $2, "error" = NULL
          WHERE "token_hash" = $1 AND "status" = 'pending' AND "expires_at" > now()
          RETURNING "id", "asset_id"`,
        [hashToken(token), JSON.stringify(dedupeHostKeys(hostKeys))],
      );
      const [row] = rows[0];
      if (!row) throw new NotFoundException();
      // El script siempre instala la clave en el usuario dedicado.
      await this.setConnectionUser(m, row.asset_id, ENROLL_SSH_USER);
      return { enrollmentId: row.id, assetId: row.asset_id };
    });
    await this.enqueueVerification(enrollmentId);
    this.changed.next(assetId);
  }

  /**
   * "Ya lo he añadido": clave añadida a mano o script embebido. Con las huellas que imprime el
   * script (pegadas por el admin), el worker solo acepta una de ellas; sin huellas, TOFU.
   */
  async confirmManual(
    assetId: string,
    sshUser: string,
    hostKeys: HostKeyFingerprint[] = [],
  ): Promise<EnrollmentContract> {
    const id = await this.db.transaction(async (m) => {
      const asset = await this.lockAsset(m, assetId);
      this.assertEnrollable(asset);
      const open = await this.openEnrollment(m, assetId);
      if (open?.status !== 'pending')
        throw new ConflictException(
          open
            ? 'Hay una verificación en curso'
            : 'No hay ningún alta pendiente',
        );
      // En modo CA solo vale el script (embebido: con las huellas pegadas), que configura sshd
      // para el usuario dedicado: no hay clave que añadir a mano.
      if (
        open.authMode === 'ca_certificate' &&
        (sshUser !== ENROLL_SSH_USER || hostKeys.length === 0)
      )
        throw new BadRequestException(
          `En modo CA hay que ejecutar el script (usuario ${ENROLL_SSH_USER}) y pegar las huellas de las host keys que imprime`,
        );
      Object.assign(open, {
        method: 'manual',
        status: 'confirmed',
        sshUser,
        tokenHash: null,
        reportedHostKeys: dedupeHostKeys(hostKeys),
        confirmedAt: new Date(),
        error: null,
      });
      await m.save(open);
      await this.setConnectionUser(m, assetId, sshUser);
      return open.id;
    });
    const enrollment = await this.enqueueVerification(id);
    this.changed.next(assetId);
    return enrollment;
  }

  /** Reintenta la verificación de un enrolamiento fallido. */
  async retryVerification(assetId: string): Promise<EnrollmentContract> {
    const id = await this.db.transaction(async (m) => {
      const asset = await this.lockAsset(m, assetId);
      this.assertEnrollable(asset);
      const last = await m.findOne(Enrollment, {
        where: { assetId },
        order: { createdAt: 'DESC' },
      });
      if (last?.status !== 'failed')
        throw new ConflictException('El último enrolamiento no ha fallado');
      Object.assign(last, { status: 'confirmed', error: null });
      await m.save(last);
      return last.id;
    });
    const enrollment = await this.enqueueVerification(id);
    this.changed.next(assetId);
    return enrollment;
  }

  // --- Utilidades ---

  /**
   * Encola `enrollment.verify` y guarda el id del job. Si Redis falla, el enrolamiento queda
   * `failed` (reintentable) en vez de `confirmed` para siempre.
   */
  private async enqueueVerification(
    enrollmentId: string,
  ): Promise<EnrollmentContract> {
    const repo = this.db.getRepository(Enrollment);
    try {
      const job = await this.jobs.enqueue(JOB_NAMES.enrollmentVerify, {
        enrollmentId,
      });
      await repo.update({ id: enrollmentId }, { jobId: job.id });
    } catch (error) {
      this.logger.error(
        `No se pudo encolar la verificación de ${enrollmentId}: ${(error as Error).message}`,
      );
      await repo.update(
        { id: enrollmentId },
        { status: 'failed', error: 'No se pudo encolar la verificación' },
      );
    }
    return toEnrollment(await repo.findOneByOrFail({ id: enrollmentId }));
  }

  private issued(
    enrollment: Enrollment,
    token: string,
    installSudo: boolean,
    caKeys: string[],
  ): IssuedEnrollment {
    const embeddedScript = this.template.render({
      mode: 'embedded',
      apiUrl: '',
      token: '',
      ...this.scriptAccess(enrollment, caKeys),
      sudoersVersion: SUDOERS_VERSION,
    });
    return {
      ...toEnrollment(enrollment),
      command: installCommand(this.publicUrl, token, installSudo),
      embeddedCommand: embeddedCommand(embeddedScript, installSudo),
      manualCommand: enrollment.publicKey
        ? manualCommand(enrollment.publicKey)
        : null,
    };
  }

  /** Lo que el script instala según el modo: la clave estática o las claves de la CA. */
  private scriptAccess(enrollment: Enrollment, caKeys: string[]) {
    const ca = enrollment.authMode === 'ca_certificate';
    return {
      authMode: enrollment.authMode,
      publicKey: ca ? '' : (enrollment.publicKey ?? ''),
      keyComment: keyComment(enrollment.assetId),
      caKeys: ca ? caKeys : [],
      caVersion: SSH_CA_CONFIG_VERSION,
      issuedAt: Math.floor(Date.now() / 1000),
      adminAccess: enrollment.adminAccess ?? ('keep' as const),
      adminAccessVersion: ADMIN_ACCESS_VERSION,
    };
  }

  /**
   * Claves públicas de las CA vigentes (la que firma y, durante una rotación, la siguiente). Sin
   * proveedor con CA SSH o sin ninguna CA, no se puede generar un script en modo CA.
   */
  private async caKeys(): Promise<string[]> {
    const ca = this.secrets.sshCertificates();
    if (!ca)
      throw new BadRequestException(
        'Ningún proveedor de secretos activo tiene CA SSH (hace falta OpenBao con el motor SSH)',
      );
    const keys = (await ca.sshCaPublicKeys()).map((k) => k.publicKey);
    if (keys.length === 0)
      throw new ConflictException(
        `El proveedor ${ca.id} no tiene ninguna CA SSH (ejecuta pnpm openbao:bootstrap)`,
      );
    return keys;
  }

  /** Certificados si hay un proveedor con CA SSH y alguna CA; si no, clave estática. */
  private async defaultAuthMode(): Promise<SshAuthMode> {
    const ca = this.secrets.sshCertificates();
    if (!ca) return 'static_key';
    try {
      return (await ca.sshCaPublicKeys()).length > 0
        ? 'ca_certificate'
        : 'static_key';
    } catch (error) {
      this.logger.warn(
        `No se pudo consultar la CA SSH de ${ca.id} (${(error as Error).message}): alta con clave estática`,
      );
      return 'static_key';
    }
  }

  /** Clave pública estática del asset: la del último enrolamiento que la instaló. */
  private async staticPublicKey(
    m: EntityManager,
    assetId: string,
  ): Promise<string> {
    const withKey = await m
      .getRepository(Enrollment)
      .createQueryBuilder('e')
      .where('e.assetId = :assetId', { assetId })
      .andWhere('e.publicKey IS NOT NULL')
      .orderBy('e.createdAt', 'DESC')
      .getOne();
    if (!withKey?.publicKey)
      throw new ConflictException('El asset no tiene clave estática');
    return withKey.publicKey;
  }

  private writableProvider(): string {
    return writableSecretsProvider(this.secrets, this.config);
  }

  private expiry(): Date {
    return new Date(Date.now() + this.tokenTtlMs);
  }

  private async findAsset(m: EntityManager, id: string): Promise<Asset> {
    const asset = await m.findOneBy(Asset, { id });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    return asset;
  }

  /** Serializa las operaciones de enrolamiento de un mismo asset. */
  private async lockAsset(m: EntityManager, id: string): Promise<Asset> {
    const asset = await m.findOne(Asset, {
      where: { id },
      lock: { mode: 'pessimistic_write' },
    });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    return asset;
  }

  private assertEnrollable(asset: Asset): void {
    if (asset.status === 'retired')
      throw new ConflictException('El asset está retirado');
    const credentials =
      asset.sshAuth === 'ca_certificate' || asset.credentials.sshPrivateKey;
    if (!asset.connection || !credentials)
      throw new ConflictException('El asset no tiene conexión SSH ni clave');
  }

  private openEnrollment(
    m: EntityManager,
    assetId: string,
  ): Promise<Enrollment | null> {
    return m.findOneBy(Enrollment, {
      assetId,
      status: In([...OPEN_STATUSES]),
    });
  }

  private async setConnectionUser(
    m: EntityManager,
    assetId: string,
    user: string,
  ): Promise<void> {
    const asset = await this.findAsset(m, assetId);
    if (!asset.connection) return;
    asset.connection = { ...asset.connection, user };
    await m.save(asset);
  }
}

export function toEnrollment(e: Enrollment): EnrollmentContract {
  return {
    id: e.id,
    assetId: e.assetId,
    method: e.method,
    purpose: e.purpose,
    authMode: e.authMode,
    adminAccess: e.adminAccess,
    status: e.status,
    expired:
      e.status === 'pending' &&
      e.expiresAt !== null &&
      e.expiresAt.getTime() <= Date.now(),
    expiresAt: e.expiresAt?.toISOString() ?? null,
    publicKey: e.publicKey,
    sshUser: e.sshUser,
    reportedHostKeys: e.reportedHostKeys,
    sudoersVersion: e.sudoersVersion,
    error: e.error,
    jobId: e.jobId,
    confirmedAt: e.confirmedAt?.toISOString() ?? null,
    verifiedAt: e.verifiedAt?.toISOString() ?? null,
    createdAt: e.createdAt.toISOString(),
  };
}

/** 32 bytes aleatorios en base64url (43 caracteres). */
function newToken(): string {
  return randomBytes(32).toString('base64url');
}

/** Solo se guarda el hash: con un volcado de la BD no se pueden usar los tokens vigentes. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function dedupeHostKeys(keys: HostKeyFingerprint[]): HostKeyFingerprint[] {
  const seen = new Set<string>();
  return keys
    .filter((k) => !seen.has(k.fingerprint) && seen.add(k.fingerprint))
    .map(({ type, fingerprint }) => ({ type, fingerprint }));
}
