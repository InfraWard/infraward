import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  DiscoveryError,
  DomainApiError,
  type Discoverer,
  type DiscoveryListing,
} from '@infraward/connectors';
import {
  Asset,
  Notification,
  scansAutomatically,
} from '@infraward/domain';
import { SecretError, SecretsService } from '@infraward/secrets';
import {
  discoveryDeduplicationId,
  HOST_SBOM_ASSET_TYPES,
  JOB_NAMES,
  type AssetCollectJobData,
  type AssetCollectJobResult,
  type AssetDiscoverJobData,
  type AssetDiscoverJobResult,
  type AssetFacts,
  type AssetStatus,
  type CollectedFacts,
  type DomainsSyncJobData,
  type DomainsTestJobData,
  type InventoryReconcileJobData,
  type InventoryReconcileJobResult,
  type InventoryTrigger,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { randomUUID } from 'node:crypto';
import {
  DataSource,
  Like,
  QueryFailedError,
  type EntityManager,
} from 'typeorm';
import { AnsibleRunner, CollectionError } from '../collect/ansible-runner.js';
import {
  checkSudoers,
  detectRoles,
  mergeRoles,
  normalizeCollection,
} from '../collect/normalize.js';
import {
  CLONE_KEY_SEPARATOR,
  decideMachineIdentity,
  type IdentityCandidate,
} from '../collect/machine-identity.js';
import type { EnvironmentVariables } from '../config/env.validation.js';
import {
  HostKeyMismatchError,
  selectHostKey,
  type ScannedHostKey,
} from '../ssh/host-keys.js';
import { throughPct } from '../ssh/pct.js';
import { SshClient, SshError } from '../ssh/ssh-client.js';
import { SshIdentities } from '../ssh/ssh-identity.js';
import { ScanScheduler } from '../scan/scan-scheduler.js';
import { InventoryReconciler } from '../inventory/reconciler.js';
import { ListingReconciler } from '../inventory/listing-reconciler.js';
import { DomainSync } from '../domains/domain-sync.js';
import { ServiceLinker } from '../domains/service-linker.js';
import {
  saveSnapshotIfChanged,
  SEEN,
} from '../inventory/maintenance.js';
import { recordQueued } from './job-runs.js';
import { AssetRoutes } from './asset-routes.js';
import { PrioritizeTrigger } from '../intel/prioritize-trigger.js';
import { reportProgress } from './progress.js';
import { assertFence } from './fence.js';
import { HostSlots } from './host-slots.js';
import { isInterruption } from './job-context.js';
import { JobQueues } from './job-queues.js';

/**
 * Resultado de guardar una recolección: guardada (con snapshot nuevo, o null si nada cambió), o
 * duplicado sin escribir nada.
 */
type SaveOutcome =
  | { snapshotId: string | null; roles: string[]; duplicateOf?: undefined }
  | { duplicateOf: { id: string; name: string } };

/** Último evento de una recolección guardada. */
function collectedMessage(
  warnings: readonly string[],
  clone: CollectedFacts['infraward']['machineIdClone'],
): string {
  const base = warnings.length
    ? `Recolección parcial (${warnings.length} avisos)`
    : 'Recolección completada';
  return clone
    ? `${base} (machine-id clonado: compartido con ${clone.sharedWith.map((s) => s.name).join(', ')})`
    : base;
}

/** Estados en los que se puede recoger un asset (tras el alta verificada o el descubrimiento). */
const COLLECTABLE = new Set<AssetStatus>(['active', 'missing']);
const HOST_SBOM_TYPES = new Set<string>(HOST_SBOM_ASSET_TYPES);

/**
 * Claves de `facts` que escriben los descubridores (p. ej. `proxmox` en un CT). La recolección
 * sustituye el resto de facts pero conserva estas.
 */
const DISCOVERER_FACT_KEYS = ['proxmox', 'docker'] as const;

/** Horas durante las que no se repite el aviso del mismo fallo de un asset (§10). */
const FAILURE_REPEAT_HOURS = 24;

const KNOWN_ERRORS = [
  CollectionError,
  DiscoveryError,
  SshError,
  HostKeyMismatchError,
  SecretError,
  DomainApiError,
];

/**
 * Consumidor de la cola `discovery` (DESIGN §8). Todo es de solo lectura en los servidores.
 * - `asset.collect`: recoge un asset con Ansible y guarda un Snapshot. Un servidor se recoge
 *   por SSH con su host key fijada (o TOFU si no hay); un hijo descubierto (CT de Proxmox), desde
 *   su padre con la conexión `infraward_pct`. Después encola el descubrimiento de los roles que
 *   tengan descubridor.
 * - `asset.discover`: lista los hijos con el descubridor del rol (Proxmox: CT y VMs), los
 *   reconcilia con el inventario y encola la recolección de los que se pueden recoger.
 */
/** Jobs de esta cola tras los que cambia el contexto de la prioridad (DESIGN §9). */
const PRIORITY_INPUTS = new Set<string>([
  JOB_NAMES.assetCollect,
  JOB_NAMES.assetDiscover,
  JOB_NAMES.domainsSync,
  JOB_NAMES.servicesLink,
]);

@Injectable()
export class DiscoveryProcessor {
  private readonly logger = new Logger(DiscoveryProcessor.name);

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly ssh: SshClient,
    private readonly ansible: AnsibleRunner,
    private readonly queue: JobQueues,
    private readonly routes: AssetRoutes,
    private readonly scans: ScanScheduler,
    private readonly identities: SshIdentities,
    private readonly reconciler: InventoryReconciler,
    private readonly listings: ListingReconciler,
    private readonly domains: DomainSync,
    @Optional() private readonly services?: ServiceLinker,
    @Optional() private readonly prioritize?: PrioritizeTrigger,
    @Optional() private readonly slots?: HostSlots,
  ) {}

  async process(job: Job): Promise<unknown> {
    const result = await this.dispatch(job);
    // Facts, contenedores o caminos de dominios nuevos: la prioridad se recalcula.
    if (PRIORITY_INPUTS.has(job.name)) await this.prioritize?.request(job.name);
    return result;
  }

  private async dispatch(job: Job): Promise<unknown> {
    switch (job.name) {
      case JOB_NAMES.assetCollect:
        return this.guard(job, 'Recolección', 'la recolección', () =>
          this.collect(job as Job<AssetCollectJobData, AssetCollectJobResult>),
        );
      case JOB_NAMES.assetDiscover:
        return this.guard(job, 'Descubrimiento', 'el descubrimiento', () =>
          this.discover(
            job as Job<AssetDiscoverJobData, AssetDiscoverJobResult>,
          ),
        );
      case JOB_NAMES.domainsTest:
        return this.domains.test(job as Job<DomainsTestJobData>);
      case JOB_NAMES.domainsSync:
        return this.guard(job, 'Sincronización', 'la sincronización', () =>
          this.domains.sync(job as Job<DomainsSyncJobData>),
        );
      case JOB_NAMES.servicesLink:
        if (!this.services) throw new Error('Sin ServiceLinker');
        return this.services.link();
      case JOB_NAMES.inventoryReconcile:
        return this.reconciler.run(
          job as Job<InventoryReconcileJobData, InventoryReconcileJobResult>,
        );
      default:
        throw new Error(
          `Job desconocido en la cola ${job.queueName}: ${job.name}`,
        );
    }
  }

  /** Caminos de los dominios (QoL-5b) tras un cambio en el inventario; un fallo solo va al log. */
  private async relinkServices(): Promise<void> {
    try {
      await this.services?.link();
    } catch (error) {
      this.logger.warn(
        `No se pudieron calcular los caminos de los dominios: ${(error as Error).name}`,
      );
    }
  }

  /** Errores: los conocidos llevan un mensaje apto para mostrarse; los demás, nunca. */
  private async guard<T>(
    job: Job<{ assetId: string }>,
    what: string,
    during: string,
    fn: () => Promise<T>,
  ): Promise<T> {
    const { assetId } = job.data;
    try {
      return await fn();
    } catch (error) {
      // Host ocupado, parada de la réplica o ejecución sustituida: no es un fallo del job.
      if (isInterruption(error)) throw error;
      const known = KNOWN_ERRORS.some((type) => error instanceof type);
      const message = known
        ? (error as Error).message
        : `Error interno durante ${during}`;
      if (known) {
        this.logger.warn(`${what} de ${assetId}: ${message}`);
      } else {
        // Tipo y traza, nunca el mensaje: un error ajeno podría llevar datos sensibles.
        const { name, stack } = error as Error;
        const frames = stack?.split('\n').slice(1).join('\n') ?? '';
        this.logger.error(`${what} de ${assetId}: ${name}\n${frames}`);
      }
      await reportProgress(job, 100, `Fallo: ${message}`);
      if ((job.data as { trigger?: InventoryTrigger }).trigger === 'reconcile')
        await this.notifyFailure(assetId, what, message);
      throw new Error(message, { cause: error });
    }
  }

  /**
   * Fallo en la cadena de una reconciliación (§10): el asset no cambia de estado; se avisa. El
   * mismo fallo del mismo asset no se repite en `FAILURE_REPEAT_HOURS` (sería un aviso por ciclo).
   */
  private async notifyFailure(
    assetId: string,
    what: string,
    message: string,
  ): Promise<void> {
    try {
      const asset = await this.db.getRepository(Asset).findOne({
        where: { id: assetId },
        select: { id: true, name: true, type: true },
      });
      const text = `${what} de ${asset?.name ?? assetId} en la reconciliación: ${message}`;
      const [repeated]: unknown[] = await this.db.query(
        `SELECT 1 FROM notifications
          WHERE kind = 'reconcile_failed' AND asset_id IS NOT DISTINCT FROM $1
            AND message = $2 AND created_at > now() - make_interval(hours => $3)
          LIMIT 1`,
        [asset?.id ?? null, text, FAILURE_REPEAT_HOURS],
      );
      if (repeated) return;
      await this.db.getRepository(Notification).insert({
        kind: 'reconcile_failed',
        assetId: asset?.id ?? null,
        assetName: asset?.name ?? null,
        message: text,
        items: asset
          ? [{ id: asset.id, name: asset.name, type: asset.type }]
          : [],
        total: asset ? 1 : 0,
      });
    } catch (error) {
      this.logger.warn(
        `No se pudo guardar el aviso del fallo de ${assetId}: ${(error as Error).name}`,
      );
    }
  }

  // --- asset.collect ---

  private async collect(
    job: Job<AssetCollectJobData, AssetCollectJobResult>,
  ): Promise<AssetCollectJobResult> {
    const { assetId, trigger } = job.data;
    this.logger.log(`Recogiendo el asset ${assetId}`);
    const asset = await this.db.getRepository(Asset).findOneBy({ id: assetId });
    if (!asset) throw new CollectionError('El asset no existe');
    if (!COLLECTABLE.has(asset.status))
      throw new CollectionError(
        `El asset está en estado ${asset.status}: solo se recogen assets dados de alta o descubiertos`,
      );
    const route = await this.routes.route(asset);
    const { connection: target, via } = route;
    await this.slots?.acquire(route.host.id, route.host.name);

    await reportProgress(
      job,
      5,
      `Leyendo la host key de ${target.host}${via ? ' (nodo del CT)' : ''}`,
    );
    const scanned = await this.ssh.scanHostKeys(target.host, target.port);
    // Con huella fijada solo vale esa; sin ella (p. ej. alta anterior a la sesión 6), TOFU.
    const hostKey = selectHostKey(scanned, route.pinned, []);

    await reportProgress(job, 15, `Conectando como ${target.user}`);
    // Clave estática (sin caché) o par efímero con certificado de la CA (modo CA).
    const identity = await this.identities.resolve(route, {
      assetId,
      jobId: job.id,
    });

    await reportProgress(
      job,
      25,
      via
        ? `Recogiendo el CT ${via.vmid} con pct exec desde el nodo`
        : 'Recogiendo facts, paquetes, servicios y puertos',
    );
    const raw = await this.ansible.collect(target, identity, hostKey, via);

    await reportProgress(job, 85, 'Guardando los facts');
    const facts = normalizeCollection(raw);
    const detected = detectRoles(facts);
    // Los CT clonados comparten machine-id: su clave natural es la del descubridor.
    const direct = !via;
    const scannedFingerprints = scanned.map((k) => k.fingerprint);

    let saved: SaveOutcome;
    try {
      saved = await this.save(job, assetId, facts, detected, hostKey, {
        direct,
        assignNaturalKey: direct,
        scanned: scannedFingerprints,
      });
    } catch (error) {
      // Otro asset se quedó el mismo machine-id entre la comprobación y el commit: al repetir,
      // la comprobación lo ve (duplicado, o aviso si está retirado).
      if (!direct || !isUniqueViolation(error)) throw error;
      facts.infraward.warnings = facts.infraward.warnings.filter(
        (w) => !w.startsWith('machine-id'),
      );
      saved = await this.save(job, assetId, facts, detected, hostKey, {
        direct,
        assignNaturalKey: direct,
        scanned: scannedFingerprints,
      });
    }

    if (saved.duplicateOf) {
      const { duplicateOf } = saved;
      const result: AssetCollectJobResult = {
        assetId,
        snapshotId: null,
        duplicateOf,
        roles: asset.roles,
        hostKeyFingerprint: hostKey.fingerprint,
        sudoersVersion: facts.infraward.sudoersVersion,
        via: facts.infraward.via,
        discoveryJobId: null,
        hostScanJobId: null,
        warnings: [],
      };
      await reportProgress(
        job,
        100,
        `Duplicado de ${duplicateOf.name}: no se ha guardado nada`,
      );
      this.logger.warn(
        `Asset ${assetId}: su machine-id ya es del asset ${duplicateOf.id}; marcado como duplicado sin guardar nada`,
      );
      return result;
    }

    const discoveryJobId = await this.enqueueDiscovery(
      assetId,
      saved.roles,
      job.id,
      trigger,
    );
    // SBOM del sistema (§9): copia las BDs de paquetes recién vistas, sin sudo. Es automático:
    // solo con el escaneo activado y periódico en su política (§10), leída ahora y no al empezar
    // (el descubrimiento o un cambio de reglas pueden haberla recalculado entretanto).
    const hostScanJobId =
      HOST_SBOM_TYPES.has(asset.type) &&
      scansAutomatically(await this.currentPolicy(assetId))
        ? await this.scans.enqueueHostScan(assetId, job.id)
        : null;
    const result: AssetCollectJobResult = {
      assetId,
      snapshotId: saved.snapshotId,
      unchanged: saved.snapshotId === null,
      duplicateOf: null,
      roles: saved.roles,
      hostKeyFingerprint: hostKey.fingerprint,
      sudoersVersion: facts.infraward.sudoersVersion,
      via: facts.infraward.via,
      discoveryJobId,
      hostScanJobId,
      warnings: facts.infraward.warnings,
    };
    // Puertos o nginx nuevos cambian los caminos de los dominios; si hay descubrimiento, lo hace él.
    if (!discoveryJobId) await this.relinkServices();
    await reportProgress(
      job,
      100,
      `${collectedMessage(result.warnings, facts.infraward.machineIdClone)}${result.unchanged ? ' (sin cambios)' : ''}`,
    );
    this.logger.log(
      `Asset ${assetId} recogido: ${result.snapshotId ? `snapshot ${result.snapshotId}` : 'sin cambios'}, roles [${result.roles.join(', ')}]`,
    );
    return result;
  }

  /**
   * Snapshot + asset en una transacción, con la fila del asset bloqueada: si se retiró o le
   * cambiaron la huella mientras tanto, no se escribe nada. Si el machine-id es de otro asset no
   * retirado (la misma máquina dada de alta dos veces), solo se marca el duplicado.
   */
  private save(
    job: Job,
    assetId: string,
    facts: CollectedFacts,
    detected: string[],
    hostKey: ScannedHostKey,
    options: {
      direct: boolean;
      assignNaturalKey: boolean;
      /** Huellas de todas las host keys del servidor (para distinguir clones de duplicados). */
      scanned: readonly string[];
    },
  ): Promise<SaveOutcome> {
    return this.db.transaction(async (m) => {
      await assertFence(m);
      const current = await m.findOne(Asset, {
        where: { id: assetId },
        lock: { mode: 'pessimistic_write' },
      });
      if (!current || !COLLECTABLE.has(current.status))
        throw new CollectionError(
          'El asset se retiró o cambió de estado durante la recolección',
        );
      if (
        options.direct &&
        current.hostKeyFingerprint &&
        current.hostKeyFingerprint !== hostKey.fingerprint
      )
        throw new HostKeyMismatchError(
          'La huella fijada del asset cambió durante la recolección',
        );

      let naturalKey = current.naturalKey;
      if (options.assignNaturalKey) {
        const identity = decideMachineIdentity({
          assetId: current.id,
          currentKey: current.naturalKey,
          machineId: facts.machineId,
          fingerprint: current.hostKeyFingerprint ?? hostKey.fingerprint,
          scanned: options.scanned,
          candidates: await this.identityCandidates(m, current, facts),
        });
        if (identity.duplicateOf) {
          await m.update(Asset, current.id, {
            duplicateOfId: identity.duplicateOf.id,
          });
          return { duplicateOf: identity.duplicateOf };
        }
        naturalKey = identity.naturalKey;
        facts.infraward.machineIdClone = identity.clone;
        facts.infraward.warnings.push(...identity.warnings);
      } else if (
        options.direct &&
        facts.machineId &&
        current.naturalKey !== facts.machineId
      )
        facts.infraward.warnings.push(
          `machine-id ${facts.machineId} ya pertenece a otro servidor: no se asigna como clave natural`,
        );

      const roles = mergeRoles(current.roles, detected);
      checkSudoers(facts, roles);
      // Lo que escribieron los descubridores (p. ej. `proxmox`) no es de la recolección.
      const kept = Object.fromEntries(
        DISCOVERER_FACT_KEYS.filter((k) => k in current.facts).map((k) => [
          k,
          current.facts[k],
        ]),
      );
      const stored: AssetFacts = {
        ...(facts as unknown as AssetFacts),
        ...kept,
      };
      // Snapshot solo si cambió algo de verdad (§10); los facts se actualizan siempre.
      const snapshotId = await saveSnapshotIfChanged(
        m,
        assetId,
        stored,
        roles,
        'collect',
        job.id ?? null,
      );
      Object.assign(current, {
        facts: stored,
        roles,
        naturalKey,
        duplicateOfId: null,
        // La huella de un CT recogido por pct exec es la del nodo: no se fija en el CT.
        hostKeyFingerprint: options.direct
          ? (current.hostKeyFingerprint ?? hostKey.fingerprint)
          : current.hostKeyFingerprint,
        // Visto de nuevo: `missing` vuelve a `active` y su contador a cero (§10).
        status: 'active',
        ...SEEN,
        // Recogido = reconciliado: la siguiente periódica cuenta desde aquí (§10).
        reconciledAt: new Date(),
      } satisfies Partial<Asset>);
      await m.save(current);
      return { snapshotId, roles };
    });
  }

  /**
   * Assets del mismo tipo cuya clave natural es el machine-id que reporta este servidor o la de
   * un clon suyo (`<machine-id>+<huella>`), para decidir entre misma máquina, clon o nada.
   */
  private identityCandidates(
    m: EntityManager,
    asset: Asset,
    facts: CollectedFacts,
  ): Promise<IdentityCandidate[]> {
    const machineId = facts.machineId;
    if (!machineId) return Promise.resolve([]);
    const clones = `${machineId.replace(/[\\%_]/g, String.raw`\$&`)}${CLONE_KEY_SEPARATOR}%`;
    return m.find(Asset, {
      where: [
        { type: asset.type, naturalKey: machineId },
        { type: asset.type, naturalKey: Like(clones) },
      ],
      select: {
        id: true,
        name: true,
        status: true,
        naturalKey: true,
        hostKeyFingerprint: true,
      },
    });
  }

  /** La política efectiva guardada ahora mismo (null si el asset ya no existe). */
  private async currentPolicy(
    assetId: string,
  ): Promise<Asset['effectivePolicy'] | null> {
    const row = await this.db.getRepository(Asset).findOne({
      where: { id: assetId },
      select: { id: true, effectivePolicy: true },
    });
    return row?.effectivePolicy ?? null;
  }

  /**
   * Tras recoger, encola el descubrimiento si algún rol tiene descubridor (§8: descubrimiento
   * recursivo). Si no se puede encolar, la recolección sigue siendo válida.
   */
  private async enqueueDiscovery(
    assetId: string,
    roles: string[],
    parentJobId?: string,
    trigger?: InventoryTrigger,
  ): Promise<string | null> {
    if (!roles.some((role) => this.routes.discoverers.has(role))) return null;
    try {
      const job = await this.queue.add(
        JOB_NAMES.assetDiscover,
        {
          assetId,
          ...(trigger ? { trigger } : {}),
        } satisfies AssetDiscoverJobData,
        {
          jobId: randomUUID(),
          deduplication: { id: discoveryDeduplicationId(assetId) },
        },
      );
      await recordQueued(this.db, job, parentJobId, this.logger);
      this.logger.log(`Descubrimiento de ${assetId} encolado (job ${job.id})`);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar el descubrimiento de ${assetId}: ${(error as Error).name}`,
      );
      return null;
    }
  }

  // --- asset.discover ---

  private async discover(
    job: Job<AssetDiscoverJobData, AssetDiscoverJobResult>,
  ): Promise<AssetDiscoverJobResult> {
    const { assetId, trigger } = job.data;
    this.logger.log(`Descubriendo los hijos de ${assetId}`);
    const parent = await this.db
      .getRepository(Asset)
      .findOneBy({ id: assetId });
    if (!parent) throw new DiscoveryError('El asset no existe');
    const discoverers = this.routes.discoverersFor(parent);
    if (discoverers.length === 0)
      throw new DiscoveryError(
        'El asset no tiene ningún rol con descubridor (p. ej. proxmox-node, docker-host)',
      );
    if (parent.status !== 'active')
      throw new DiscoveryError(
        'Solo se descubre desde un asset activo (recógelo antes)',
      );
    // Un servidor con su conexión o un CT desde su nodo; siempre con huella fijada (sin TOFU).
    const route = await this.routes.route(parent);
    if (!route.pinned)
      throw new DiscoveryError(
        'Solo se descubre desde un servidor con conexión, clave y host key fijada (recógelo antes)',
      );
    const { connection: target, via } = route;
    await this.slots?.acquire(route.host.id, route.host.name);

    await reportProgress(job, 5, `Leyendo la host key de ${target.host}`);
    const scanned = await this.ssh.scanHostKeys(target.host, target.port);
    const hostKey = selectHostKey(scanned, route.pinned, []);
    const identity = await this.identities.resolve(route, {
      assetId: parent.id,
      jobId: job.id,
    });

    await reportProgress(
      job,
      20,
      `Listando con ${discoverers.map((d) => d.role).join(', ')}${via ? ` (CT ${via.vmid} desde el nodo)` : ''}`,
    );
    // Cada descubridor por separado: si uno falla, no se toca nada de lo suyo, pero los demás
    // siguen. Un fallo de conexión sí corta el job.
    const listings = await this.ssh.session(
      target,
      identity,
      hostKey,
      async (node) => {
        const host = via ? throughPct(node, via.vmid) : node;
        const results: (
          | { discoverer: Discoverer; listing: DiscoveryListing }
          | { discoverer: Discoverer; error: DiscoveryError }
        )[] = [];
        for (const discoverer of discoverers) {
          try {
            const listing = await discoverer.discover(
              { id: parent.id, name: parent.name, facts: parent.facts },
              host,
            );
            results.push({ discoverer, listing });
          } catch (error) {
            if (!(error instanceof DiscoveryError)) throw error;
            results.push({ discoverer, error });
          }
        }
        return results;
      },
    );
    const failed = listings.filter((l) => 'error' in l);
    if (failed.length === listings.length) throw failed[0].error;

    await reportProgress(job, 70, 'Reconciliando los hijos con el inventario');
    const counts = {
      created: 0,
      updated: 0,
      reparented: 0,
      renamed: 0,
      missing: 0,
      reactivated: 0,
      retired: 0,
    };
    const warnings = failed.map(
      (l) => `${l.discoverer.role}: ${l.error.message}`,
    );
    const collect: string[] = [];
    let complete = failed.length === 0;
    for (const l of listings) {
      if ('error' in l) continue;
      const applied = await this.listings.apply(
        { id: parent.id, name: parent.name },
        l.discoverer,
        l.listing,
        job.id ?? null,
      );
      for (const key of Object.keys(counts) as (keyof typeof counts)[])
        counts[key] += applied.counts[key];
      collect.push(...applied.collect);
      warnings.push(...l.listing.warnings, ...applied.warnings);
      complete &&= l.listing.complete;
    }

    await reportProgress(job, 90, 'Encolando la recolección de los hijos');
    const collectJobIds: string[] = [];
    for (const childId of collect) {
      const jobId = await this.enqueueCollect(childId, job.id, trigger);
      if (jobId) collectJobIds.push(jobId);
    }
    // Contenedores: cada imagen nueva se escanea una vez; las ya escaneadas solo se enlazan. Con
    // Docker y Podman en el mismo host, las imágenes de los dos (`stores` es por host): solo se
    // quitan las que ya no están si los dos listados están completos y ninguno falló.
    let scanJobIds: string[] = [];
    const engines = listings.filter(
      (l) => l.discoverer.childTypes.includes('container'),
    );
    const listed = engines.filter(
      (l): l is { discoverer: Discoverer; listing: DiscoveryListing } =>
        !('error' in l),
    );
    if (listed.length > 0)
      scanJobIds = await this.scans.afterDiscovery(
        parent.id,
        listed.length === 1 && engines.length === 1
          ? listed[0].listing.hostImages
          : {
              images: listed.flatMap((l) => l.listing.hostImages?.images ?? []),
              complete:
                engines.length === listed.length &&
                listed.every((l) => l.listing.hostImages?.complete === true),
            },
        job.id,
      );
    const collectQueued = collectJobIds.length;
    const scanQueued = scanJobIds.length;

    const result: AssetDiscoverJobResult = {
      assetId,
      discoverers: listings
        .filter((l) => !('error' in l))
        .map((l) => l.discoverer.role),
      ...counts,
      collectQueued,
      scanQueued,
      collectJobIds,
      scanJobIds,
      complete,
      warnings,
    };
    await this.relinkServices();
    await reportProgress(
      job,
      100,
      `Descubrimiento completado: ${result.created} nuevos, ${result.updated} actualizados, ${result.missing} desaparecidos, ${result.retired} retirados`,
    );
    this.logger.log(
      `Hijos de ${assetId}: ${result.created} nuevos, ${result.updated} actualizados, ${result.reparented} movidos, ${result.renamed} renombrados, ${result.missing} desaparecidos, ${result.reactivated} reaparecidos, ${result.retired} retirados, ${collectQueued} recolecciones y ${scanQueued} escaneos encolados`,
    );
    return result;
  }

  /**
   * Encola la recolección de un hijo (deduplicada por asset, igual que la de la API). Devuelve
   * el id del job (el que ya estaba en cola si se deduplicó) o null si no se pudo encolar.
   */
  private async enqueueCollect(
    assetId: string,
    parentJobId?: string,
    trigger?: InventoryTrigger,
  ): Promise<string | null> {
    try {
      const job = await this.queue.add(
        JOB_NAMES.assetCollect,
        {
          assetId,
          ...(trigger ? { trigger } : {}),
        } satisfies AssetCollectJobData,
        { jobId: randomUUID(), deduplication: { id: assetId } },
      );
      await recordQueued(this.db, job, parentJobId, this.logger);
      return job.id ?? null;
    } catch (error) {
      this.logger.warn(
        `No se pudo encolar la recolección de ${assetId}: ${(error as Error).name}`,
      );
      return null;
    }
  }
}

function isUniqueViolation(error: unknown): boolean {
  return (
    error instanceof QueryFailedError &&
    (error.driverError as { code?: string } | undefined)?.code === '23505'
  );
}
