import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { createDiscoverers, type Discoverer } from '@infraward/connectors';
import { Asset, AssetRelation } from '@infraward/domain';
import {
  DISCOVERABLE_ROLES,
  discoveryDeduplicationId,
  JOB_NAMES,
  type EnqueueJobResponse,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { JobsService } from '../jobs/jobs.service.js';

/** Estados en los que se puede recoger un asset (alta verificada o descubierto). */
const COLLECTABLE = new Set(['active', 'missing']);
const DISCOVERABLE = new Set<string>(DISCOVERABLE_ROLES);

/**
 * Lanza recolecciones y descubrimientos (DESIGN §8). La API solo encola: Ansible y los
 * descubridores los ejecuta el worker. Las comprobaciones son las mismas que hará el worker,
 * para responder 409 en lugar de encolar un job que va a fallar.
 */
@Injectable()
export class CollectionService {
  private readonly discoverers = createDiscoverers();

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly jobs: JobsService,
  ) {}

  /**
   * Encola `asset.collect`. Si ya hay una recolección pendiente o en curso, devuelve esa.
   * `parentJobId`: la operación en lote que la pide.
   */
  async collect(
    assetId: string,
    options: { parentJobId?: string } = {},
  ): Promise<EnqueueJobResponse> {
    const asset = await this.find(assetId);
    if (!COLLECTABLE.has(asset.status))
      throw new ConflictException(
        `El asset está en estado ${asset.status}: solo se recogen assets dados de alta o descubiertos`,
      );
    if (!hasSshAccess(asset)) await this.assertCollectableViaParent(asset);
    return this.jobs.enqueue(
      JOB_NAMES.assetCollect,
      { assetId },
      { deduplicationId: assetId, parentJobId: options.parentJobId },
    );
  }

  /** Encola `asset.discover` (hijos del asset). Deduplicado por asset. */
  async discover(assetId: string): Promise<EnqueueJobResponse> {
    const asset = await this.find(assetId);
    if (!asset.roles.some((role) => DISCOVERABLE.has(role)))
      throw new ConflictException(
        `El asset no tiene ningún rol con descubridor (${DISCOVERABLE_ROLES.join(', ')})`,
      );
    if (asset.status !== 'active')
      throw new ConflictException('Solo se descubre desde un asset activo');
    // Un servidor con su conexión y huella fijada, o un CT a través de su nodo.
    if (hasSshAccess(asset)) {
      if (!asset.hostKeyFingerprint)
        throw new ConflictException(
          'Solo se descubre desde un servidor con conexión, clave y host key fijada (recógelo antes)',
        );
    } else {
      await this.assertCollectableViaParent(asset);
    }
    return this.jobs.enqueue(
      JOB_NAMES.assetDiscover,
      { assetId },
      { deduplicationId: discoveryDeduplicationId(assetId) },
    );
  }

  private async find(id: string): Promise<Asset> {
    const asset = await this.db.getRepository(Asset).findOneBy({ id });
    if (!asset) throw new NotFoundException('Asset no encontrado');
    return asset;
  }

  /**
   * Un hijo sin conexión propia se recoge (y se descubre: p. ej. los contenedores de un CT)
   * desde su padre si su descubridor sabe hacerlo.
   */
  private async assertCollectableViaParent(asset: Asset): Promise<void> {
    const relation = await this.db
      .getRepository(AssetRelation)
      .findOneBy({ childId: asset.id, type: 'contains' });
    const parent = relation
      ? await this.db.getRepository(Asset).findOneBy({ id: relation.parentId })
      : null;
    const discoverer = parent?.roles
      .map((role) => this.discoverers.get(role))
      .find(
        (d): d is Discoverer =>
          d !== undefined && d.childTypes.includes(asset.type),
      );
    if (!parent || !discoverer)
      throw new ConflictException(
        'El asset no tiene conexión SSH propia ni un padre desde el que recogerlo',
      );
    const route = discoverer.collectTarget(asset);
    if (!route.target) throw new ConflictException(route.reason);
    if (
      parent.status !== 'active' ||
      !hasSshAccess(parent) ||
      !parent.hostKeyFingerprint
    )
      throw new ConflictException(
        `El nodo ${parent.name} no está activo o no tiene conexión, clave y host key fijada`,
      );
  }
}

/** Conexión propia y con qué entrar: la clave estática o, en modo CA, los certificados. */
function hasSshAccess(asset: Asset): boolean {
  return (
    asset.connection !== null &&
    (Boolean(asset.credentials.sshPrivateKey) ||
      asset.sshAuth === 'ca_certificate')
  );
}
