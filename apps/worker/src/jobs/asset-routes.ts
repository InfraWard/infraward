import { Inject, Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import type { CollectTarget, Discoverer } from '@infraward/connectors';
import { Asset, AssetRelation } from '@infraward/domain';
import type {
  AssetConnection,
  AssetType,
  SshAuthMode,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { CollectionError } from '../collect/ansible-runner.js';

/** Registro `rol → descubridor` (lo crea `createDiscoverers` de `@infraward/connectors`). */
export const DISCOVERERS = Symbol('DISCOVERERS');

/** Cómo llegar a un asset: directo por SSH o a través de su padre. */
export interface AssetRoute {
  connection: AssetConnection;
  /** Modo de acceso del asset al que se conecta (con `via`, el del padre). */
  auth: SshAuthMode;
  /** Clave estática; null en modo CA. */
  keyRef: string | null;
  /** Huella fijada (con `via`, la del padre: obligatoria). null ⇒ TOFU (solo directo). */
  pinned: string | null;
  via?: CollectTarget;
  /**
   * Host raíz: el asset dueño de la conexión SSH (con `via`, el padre). Contra él cuenta el
   * límite de jobs a la vez (DESIGN §20).
   */
  host: { id: string; name: string };
}

/**
 * Rutas hasta los assets y descubridores de sus roles. Un servidor dado de alta se alcanza con
 * su conexión; un hijo sin conexión propia (CT de Proxmox), a través del padre `contains` si el
 * descubridor del padre sabe hacerlo (`pct exec`).
 */
@Injectable()
export class AssetRoutes {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    @Inject(DISCOVERERS)
    readonly discoverers: ReadonlyMap<string, Discoverer>,
  ) {}

  async route(asset: Asset): Promise<AssetRoute> {
    const ownKey = asset.credentials.sshPrivateKey ?? null;
    if (asset.connection && (ownKey || asset.sshAuth === 'ca_certificate'))
      return {
        connection: asset.connection,
        auth: asset.sshAuth,
        keyRef: ownKey,
        pinned: asset.hostKeyFingerprint,
        host: { id: asset.id, name: asset.name },
      };

    const relation = await this.db
      .getRepository(AssetRelation)
      .findOneBy({ childId: asset.id, type: 'contains' });
    const parent = relation
      ? await this.db.getRepository(Asset).findOneBy({ id: relation.parentId })
      : null;
    const discoverer = parent && this.discovererFor(parent, asset.type);
    if (!parent || !discoverer)
      throw new CollectionError(
        'El asset no tiene conexión SSH propia ni un padre desde el que recogerlo',
      );
    const route = discoverer.collectTarget(asset);
    if (!route.target) throw new CollectionError(route.reason);
    const parentKey = parent.credentials.sshPrivateKey ?? null;
    if (
      parent.status !== 'active' ||
      !parent.connection ||
      (!parentKey && parent.sshAuth !== 'ca_certificate') ||
      // Sin TOFU a través de otro asset: el nodo tiene que tener su huella fijada.
      !parent.hostKeyFingerprint
    )
      throw new CollectionError(
        `El nodo ${parent.name} no está activo o no tiene conexión, clave y host key fijada`,
      );
    return {
      connection: parent.connection,
      auth: parent.sshAuth,
      keyRef: parentKey,
      pinned: parent.hostKeyFingerprint,
      via: route.target,
      host: { id: parent.id, name: parent.name },
    };
  }

  /** Descubridores de los roles del asset (p. ej. un nodo con Proxmox y Docker: los dos). */
  discoverersFor(asset: Asset): Discoverer[] {
    return [...new Set(asset.roles)]
      .map((role) => this.discoverers.get(role))
      .filter((d): d is Discoverer => d !== undefined);
  }

  private discovererFor(
    parent: Asset,
    childType: AssetType,
  ): Discoverer | undefined {
    return this.discoverersFor(parent).find((d) =>
      d.childTypes.includes(childType),
    );
  }
}
