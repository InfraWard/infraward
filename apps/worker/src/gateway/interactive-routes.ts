import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Asset, AssetRelation } from '@infraward/domain';
import {
  ENROLL_SSH_USER,
  PODMAN_ENABLE_SCRIPT,
  parseTerminalAction,
  type AssetConnection,
  type TerminalAction,
  type TerminalHop,
} from '@infraward/shared-types';
import { DataSource } from 'typeorm';
import { AssetRoutes } from '../jobs/asset-routes.js';

const VMID = /^[1-9]\d{2,8}$/;
const CONTAINER_ID = /^[0-9a-f]{64}$/;
const ACCOUNT = /^[a-z_][a-z0-9_-]{0,31}$/;

/**
 * Shell de un contenedor (corre en el host Docker, con el id como `$1`, nunca interpolado): bash
 * si lo tiene, si no sh; sin ninguno, un mensaje claro. Comprueba antes que está en marcha.
 */
const shellScript = (cli: 'docker' | 'podman') =>
  [
    'id=$1',
    `[ "$(${cli} inspect -f '{{.State.Running}}' "$id" 2>/dev/null)" = true ] || { echo 'El contenedor no está en marcha' >&2; exit 125; }`,
    `if ${cli} exec "$id" /bin/bash -c : 2>/dev/null; then exec ${cli} exec -it "$id" /bin/bash`,
    `elif ${cli} exec "$id" /bin/sh -c : 2>/dev/null; then exec ${cli} exec -it "$id" /bin/sh`,
    "else echo 'El contenedor no tiene shell (sh ni bash)' >&2; exit 127; fi",
  ].join('\n');
export const DOCKER_SHELL_SCRIPT = shellScript('docker');
/** Lo mismo con Podman como root (solo contenedores rootful: Podman no tiene demonio). */
export const PODMAN_SHELL_SCRIPT = shellScript('podman');

/** Destino de una terminal: conexión SSH (con la cuenta de administración) y comando remoto. */
export interface InteractiveRoute {
  connection: AssetConnection;
  /** Huella de la host key fijada del servidor (obligatoria: sin TOFU). */
  pinned: string;
  /** Servidor por el que se entra (cupo por host). */
  host: { id: string; name: string };
  /** Saltos dentro del servidor (CT, contenedor), para el registro. */
  hops: TerminalHop[];
  /** argv remoto; null = shell de login de la cuenta. */
  command: string[] | null;
  /** Acción de solo lectura: lo que teclee la persona no llega al servidor. */
  readOnly: boolean;
}

/** Error de destino con un mensaje apto para la persona. */
export class InteractiveRouteError extends Error {}

/**
 * Cómo se llega a una terminal (DESIGN §11), con la conexión de `AssetRoutes` (la del worker):
 * servidor → SSH directo; CT → SSH al nodo + `sudo pct enter <vmid>`; contenedor → SSH a su host
 * Docker (o al nodo del CT que lo tiene) + `docker exec -it` con la shell que haya. Siempre con la
 * cuenta de administración, nunca con `inventory`; ids y vmid validados, sin texto libre.
 */
@Injectable()
export class InteractiveRoutes {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly routes: AssetRoutes,
  ) {}

  async resolve(
    assetId: string,
    account: string,
    action: TerminalAction | null = null,
  ): Promise<InteractiveRoute> {
    const route = await this.resolveShell(assetId, account, action);
    return { ...route, readOnly: action !== null };
  }

  private async resolveShell(
    assetId: string,
    account: string,
    action: TerminalAction | null,
  ): Promise<Omit<InteractiveRoute, 'readOnly'>> {
    if (!ACCOUNT.test(account) || account === ENROLL_SSH_USER || account === 'root')
      throw new InteractiveRouteError('Cuenta de administración no válida');
    const asset = await this.db.getRepository(Asset).findOneBy({ id: assetId });
    if (!asset) throw new InteractiveRouteError('El asset no existe');
    if (action) return this.actionRoute(asset, account, action);
    switch (asset.type) {
      case 'server': {
        const base = await this.route(asset);
        if (base.via) throw new InteractiveRouteError('El servidor no tiene SSH propio');
        return { ...this.connection(base, account), hops: [], command: null };
      }
      case 'lxc': {
        const base = await this.route(asset);
        const vmid = base.via?.kind === 'pct' ? String(base.via.vmid) : '';
        if (!VMID.test(vmid)) throw new InteractiveRouteError('El CT no tiene vmid');
        return {
          ...this.connection(base, account),
          hops: [{ kind: 'pct', vmid: Number(vmid) }],
          command: ['sudo', '-n', 'pct', 'enter', vmid],
        };
      }
      case 'container': {
        const facts = asset.facts.docker as
          | { id?: unknown; engine?: unknown; rootlessUser?: unknown }
          | undefined;
        const id = facts?.id;
        if (typeof id !== 'string' || !CONTAINER_ID.test(id))
          throw new InteractiveRouteError('El contenedor no tiene su id de Docker');
        if (facts?.rootlessUser !== undefined)
          throw new InteractiveRouteError(
            'La terminal no entra en contenedores de Podman rootless',
          );
        const podman = facts?.engine === 'podman';
        const parent = await this.parent(asset);
        const base = await this.route(parent);
        const docker = [
          'sh',
          '-c',
          podman ? PODMAN_SHELL_SCRIPT : DOCKER_SHELL_SCRIPT,
          'sh',
          id,
        ];
        const hop: TerminalHop = { kind: podman ? 'podman' : 'docker', containerId: id };
        if (!base.via)
          return {
            ...this.connection(base, account),
            hops: [hop],
            command: ['sudo', '-n', ...docker],
          };
        const vmid = String(base.via.vmid);
        if (!VMID.test(vmid)) throw new InteractiveRouteError('El CT no tiene vmid');
        return {
          ...this.connection(base, account),
          hops: [{ kind: 'pct', vmid: Number(vmid) }, hop],
          command: ['sudo', '-n', 'pct', 'exec', vmid, '--', ...docker],
        };
      }
      default:
        throw new InteractiveRouteError('Solo se abren terminales en servidores, CT y contenedores');
    }
  }

  /**
   * Acción de solo lectura (comando fijo, nunca texto libre): habilitar Podman rootless corre
   * `PODMAN_ENABLE_SCRIPT` como root en el servidor (o en el CT, por `pct exec` desde el nodo) con
   * los usuarios como argumentos, ya validados por la API y aquí otra vez.
   */
  private async actionRoute(
    asset: Asset,
    account: string,
    raw: TerminalAction,
  ): Promise<Omit<InteractiveRoute, 'readOnly'>> {
    const action = parseTerminalAction(raw);
    if (!action) throw new InteractiveRouteError('Acción no válida');
    const script = ['sh', '-c', PODMAN_ENABLE_SCRIPT, 'sh', ...action.users];
    if (asset.type === 'server') {
      const base = await this.route(asset);
      if (base.via) throw new InteractiveRouteError('El servidor no tiene SSH propio');
      return { ...this.connection(base, account), hops: [], command: ['sudo', '-n', ...script] };
    }
    if (asset.type === 'lxc') {
      const base = await this.route(asset);
      const vmid = base.via?.kind === 'pct' ? String(base.via.vmid) : '';
      if (!VMID.test(vmid)) throw new InteractiveRouteError('El CT no tiene vmid');
      return {
        ...this.connection(base, account),
        hops: [{ kind: 'pct', vmid: Number(vmid) }],
        command: ['sudo', '-n', 'pct', 'exec', vmid, '--', ...script],
      };
    }
    throw new InteractiveRouteError('Esta acción solo se ejecuta en servidores y CT');
  }

  private async route(asset: Asset) {
    try {
      return await this.routes.route(asset);
    } catch (error) {
      throw new InteractiveRouteError((error as Error).message);
    }
  }

  private async parent(asset: Asset): Promise<Asset> {
    const relation = await this.db
      .getRepository(AssetRelation)
      .findOneBy({ childId: asset.id, type: 'contains' });
    const parent = relation
      ? await this.db.getRepository(Asset).findOneBy({ id: relation.parentId })
      : null;
    if (!parent || (parent.type !== 'server' && parent.type !== 'lxc'))
      throw new InteractiveRouteError('El contenedor no tiene un host Docker');
    return parent;
  }

  private connection(
    base: Awaited<ReturnType<AssetRoutes['route']>>,
    account: string,
  ): Pick<InteractiveRoute, 'connection' | 'pinned' | 'host'> {
    if (base.auth !== 'ca_certificate')
      throw new InteractiveRouteError(`${base.host.name} no está en modo CA`);
    if (!base.pinned)
      throw new InteractiveRouteError(`${base.host.name} no tiene la host key fijada`);
    return {
      connection: { ...base.connection, user: account },
      pinned: base.pinned,
      host: base.host,
    };
  }
}
