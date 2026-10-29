import type {
  AssetFacts,
  AssetRelationType,
  AssetType,
} from '@infraward/shared-types';
import type { PrivilegedQuery } from './privileged.js';

/** Resultado de un comando en el host. `code` es null si no terminó (timeout o señal). */
export interface HostCommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Ejecución en el asset padre (p. ej. el nodo Proxmox por SSH con su clave y host key fijada).
 * La da el worker: el descubridor no sabe de SSH ni de secretos.
 * - `run`: el argv tal cual (sin shell en medio), sin privilegios.
 * - `query`: una consulta de la lista cerrada del ayudante de root (`PRIVILEGED_QUERIES`): por SSH,
 *   `sudo -n infraward-query <consulta> <args…>` (sudoers v4); en un CT (`pct exec` desde el
 *   nodo, ya root), el comando real.
 */
export interface HostExec {
  run(argv: string[]): Promise<HostCommandResult>;
  query(query: PrivilegedQuery): Promise<HostCommandResult>;
}

/** Lo que el descubridor necesita saber del asset padre. */
export interface DiscoveryParent {
  id: string;
  name: string;
  facts: AssetFacts;
}

/** Un hijo tal como lo ve el descubridor. */
export interface DiscoveredAsset {
  type: AssetType;
  name: string;
  /** Clave natural estable (§8). Única por tipo. */
  naturalKey: string;
  /**
   * Claves antiguas con las que este mismo hijo pudo guardarse antes (p. ej. un nodo que se ha
   * unido a un clúster): si existe un asset con una de ellas y no con la nueva, se renombra.
   */
  aliases: string[];
  /** Facts del descubridor; se fusionan con los del asset sin pisar los recogidos. */
  facts: AssetFacts;
  /** true si hay que encolar su recolección tras el descubrimiento (p. ej. CT en marcha). */
  collect: boolean;
  /**
   * Padre dentro del mismo listado (hijos anidados: suscripción → dominio → base de datos). Sin
   * él, cuelga del asset descubierto. El padre tiene que aparecer antes en `children`.
   */
  parent?: AssetRef;
}

/** Referencia a un asset por su tipo y clave natural (aún puede no existir). */
export interface AssetRef {
  type: AssetType;
  naturalKey: string;
}

/**
 * Relación no jerárquica entre assets del listado (contenedor → volumen, dominio → certificado).
 * El worker sustituye, para cada origen del listado, sus relaciones de los tipos que gestiona el
 * descubridor (`linkTypes`) por estas.
 */
export interface DiscoveredLink {
  type: AssetRelationType;
  from: AssetRef;
  to: AssetRef;
}

/** Imagen presente en un host Docker (la use o no algún contenedor). */
export interface HostImage {
  imageId: string;
  repoDigests: string[];
  repoTags: string[];
  platform: string | null;
  size: number | null;
}

/** Resultado de `discover`. */
export interface DiscoveryListing {
  /** Hijos que cuelgan de este padre. */
  children: DiscoveredAsset[];
  /**
   * `<tipo>|<clave natural>` de todo lo que existe en el ámbito del descubridor, incluidos los
   * hijos de otros padres (en un clúster, los guests de otros nodos): lo que no esté aquí ha
   * desaparecido; lo que esté en otro padre solo ha cambiado de sitio.
   */
  seen: Set<string>;
  /** false si alguna parte del listado falló: entonces no se marca nada como desaparecido. */
  complete: boolean;
  /**
   * Tipos cuyo listado es parcial aunque el resto esté completo (p. ej. volúmenes y redes sin
   * `docker volume ls` en el sudoers: solo los que usan los contenedores). No se marcan como
   * desaparecidos.
   */
  partialTypes?: AssetType[];
  links?: DiscoveredLink[];
  /**
   * Imágenes del host (Docker). `complete` = `docker images` respondió: solo entonces se quita la
   * relación `stores` de las que ya no están.
   */
  hostImages?: { images: HostImage[]; complete: boolean };
  warnings: string[];
}

/** Cómo se recoge un hijo a través de su padre (sin SSH propio). */
export type CollectTarget = { kind: 'pct'; vmid: number };

/** Hijo ya en el inventario, para decidir cómo recogerlo. */
export interface ChildAsset {
  type: AssetType;
  facts: AssetFacts;
}

/**
 * Descubridor de hijos de un asset (DESIGN §8). Lo activa un rol del padre y genera hijos de
 * `childTypes`. Es de SOLO LECTURA: solo lanza comandos de consulta en el padre.
 */
export interface Discoverer {
  readonly role: string;
  readonly childTypes: readonly AssetType[];
  /** Relaciones que mantiene con `links` (se sustituyen en cada descubrimiento). */
  readonly linkTypes?: readonly AssetRelationType[];
  discover(parent: DiscoveryParent, host: HostExec): Promise<DiscoveryListing>;
  /**
   * Cómo recoger un hijo desde el padre con los mismos playbooks; null si no se puede (p. ej.
   * una VM, o un CT parado). `reason` explica por qué no.
   */
  collectTarget(
    child: ChildAsset,
  ): { target: CollectTarget } | { target: null; reason: string };
}

/** Clave de `DiscoveryListing.seen`. */
export function seenKey(type: AssetType, naturalKey: string): string {
  return `${type}|${naturalKey}`;
}

/** Error de un descubridor con un mensaje apto para guardarse y mostrarse (sin secretos). */
export class DiscoveryError extends Error {}
