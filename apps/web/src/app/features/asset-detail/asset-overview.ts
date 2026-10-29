import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';
import type {
  Asset,
  AssetRelations,
  AssetRelationWithPeer,
  AssetSummary,
  AssetTreeSummaryNode,
  DockerHostResources,
} from '@infraward/shared-types';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { PanelModule } from '@openng/optimus-ui/panel';
import { TagModule } from '@openng/optimus-ui/tag';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import {
  ASSET_STATUS_LABELS,
  ASSET_STATUS_SEVERITY,
  ASSET_TYPE_ICONS,
  ASSET_TYPE_LABELS,
  RELATION_INCOMING_LABELS,
  RELATION_LABELS,
  RUNTIME_LABELS,
  RUNTIME_SEVERITY,
  SEVERITY_TAG,
  type TagSeverity,
} from '../../shared/labels';
import { fixableLabel, toRow, type InventoryRow } from '../inventory/tree-nodes';
import {
  certificateItems,
  collectionItems,
  connectorItems,
  dnsRecordItems,
  containerItems,
  containerMounts,
  containerNetworks,
  dockerNetworkItems,
  factsPorts,
  factsServices,
  imageItems,
  listeningPorts,
  networkItems,
  pleskItems,
  runningServices,
  systemItems,
  volumeItems,
  zoneItems,
} from './facts-summary';
import { ExpiryThresholds } from '../../core/expiry-thresholds';
import { AssetDomainsCard } from './asset-domains';
import { DnsCheckCard } from './dns-check';
import { DomainServicePathsCard, ServedDomainsCard } from './served-domains';
import { ServicePathCard } from './service-path';
import { AssetNotes } from './asset-notes';
import { AssetProjectsCard } from './asset-projects';
import { AssetPolicyBlock } from './asset-policy';
import { AssetAccessCard } from './asset-access';
import { AdminAccessControl } from './admin-access';
import { AuthService } from '../../core/auth/auth.service';
import { TERMINAL_ASSET_TYPES } from '@infraward/shared-types';

/** Puertos que caben en el resumen (como servicios, el resto en su pestaña). */
const MAX_SUMMARY_PORTS = 8;
/** Hijos que caben en «Contiene». */
const MAX_SUMMARY_CHILDREN = 25;

/** Orden de «Contiene»: colgantes, caducidades cercanas, el resto (orden estable). */
function attentionRank(row: InventoryRow): number {
  if (row.dnsWarning === 'high') return 0;
  if (row.expiry?.warn) return 1;
  if (row.dnsWarning === 'info') return 2;
  return 3;
}

/** Relación con la que un contenedor usa un asset de cada tipo (para «sin uso»). */
const USAGE_RELATION: Partial<Record<string, string>> = {
  image: 'instance_of',
  volume: 'mounts',
  network: 'attached_to',
};

/** Relación con el otro extremo y cómo se lee desde este asset. */
interface Link {
  label: string;
  peer: AssetSummary;
}

/**
 * Pestaña «Resumen» de la ficha: lo que hace falta para trabajar con el asset de un vistazo
 * (sistema, red, servicios y puertos, qué contiene y de qué depende); los identificadores van
 * plegados al final.
 */
@Component({
  selector: 'app-asset-overview',
  imports: [
    DatePipe,
    RouterLink,
    ButtonModule,
    CardModule,
    PanelModule,
    TagModule,
    TooltipModule,
    AssetPolicyBlock,
    AssetNotes,
    AssetProjectsCard,
    AssetDomainsCard,
    DnsCheckCard,
    ServicePathCard,
    ServedDomainsCard,
    DomainServicePathsCard,
    AssetAccessCard,
    AdminAccessControl,
  ],
  templateUrl: './asset-overview.html',
  styleUrl: './asset-overview.scss',
})
export class AssetOverview {
  readonly asset = input.required<Asset>();
  readonly relations = input.required<AssetRelations>();
  readonly ancestors = input.required<AssetSummary[]>();
  /** Nodo del árbol del asset (dirección, estado de ejecución, findings e hijos). */
  readonly node = input<AssetTreeSummaryNode | null>(null);
  /** Volúmenes, redes e imágenes si es un host Docker (null si no lo es o no se pudo leer). */
  readonly docker = input<DockerHostResources | null>(null);
  /** Pide a la ficha que abra otra pestaña. */
  readonly openTab = output<string>();
  /**
   * La política de inventario, las notas o los proyectos cambiaron (la ficha se recarga: el
   * escaneo puede quedar activado o no).
   */
  readonly policyChanged = output<void>();

  private readonly auth = inject(AuthService);
  /** «Acceso a la terminal»: solo admins, en lo que admite terminal y no está retirado. */
  protected readonly showAccess = computed(
    () =>
      this.auth.can('users.manage') &&
      (TERMINAL_ASSET_TYPES as readonly string[]).includes(this.asset().type) &&
      this.asset().status !== 'retired',
  );

  protected readonly typeLabels: Readonly<Record<string, string>> = ASSET_TYPE_LABELS;
  protected readonly typeIcons: Readonly<Record<string, string>> = ASSET_TYPE_ICONS;
  protected readonly statusLabels: Readonly<Record<string, string>> = ASSET_STATUS_LABELS;
  protected readonly statusSeverity: Readonly<Record<string, TagSeverity>> =
    ASSET_STATUS_SEVERITY;
  protected readonly runtimeLabels: Readonly<Record<string, string>> = RUNTIME_LABELS;
  protected readonly runtimeSeverity: Readonly<Record<string, TagSeverity>> =
    RUNTIME_SEVERITY;
  protected readonly severityTag: Readonly<Record<string, TagSeverity>> = SEVERITY_TAG;
  protected readonly fixableLabel = fixableLabel;
  private readonly expiry = inject(ExpiryThresholds);
  /** Tipos a los que pueden apuntar registros DNS (A/AAAA a sus IPs). */
  protected readonly hasDomains = computed(() =>
    ['server', 'vm', 'lxc'].includes(this.asset().type),
  );
  /** Tipos que pueden servir un nombre o estar en su camino (QoL-5b). */
  protected readonly canServe = computed(() =>
    ['server', 'vm', 'lxc', 'container', 'database'].includes(this.asset().type),
  );

  private readonly facts = computed(() => this.asset().facts ?? {});
  protected readonly hasFacts = computed(() => Object.keys(this.facts()).length > 0);
  protected readonly system = computed(() => systemItems(this.facts()));
  protected readonly network = computed(() => [
    ...networkItems(this.facts()),
    ...collectionItems(this.facts()),
  ]);
  private readonly type = computed(() => this.asset().type);
  // `facts.docker` es de un contenedor, un volumen o una red según el tipo.
  protected readonly container = computed(() =>
    this.type() === 'container' ? containerItems(this.facts()) : [],
  );
  protected readonly mounts = computed(() =>
    this.type() === 'container' ? containerMounts(this.facts()) : [],
  );
  protected readonly containerNetworks = computed(() =>
    this.type() === 'container' ? containerNetworks(this.facts()) : [],
  );
  protected readonly volume = computed(() =>
    this.type() === 'volume' ? volumeItems(this.facts()) : [],
  );
  protected readonly dockerNetwork = computed(() =>
    this.type() === 'network' ? dockerNetworkItems(this.facts()) : [],
  );
  protected readonly plesk = computed(() => pleskItems(this.facts()));
  protected readonly certificate = computed(() => certificateItems(this.facts()));
  protected readonly connector = computed(() =>
    this.type() === 'dns_provider' ? connectorItems(this.facts()) : [],
  );
  protected readonly zone = computed(() =>
    this.type() === 'domain' ? zoneItems(this.facts()) : [],
  );
  protected readonly dnsRecord = computed(() =>
    this.type() === 'dns_record' ? dnsRecordItems(this.facts()) : [],
  );
  protected readonly image = computed(() => imageItems(this.facts()));
  /**
   * Imágenes, volúmenes y redes: cuántos contenedores activos lo usan (0 = «sin uso»); null en
   * el resto de tipos.
   */
  protected readonly usage = computed<number | null>(() => {
    const relation = USAGE_RELATION[this.type()];
    if (!relation) return null;
    return new Set(
      this.relations()
        .incoming.filter(
          (r) =>
            r.type === relation &&
            r.peer.type === 'container' &&
            r.peer.status === 'active',
        )
        .map((r) => r.peer.id),
    ).size;
  });
  protected readonly dockerTotal = computed(() => {
    const d = this.docker();
    return d ? d.volumes.length + d.networks.length + d.images.length : 0;
  });
  protected readonly services = computed(() => runningServices(factsServices(this.facts())));
  protected readonly ports = computed(() => listeningPorts(factsPorts(this.facts())));
  /** Los primeros puertos (expuestos antes que locales); el resto, en la pestaña «Puertos». */
  protected readonly topPorts = computed(() => this.ports().slice(0, MAX_SUMMARY_PORTS));
  /** Puertos de la pestaña (filas sin agrupar, como su contador). */
  protected readonly portCount = computed(() => factsPorts(this.facts()).length);

  /** Resumen del propio asset con sus findings. */
  protected readonly row = computed<InventoryRow | null>(() => {
    const node = this.node();
    return node ? toRow(node, this.expiry.days()) : null;
  });
  protected readonly children = computed(() =>
    (this.node()?.children ?? []).map((n) => toRow(n, this.expiry.days())),
  );

  /**
   * Lo que cabe en «Contiene» (un dominio con decenas de registros y certificados ahogaría el
   * Resumen): primero lo que pide atención; el resto, en Relaciones › Jerarquía.
   */
  protected readonly shownChildren = computed(() =>
    [...this.children()]
      .sort((a, b) => attentionRank(a) - attentionRank(b))
      .slice(0, MAX_SUMMARY_CHILDREN),
  );

  constructor() {
    this.expiry.load();
  }

  /** De qué depende: padre (contains), imagen (instance_of) y el resto de relaciones salientes. */
  protected readonly dependsOn = computed<Link[]>(() => {
    const rel = this.relations();
    const parent = this.ancestors().at(-1);
    const links: Link[] = parent ? [{ label: 'Dentro de', peer: parent }] : [];
    for (const r of rel.outgoing.filter((r) => r.type !== 'contains'))
      links.push({ label: outgoingLabel(r), peer: r.peer });
    return links;
  });

  /** Quién depende de él (sin el padre `contains`, que ya está arriba). */
  protected readonly usedBy = computed<Link[]>(() =>
    this.relations()
      .incoming.filter((r) => r.type !== 'contains')
      .map((r) => ({ label: RELATION_INCOMING_LABELS[r.type], peer: r.peer })),
  );

  protected readonly credentialRefs = computed(() =>
    Object.entries(this.asset().credentials ?? {}).filter(
      (e): e is [string, string] => typeof e[1] === 'string',
    ),
  );
}

function outgoingLabel(r: AssetRelationWithPeer): string {
  return r.type === 'instance_of' ? 'Imagen' : `${RELATION_LABELS[r.type][0].toUpperCase()}${RELATION_LABELS[r.type].slice(1)}`;
}
