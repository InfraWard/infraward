import type { DomainProviderKind } from '@infraward/shared-types';
import type { Discoverer } from './discoverer.js';
import { CloudflareProvider } from './domains/cloudflare.js';
import type { DomainProvider } from './domains/domain-provider.js';
import { DockerDiscoverer } from './docker/docker.js';
import { PleskDiscoverer } from './plesk/plesk.js';
import { PodmanDiscoverer } from './podman/podman.js';
import { ProxmoxDiscoverer } from './proxmox/proxmox.js';

export * from './alerts/webhook-target.js';
export * from './discoverer.js';
export * from './docker/docker.js';
export * from './domains/cloudflare.js';
export * from './domains/domain-provider.js';
export * from './domains/link.js';
export * from './domains/listing.js';
export * from './domains/rdap.js';
export * from './domains/tls-probe.js';
export * from './plesk/certificate.js';
export * from './plesk/plesk.js';
export * from './plesk/queries.js';
export * from './podman/podman.js';
export * from './privileged.js';
export * from './processes/process-packages.js';
export * from './sshd/sshd-auth.js';
export * from './proxies/labels.js';
export * from './proxies/nginx-filter.js';
export * from './proxmox/proxmox.js';
export * from './reconcile.js';
export * from './services/resolve.js';

/** Descubridores disponibles, por el rol que los activa (DESIGN §8). */
export function createDiscoverers(): ReadonlyMap<string, Discoverer> {
  const all: Discoverer[] = [
    new ProxmoxDiscoverer(),
    new DockerDiscoverer(),
    new PodmanDiscoverer(),
    new PleskDiscoverer(),
  ];
  return new Map(all.map((d) => [d.role, d]));
}

/** Conectores de dominios disponibles, por proveedor (DESIGN §13). */
export function createDomainProviders(): ReadonlyMap<
  DomainProviderKind,
  DomainProvider
> {
  const all: DomainProvider[] = [new CloudflareProvider()];
  return new Map(all.map((p) => [p.kind, p]));
}
