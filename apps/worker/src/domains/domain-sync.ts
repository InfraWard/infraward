import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  buildDomainListing,
  createDomainProviders,
  DiscoveryError,
  DOMAIN_CHILD_TYPES,
  DOMAIN_LINK_TYPES,
  DomainApiError,
  externalCnameTargets,
  mapLimit,
  probeTls,
  RdapClient,
  tlsCandidates,
  x509Facts,
  zoneKey,
  type CnameLookup,
  type DomainProvider,
  type ProviderListing,
  type TlsObservation,
} from '@infraward/connectors';
import { Asset } from '@infraward/domain';
import { SecretError, SecretsService } from '@infraward/secrets';
import {
  type ConnectorFacts,
  type ConnectorVerification,
  type DomainProviderKind,
  type DomainsSyncJobData,
  type DomainsSyncJobResult,
  type DomainsTestJobData,
  type RegistrationFacts,
} from '@infraward/shared-types';
import type { Job } from 'bullmq';
import { DataSource } from 'typeorm';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { ListingReconciler } from '../inventory/listing-reconciler.js';
import { reportProgress } from '../jobs/progress.js';
import { dnsServers, DomainResolver } from './dns-resolver.js';
import { BearerApi, getJson } from './domain-http.js';
import { DomainLinker } from './domain-linker.js';
import { ServiceLinker } from './service-linker.js';

/** Un dominio se consulta por RDAP como mucho una vez en este tiempo. */
const RDAP_REFRESH_MS = 24 * 3_600_000;
/** Tope de nombres cuyo 443 se lee en una sincronización. */
const TLS_MAX_NAMES = 1000;

/**
 * Conectores de dominios en el worker (DESIGN §13). El token se resuelve con `SecretsService` al
 * empezar el job, vive en el `BearerApi` mientras dura y se descarta; nunca va en los datos del
 * job, en los facts, en los errores ni en los logs.
 */
@Injectable()
export class DomainSync {
  private readonly logger = new Logger(DomainSync.name);
  private readonly providers = createDomainProviders();
  private readonly rdap: RdapClient;
  private readonly resolver: DomainResolver;

  constructor(
    private readonly config: ConfigService<EnvironmentVariables, true>,
    @InjectDataSource() private readonly db: DataSource,
    private readonly secrets: SecretsService,
    private readonly listings: ListingReconciler,
    private readonly linker: DomainLinker,
    private readonly services: ServiceLinker,
  ) {
    const timeout = this.config.get('DOMAINS_HTTP_TIMEOUT_MS', { infer: true });
    this.rdap = new RdapClient(
      (url) => getJson(url, {}, timeout),
      this.config.get('RDAP_BOOTSTRAP_URL', { infer: true }),
    );
    this.resolver = new DomainResolver(
      dnsServers(this.config.get('DOMAINS_DNS_SERVERS', { infer: true })),
      this.config.get('DOMAINS_TLS_TIMEOUT_MS', { infer: true }),
    );
  }

  /** `domains.test`: prueba el token y guarda el resultado en el conector. */
  async test(job: Job<DomainsTestJobData>): Promise<ConnectorVerification> {
    const asset = await this.connector(job.data.assetId);
    const facts = connectorFacts(asset);
    const provider = this.provider(facts.kind);
    let result: ConnectorVerification;
    try {
      const api = await this.api(asset, facts.kind);
      result = { ...(await provider.verify(api)), checkedAt: new Date().toISOString() };
    } catch (error) {
      result = {
        ok: false,
        checkedAt: new Date().toISOString(),
        error: errorMessage(error),
        tokenStatus: null,
        tokenExpiresAt: null,
        accounts: [],
        zones: 0,
        warnings: [],
      };
    }
    await this.saveConnector(asset.id, { verify: result });
    await reportProgress(
      job,
      100,
      result.ok
        ? `Token válido: ${result.zones} zonas`
        : `Token no válido: ${result.error}`,
    );
    return result;
  }

  /** `domains.sync`: zonas, registros, RDAP, 443, reconciliación y enlaces. */
  async sync(job: Job<DomainsSyncJobData>): Promise<DomainsSyncJobResult> {
    const asset = await this.connector(job.data.assetId);
    const facts = connectorFacts(asset);
    const provider = this.provider(facts.kind);
    const api = await this.api(asset, facts.kind);

    await reportProgress(job, 5, 'Leyendo zonas y registros');
    let listing: ProviderListing;
    try {
      listing = await provider.list(api);
    } catch (error) {
      throw new DiscoveryError(`No se pudo listar los dominios: ${errorMessage(error)}`);
    }
    listing = await this.withoutForeignZones(asset.id, facts.kind, listing);

    await reportProgress(job, 25, `Caducidad de ${listing.zones.length} dominios (RDAP)`);
    const registrations = await this.registrations(facts.kind, listing);

    const names = tlsCandidates(listing.records).slice(0, TLS_MAX_NAMES);
    await reportProgress(job, 45, `Certificados de ${names.length} nombres (443)`);
    const { tls, complete: tlsComplete } = await this.probe(names);
    const known = await this.knownCertificates(tls);

    const now = new Date().toISOString();
    const built = buildDomainListing({
      kind: facts.kind,
      listing,
      registrations,
      tls,
      tlsComplete,
      knownCertificates: known,
      now,
    });
    await reportProgress(job, 70, 'Actualizando el inventario');
    const applied = await this.listings.apply(
      { id: asset.id, name: asset.name },
      {
        childTypes: DOMAIN_CHILD_TYPES,
        linkTypes: DOMAIN_LINK_TYPES,
        externalTargets: true,
      },
      built,
      job.id ?? null,
    );

    await reportProgress(job, 85, 'Enlazando registros y buscando colgantes');
    const zones = await this.inventoriedZones();
    const targets = externalCnameTargets(listing.records, zones);
    const lookups = await mapLimit(
      targets,
      this.config.get('DOMAINS_CONCURRENCY', { infer: true }),
      (t) => this.resolver.cname(t).catch((): CnameLookup => 'error'),
    );
    const linked = await this.linker.link(
      new Map(targets.map((t, i) => [t, lookups[i]])),
    );

    // Túneles de Cloudflare (permiso opcional) y caminos de los registros hasta su servicio.
    if (provider.tunnels) {
      await reportProgress(job, 90, 'Túneles y servicios que sirven cada nombre');
      const accounts = listing.zones
        .map((z) => z.account?.id)
        .filter((a): a is string => !!a);
      const tunnels = await provider.tunnels(api, accounts).catch((error: unknown) => ({
        items: [],
        complete: false,
        error: errorMessage(error),
      }));
      await this.saveConnector(asset.id, { tunnels: { at: now, ...tunnels } });
    }
    const served = await this.services.link();

    const warnings = [...applied.warnings, ...built.warnings];
    await this.saveConnector(asset.id, {
      lastSync: {
        at: now,
        zones: listing.zones.length,
        records: listing.records.length,
        complete: built.complete,
        warnings: warnings.slice(0, 20),
      },
    });
    const result: DomainsSyncJobResult = {
      assetId: asset.id,
      zones: listing.zones.length,
      records: listing.records.length,
      certificates: built.children.filter((c) => c.type === 'certificate').length,
      created: applied.counts.created,
      updated: applied.counts.updated,
      missing: applied.counts.missing,
      reactivated: applied.counts.reactivated,
      retired: applied.counts.retired,
      links: linked.links,
      dangling: linked.dangling,
      complete: built.complete,
      services: { complete: served.complete, partial: served.partial },
      warnings,
    };
    await reportProgress(
      job,
      100,
      `Sincronización completada: ${result.zones} dominios, ${result.records} registros, ${result.created} nuevos, ${result.missing} desaparecidos, ${result.dangling} colgantes`,
    );
    this.logger.log(
      `Conector ${asset.name}: ${result.zones} zonas, ${result.records} registros, ${result.certificates} certificados, ${result.links} enlaces, ${result.dangling} colgantes${built.complete ? '' : ' (incompleto)'}`,
    );
    return result;
  }

  private async connector(assetId: string): Promise<Asset> {
    const asset = await this.db.getRepository(Asset).findOne({ where: { id: assetId } });
    if (asset?.type !== 'dns_provider')
      throw new DiscoveryError('El conector no existe');
    if (asset.status !== 'active') throw new DiscoveryError('El conector no está activo');
    return asset;
  }

  private provider(kind: DomainProviderKind): DomainProvider {
    const provider = this.providers.get(kind);
    if (!provider) throw new DiscoveryError(`Proveedor de dominios desconocido: ${kind}`);
    return provider;
  }

  private async api(asset: Asset, kind: DomainProviderKind): Promise<BearerApi> {
    const ref = asset.credentials?.apiToken;
    if (!ref) throw new DiscoveryError('El conector no tiene token');
    const token = await this.secrets.resolve(ref, { fresh: true });
    // URL de la API de cada proveedor (configurable: los e2e la apuntan a un simulado).
    const urls: Record<DomainProviderKind, string> = {
      cloudflare: this.config.get('CLOUDFLARE_API_URL', { infer: true }),
    };
    const base = urls[kind];
    return new BearerApi(
      base,
      token,
      this.config.get('DOMAINS_HTTP_TIMEOUT_MS', { infer: true }),
    );
  }

  /**
   * Zonas que ya son de otro conector activo (dos tokens de la misma cuenta): se dejan fuera
   * para que no salten de uno a otro en cada sincronización.
   */
  private async withoutForeignZones(
    providerId: string,
    kind: DomainProviderKind,
    listing: ProviderListing,
  ): Promise<ProviderListing> {
    if (listing.zones.length === 0) return listing;
    const foreign: { natural_key: string }[] = await this.db.query(
      `SELECT a.natural_key FROM assets a
         JOIN asset_relations r ON r.child_id = a.id AND r.type = 'contains'
         JOIN assets p ON p.id = r.parent_id
        WHERE a.type = 'domain' AND a.status <> 'retired' AND a.natural_key = ANY($1::text[])
          AND p.type = 'dns_provider' AND p.status = 'active' AND p.id <> $2`,
      [listing.zones.map((z) => zoneKey(kind, z.id)), providerId],
    );
    if (foreign.length === 0) return listing;
    const skip = new Set(foreign.map((f) => f.natural_key));
    const zones = listing.zones.filter((z) => !skip.has(zoneKey(kind, z.id)));
    const kept = new Set(zones.map((z) => z.id));
    return {
      zones,
      records: listing.records.filter((r) => kept.has(r.zoneId)),
      complete: listing.complete,
      warnings: [
        ...listing.warnings,
        ...listing.zones
          .filter((z) => !kept.has(z.id))
          .map((z) => `${z.name}: ya está en otro conector; se omite`),
      ],
    };
  }

  /** RDAP de cada zona, como mucho una vez al día (si no, el resultado anterior). */
  private async registrations(
    kind: DomainProviderKind,
    listing: ProviderListing,
  ): Promise<Map<string, RegistrationFacts>> {
    const rows: { natural_key: string; registration: RegistrationFacts | null }[] =
      await this.db.query(
        `SELECT natural_key, facts->'registration' AS registration FROM assets
          WHERE type = 'domain' AND natural_key = ANY($1::text[])`,
        [listing.zones.map((z) => zoneKey(kind, z.id))],
      );
    const previous = new Map(rows.map((r) => [r.natural_key, r.registration]));
    const out = new Map<string, RegistrationFacts>();
    for (const z of listing.zones) {
      const last = previous.get(zoneKey(kind, z.id));
      if (
        last &&
        last.state !== 'error' &&
        Date.now() - Date.parse(last.checkedAt) < RDAP_REFRESH_MS
      ) {
        out.set(z.name, last);
        continue;
      }
      const result = await this.rdap.lookup(z.name);
      out.set(z.name, { ...result, checkedAt: new Date().toISOString() });
    }
    return out;
  }

  /** Certificados del 443 de cada nombre. `complete` = se leyeron todos. */
  private async probe(
    names: string[],
  ): Promise<{ tls: Map<string, TlsObservation>; complete: boolean }> {
    const port = this.config.get('DOMAINS_TLS_PORT', { infer: true });
    const timeoutMs = this.config.get('DOMAINS_TLS_TIMEOUT_MS', { infer: true });
    const lookup = this.resolver.custom ? this.resolver.lookup() : undefined;
    const results = await mapLimit(
      names,
      this.config.get('DOMAINS_CONCURRENCY', { infer: true }),
      (name) => probeTls(name, { port, timeoutMs, ...(lookup ? { lookup } : {}) }),
    );
    const tls = new Map<string, TlsObservation>();
    const checkedAt = new Date().toISOString();
    let complete = true;
    names.forEach((name, i) => {
      const r = results[i];
      if (!r.ok) {
        complete = false;
        tls.set(name, {
          facts: {
            status: 'error',
            error: r.error,
            authorized: null,
            authorizationError: null,
            hostnameMatch: null,
            fingerprint256: null,
            checkedAt,
          },
          certificate: null,
        });
        return;
      }
      const parsed = x509Facts(r.certificate);
      const fingerprint256 = parsed.fingerprint256 ?? r.certificate.fingerprint256;
      tls.set(name, {
        facts: {
          status: 'ok',
          error: null,
          authorized: r.authorized,
          authorizationError: r.authorizationError,
          hostnameMatch: r.hostnameMatch,
          fingerprint256,
          checkedAt,
        },
        certificate: { ...parsed, fingerprint256 },
      });
    });
    return { tls, complete };
  }

  /** Huella → clave natural de los certificados que ya existen y no son del 443 (Plesk). */
  private async knownCertificates(
    tls: ReadonlyMap<string, TlsObservation>,
  ): Promise<Map<string, string>> {
    const fps = [
      ...new Set(
        [...tls.values()]
          .map((t) => t.certificate?.fingerprint256)
          .filter((f): f is string => !!f),
      ),
    ];
    if (fps.length === 0) return new Map();
    const rows: { fp: string; natural_key: string }[] = await this.db.query(
      `SELECT facts->'certificate'->>'fingerprint256' AS fp, natural_key FROM assets
        WHERE type = 'certificate' AND status <> 'retired' AND natural_key NOT LIKE 'tls:%'
          AND facts->'certificate'->>'fingerprint256' = ANY($1::text[])`,
      [fps],
    );
    return new Map(rows.map((r) => [r.fp, r.natural_key]));
  }

  private async inventoriedZones(): Promise<string[]> {
    const rows: { name: string }[] = await this.db.query(
      `SELECT facts->'zone'->>'name' AS name FROM assets
        WHERE type = 'domain' AND status <> 'retired' AND facts ? 'zone'`,
    );
    return rows.map((r) => r.name).filter(Boolean);
  }

  /** Fusiona en `facts.connector` (sin tocar el resto). */
  private async saveConnector(
    assetId: string,
    patch: Partial<ConnectorFacts>,
  ): Promise<void> {
    await this.db.query(
      `UPDATE assets SET facts = jsonb_set(facts, '{connector}',
              COALESCE(facts->'connector', '{}'::jsonb) || $2::jsonb), updated_at = now()
        WHERE id = $1`,
      [assetId, JSON.stringify(patch)],
    );
  }
}

function connectorFacts(asset: Asset): ConnectorFacts {
  const facts = asset.facts?.connector as ConnectorFacts | undefined;
  if (!facts?.kind) throw new DiscoveryError('El conector no tiene proveedor');
  return facts;
}

/** Mensaje apto para mostrarse: los errores conocidos; nunca el de uno ajeno. */
function errorMessage(error: unknown): string {
  if (error instanceof DomainApiError || error instanceof DiscoveryError)
    return error.message;
  if (error instanceof SecretError)
    return `no se pudo leer el token del proveedor de secretos (${error.message})`;
  return 'error inesperado';
}
