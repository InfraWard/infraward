import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  AcceptDnsTargetResponse,
  AssetDomains,
  Connector,
  ConnectorTestResponse,
  CreateConnectorRequest,
  DeleteAssetResponse,
  DnsRecordCheck,
  DomainServicePaths,
  EnqueueJobResponse,
  ExpiryWarningSettings,
  NatForward,
  NatForwardInput,
  ServedDomains,
  ServicePathView,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/**
 * Inventario de dominios (DESIGN §13): conectores, dominios que llegan a un asset, comprobación
 * de registros DNS y umbrales de caducidad. El token solo viaja al crear o reemplazar; la API
 * nunca lo devuelve.
 */
@Injectable({ providedIn: 'root' })
export class DomainsApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  connectors(): Observable<Connector[]> {
    return this.http.get<Connector[]>(`${this.api}/connectors`);
  }

  createConnector(body: CreateConnectorRequest): Observable<Connector> {
    return this.http.post<Connector>(`${this.api}/connectors`, body);
  }

  replaceToken(id: string, apiToken: string): Observable<Connector> {
    return this.http.put<Connector>(`${this.api}/connectors/${id}/token`, {
      apiToken,
    });
  }

  testConnector(id: string): Observable<ConnectorTestResponse> {
    return this.http.post<ConnectorTestResponse>(
      `${this.api}/connectors/${id}/test`,
      {},
    );
  }

  syncConnector(id: string): Observable<EnqueueJobResponse> {
    return this.http.post<EnqueueJobResponse>(
      `${this.api}/connectors/${id}/sync`,
      {},
    );
  }

  deleteConnector(id: string): Observable<DeleteAssetResponse> {
    return this.http.delete<DeleteAssetResponse>(
      `${this.api}/connectors/${id}`,
    );
  }

  domainsOf(assetId: string): Observable<AssetDomains> {
    return this.http.get<AssetDomains>(`${this.api}/assets/${assetId}/domains`);
  }

  dnsCheck(assetId: string): Observable<DnsRecordCheck | null> {
    return this.http.get<DnsRecordCheck | null>(
      `${this.api}/assets/${assetId}/dns-check`,
    );
  }

  acceptDnsCheck(assetId: string): Observable<DnsRecordCheck> {
    return this.http.post<DnsRecordCheck>(
      `${this.api}/assets/${assetId}/dns-check/acceptance`,
      {},
    );
  }

  reopenDnsCheck(assetId: string): Observable<DnsRecordCheck> {
    return this.http.delete<DnsRecordCheck>(
      `${this.api}/assets/${assetId}/dns-check/acceptance`,
    );
  }

  /** Todos los avisos informativos con ese destino (p. ej. la IP pública de casa). */
  acceptDnsTarget(target: string): Observable<AcceptDnsTargetResponse> {
    return this.http.post<AcceptDnsTargetResponse>(
      `${this.api}/dns-checks/acceptance`,
      { target },
    );
  }

  expiryWarnings(): Observable<ExpiryWarningSettings> {
    return this.http.get<ExpiryWarningSettings>(
      `${this.api}/settings/expiry-warnings`,
    );
  }

  setExpiryWarnings(days: number[]): Observable<ExpiryWarningSettings> {
    return this.http.put<ExpiryWarningSettings>(
      `${this.api}/settings/expiry-warnings`,
      { days },
    );
  }

  /** Camino de un registro DNS hasta el asset que lo sirve (QoL-5b). */
  servicePath(recordId: string): Observable<ServicePathView> {
    return this.http.get<ServicePathView>(
      `${this.api}/assets/${recordId}/service-path`,
    );
  }

  servicePaths(domainId: string): Observable<DomainServicePaths> {
    return this.http.get<DomainServicePaths>(
      `${this.api}/assets/${domainId}/service-paths`,
    );
  }

  servedDomains(assetId: string): Observable<ServedDomains> {
    return this.http.get<ServedDomains>(
      `${this.api}/assets/${assetId}/served-domains`,
    );
  }

  pinServicePath(recordId: string, targetAssetId: string): Observable<ServicePathView> {
    return this.http.post<ServicePathView>(
      `${this.api}/assets/${recordId}/service-path/pin`,
      { targetAssetId },
    );
  }

  unpinServicePath(recordId: string): Observable<ServicePathView> {
    return this.http.delete<ServicePathView>(
      `${this.api}/assets/${recordId}/service-path/pin`,
    );
  }

  natForwards(): Observable<NatForward[]> {
    return this.http.get<NatForward[]>(`${this.api}/settings/nat-forwards`);
  }

  createNatForward(body: NatForwardInput): Observable<NatForward> {
    return this.http.post<NatForward>(`${this.api}/settings/nat-forwards`, body);
  }

  updateNatForward(id: string, body: NatForwardInput): Observable<NatForward> {
    return this.http.put<NatForward>(
      `${this.api}/settings/nat-forwards/${id}`,
      body,
    );
  }

  deleteNatForward(id: string): Observable<void> {
    return this.http.delete<void>(`${this.api}/settings/nat-forwards/${id}`);
  }
}
