import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  AssetFindingsPage,
  AssetVulnerabilitiesPage,
  FindingListQuery,
  FindingSearchResult,
  EnqueueJobResponse,
  IntelStatus,
  NewVulnerabilitiesPage,
  Page,
  VulnerabilitiesPage,
  RescanAffectedResponse,
  SearchSuggestions,
  VulnerabilityDetail,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';
import { toParams } from './query-params';

@Injectable({ providedIn: 'root' })
export class FindingsApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  /** Findings de un asset (un contenedor ve los de su imagen) y el estado del escaneo. */
  assetFindings(
    assetId: string,
    query: FindingListQuery,
  ): Observable<AssetFindingsPage> {
    return this.http.get<AssetFindingsPage>(
      `${this.api}/assets/${encodeURIComponent(assetId)}/findings`,
      { params: toParams(query) },
    );
  }

  /** Lo mismo agrupado por CVE: una fila por vulnerabilidad con sus paquetes. */
  assetVulnerabilities(
    assetId: string,
    query: FindingListQuery,
  ): Observable<AssetVulnerabilitiesPage> {
    return this.http.get<AssetVulnerabilitiesPage>(
      `${this.api}/assets/${encodeURIComponent(assetId)}/vulnerabilities`,
      { params: toParams(query) },
    );
  }

  /** Vulnerabilidades del inventario: una fila por CVE con imágenes y contenedores afectados. */
  vulnerabilities(query: FindingListQuery): Observable<VulnerabilitiesPage> {
    return this.http.get<VulnerabilitiesPage>(`${this.api}/vulnerabilities`, {
      params: toParams(query),
    });
  }

  /** Findings del inventario con los assets a los que afectan. */
  search(query: FindingListQuery): Observable<Page<FindingSearchResult>> {
    return this.http.get<Page<FindingSearchResult>>(`${this.api}/findings`, {
      params: toParams(query),
    });
  }

  /** Un CVE: detalles de la BD de Trivy y árbol de afectados. */
  detail(id: string): Observable<VulnerabilityDetail> {
    return this.http.get<VulnerabilityDetail>(
      `${this.api}/vulnerabilities/${encodeURIComponent(id)}`,
    );
  }

  /** Re-escanea (con `force`) los afectados por un CVE (admin). */
  rescan(id: string): Observable<RescanAffectedResponse> {
    return this.http.post<RescanAffectedResponse>(
      `${this.api}/vulnerabilities/${encodeURIComponent(id)}/rescan`,
      {},
    );
  }

  /** Sugerencias de la barra de búsqueda global (CVE y paquetes). */
  suggest(q: string): Observable<SearchSuggestions> {
    return this.http.get<SearchSuggestions>(`${this.api}/search/suggest`, {
      params: { q },
    });
  }

  /** CVE abiertos desde el último «Marcar como vistos» del usuario. */
  newSince(): Observable<NewVulnerabilitiesPage> {
    return this.http.get<NewVulnerabilitiesPage>(
      `${this.api}/vulnerabilities/new`,
    );
  }

  markSeen(): Observable<{ since: string }> {
    return this.http.post<{ since: string }>(
      `${this.api}/vulnerabilities/new/seen`,
      {},
    );
  }

  /** Estado de CISA KEV y EPSS: antigüedad de los datos y último fallo. */
  intelStatus(): Observable<IntelStatus> {
    return this.http.get<IntelStatus>(`${this.api}/vulnerabilities/intel`);
  }

  /**
   * Re-evalúa ya todos los SBOMs con la BD de Trivy (`assets.operate`); con `downloadDb`, el
   * worker descarga antes la BD aunque no haya caducado.
   */
  reevaluateSboms(downloadDb: boolean): Observable<EnqueueJobResponse> {
    return this.http.post<EnqueueJobResponse>(`${this.api}/sboms/reevaluate`, {
      downloadDb,
    });
  }

  /** Descarga KEV y EPSS ahora (`assets.operate`). */
  refreshIntel(): Observable<EnqueueJobResponse> {
    return this.http.post<EnqueueJobResponse>(
      `${this.api}/vulnerabilities/intel/refresh`,
      {},
    );
  }
}
