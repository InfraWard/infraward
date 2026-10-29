import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  Asset,
  AssetGraph,
  AssetRelations,
  AssetSummary,
  AssetTreeSummaryNode,
  DeleteAssetResponse,
  DockerHostResources,
  EnqueueJobResponse,
  Page,
  ScanAssetResponse,
  Snapshot,
  SnapshotSummary,
  TopologyQuery,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';
import { toParams } from './query-params';

/** Inventario: lecturas y acciones sobre los assets (estas, solo admin). */
@Injectable({ providedIn: 'root' })
export class InventoryApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  tree(includeRetired = false): Observable<AssetTreeSummaryNode[]> {
    return this.http.get<AssetTreeSummaryNode[]>(`${this.api}/assets/tree`, {
      params: includeRetired ? { includeRetired: 'true' } : {},
    });
  }

  asset(id: string): Observable<Asset> {
    return this.http.get<Asset>(`${this.api}/assets/${enc(id)}`);
  }

  /** Subárbol resumido con raíz en el asset (dirección, estado de ejecución, findings e hijos). */
  subtree(id: string): Observable<AssetTreeSummaryNode> {
    return this.http.get<AssetTreeSummaryNode>(
      `${this.api}/assets/${enc(id)}/tree`,
    );
  }

  /** Antepasados `contains`, de la raíz al padre. */
  ancestors(id: string): Observable<AssetSummary[]> {
    return this.http.get<AssetSummary[]>(
      `${this.api}/assets/${enc(id)}/ancestors`,
    );
  }

  /** Volúmenes, redes e imágenes de un host Docker con su uso (listas vacías si no lo es). */
  dockerResources(id: string): Observable<DockerHostResources> {
    return this.http.get<DockerHostResources>(
      `${this.api}/assets/${enc(id)}/docker`,
    );
  }

  relations(id: string): Observable<AssetRelations> {
    return this.http.get<AssetRelations>(
      `${this.api}/assets/${enc(id)}/relations`,
    );
  }

  /** Mapa de relaciones centrado en el asset, hasta `depth` saltos. */
  graph(id: string, depth: number): Observable<AssetGraph> {
    return this.http.get<AssetGraph>(`${this.api}/assets/${enc(id)}/graph`, {
      params: { depth },
    });
  }

  /** Topología por niveles: nivel host más el contenido de `expand`. */
  topology(query: TopologyQuery): Observable<AssetGraph> {
    return this.http.get<AssetGraph>(`${this.api}/assets/topology`, {
      params: toParams({ ...query, expand: query.expand?.join(',') }),
    });
  }

  snapshots(
    id: string,
    page: { limit: number; offset: number },
  ): Observable<Page<SnapshotSummary>> {
    const params = new HttpParams()
      .set('limit', page.limit)
      .set('offset', page.offset);
    return this.http.get<Page<SnapshotSummary>>(
      `${this.api}/assets/${enc(id)}/snapshots`,
      { params },
    );
  }

  snapshot(id: string): Observable<Snapshot> {
    return this.http.get<Snapshot>(`${this.api}/snapshots/${enc(id)}`);
  }

  /** Vuelve a recoger el asset (y, si tiene descubridor, a descubrir sus hijos). */
  collect(id: string): Observable<EnqueueJobResponse> {
    return this.http.post<EnqueueJobResponse>(
      `${this.api}/assets/${enc(id)}/collect`,
      {},
    );
  }

  /** Escanea con Trivy sus imágenes; `force` re-analiza aunque ya estén escaneadas. */
  scan(id: string, force = true): Observable<ScanAssetResponse> {
    return this.http.post<ScanAssetResponse>(
      `${this.api}/assets/${enc(id)}/scan`,
      {},
      { params: force ? { force: 'true' } : {} },
    );
  }

  /** Baja (retira el subárbol) o, con `purge`, borrado físico. */
  remove(id: string, purge: boolean): Observable<DeleteAssetResponse> {
    return this.http.delete<DeleteAssetResponse>(
      `${this.api}/assets/${enc(id)}`,
      { params: purge ? { purge: 'true' } : {} },
    );
  }
}

const enc = encodeURIComponent;
