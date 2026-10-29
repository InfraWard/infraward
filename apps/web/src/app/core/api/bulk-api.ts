import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  BulkAssetIds,
  BulkAssetTarget,
  BulkOperationResult,
  BulkPolicyRequest,
  BulkPreviewResponse,
  BulkProjectRequest,
  BulkTagsRequest,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/** Operaciones en lote sobre varios assets (QoL-6; cada una con el permiso de su acción). */
@Injectable({ providedIn: 'root' })
export class BulkApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  preview(target: BulkAssetTarget): Observable<BulkPreviewResponse> {
    return this.http.post<BulkPreviewResponse>(`${this.api}/assets/bulk/preview`, target);
  }

  tags(body: BulkTagsRequest): Observable<BulkOperationResult> {
    return this.post('tags', body);
  }

  project(body: BulkProjectRequest): Observable<BulkOperationResult> {
    return this.post('project', body);
  }

  policy(body: BulkPolicyRequest): Observable<BulkOperationResult> {
    return this.post('policy', body);
  }

  collect(target: BulkAssetTarget): Observable<BulkOperationResult> {
    return this.post('collect', target);
  }

  scan(target: BulkAssetTarget): Observable<BulkOperationResult> {
    return this.post('scan', target);
  }

  retire(target: BulkAssetIds): Observable<BulkOperationResult> {
    return this.post('retire', target);
  }

  private post(path: string, body: object): Observable<BulkOperationResult> {
    return this.http.post<BulkOperationResult>(`${this.api}/assets/bulk/${path}`, body);
  }
}
