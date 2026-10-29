import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  ApiTokenSummary,
  CreateApiTokenRequest,
  CreatedApiTokenResponse,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/** Tokens de API: los propios (cualquiera) y los de todos (users.manage). */
@Injectable({ providedIn: 'root' })
export class ApiTokensApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  mine(): Observable<ApiTokenSummary[]> {
    return this.http.get<ApiTokenSummary[]>(`${this.api}/auth/tokens`);
  }

  /** El token en claro solo viene en esta respuesta. */
  create(body: CreateApiTokenRequest): Observable<CreatedApiTokenResponse> {
    return this.http.post<CreatedApiTokenResponse>(`${this.api}/auth/tokens`, body);
  }

  revokeMine(id: string): Observable<ApiTokenSummary> {
    return this.http.delete<ApiTokenSummary>(`${this.api}/auth/tokens/${encodeURIComponent(id)}`);
  }

  all(): Observable<ApiTokenSummary[]> {
    return this.http.get<ApiTokenSummary[]>(`${this.api}/api-tokens`);
  }

  revoke(id: string): Observable<ApiTokenSummary> {
    return this.http.delete<ApiTokenSummary>(`${this.api}/api-tokens/${encodeURIComponent(id)}`);
  }
}
