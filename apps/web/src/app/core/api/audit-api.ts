import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type { AuditPage, AuditQuery } from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/** Registro de auditoría (solo admin), por cursor. */
@Injectable({ providedIn: 'root' })
export class AuditApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  list(query: AuditQuery): Observable<AuditPage> {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') continue;
      if (Array.isArray(value)) {
        if (value.length) params = params.set(key, value.join(','));
      } else params = params.set(key, String(value));
    }
    return this.http.get<AuditPage>(`${this.api}/audit`, { params });
  }
}
