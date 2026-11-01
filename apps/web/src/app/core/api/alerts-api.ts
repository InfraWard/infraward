import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  AlertChannel,
  AlertsStatus,
  AlertTestResult,
  CreateAlertChannelRequest,
  UpdateAlertChannelRequest,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/** Canales de alertas fuera de la app (solo admins). */
@Injectable({ providedIn: 'root' })
export class AlertsApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  status(): Observable<AlertsStatus> {
    return this.http.get<AlertsStatus>(`${this.api}/alerts/status`);
  }

  channels(): Observable<AlertChannel[]> {
    return this.http.get<AlertChannel[]>(`${this.api}/alerts/channels`);
  }

  create(body: CreateAlertChannelRequest): Observable<AlertChannel> {
    return this.http.post<AlertChannel>(`${this.api}/alerts/channels`, body);
  }

  update(id: string, body: UpdateAlertChannelRequest): Observable<AlertChannel> {
    return this.http.patch<AlertChannel>(
      `${this.api}/alerts/channels/${encodeURIComponent(id)}`,
      body,
    );
  }

  remove(id: string): Observable<void> {
    return this.http.delete<void>(`${this.api}/alerts/channels/${encodeURIComponent(id)}`);
  }

  test(id: string): Observable<AlertTestResult> {
    return this.http.post<AlertTestResult>(
      `${this.api}/alerts/channels/${encodeURIComponent(id)}/test`,
      {},
    );
  }
}
