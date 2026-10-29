import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  ConfirmManualEnrollmentRequest,
  EnrollServerRequest,
  EnrollServerResponse,
  Enrollment,
  AdminAccessRequest,
  IssuedEnrollment,
  SshAuthMode,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/** Alta de servidores (DESIGN §7). Las escrituras requieren rol admin. */
@Injectable({ providedIn: 'root' })
export class EnrollmentApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  enroll(request: EnrollServerRequest): Observable<EnrollServerResponse> {
    return this.http.post<EnrollServerResponse>(
      `${this.api}/assets/enroll`,
      request,
    );
  }

  latest(assetId: string): Observable<Enrollment> {
    return this.http.get<Enrollment>(
      `${this.api}/assets/${enc(assetId)}/enrollment`,
    );
  }

  /**
   * Comando nuevo (invalida el anterior) o, con el asset activo, actualización del sudoers. Con
   * `authMode: 'ca_certificate'` sobre un servidor con clave estática, migración a CA. Con
   * `adminAccess`, el script instala (`operator`) o retira (`none`) el acceso de administración.
   */
  issueToken(
    assetId: string,
    installSudo: boolean,
    authMode?: SshAuthMode,
    adminAccess?: AdminAccessRequest,
  ): Observable<IssuedEnrollment> {
    return this.http.post<IssuedEnrollment>(
      `${this.api}/assets/${enc(assetId)}/enrollment/token`,
      {
        installSudo,
        ...(authMode && { authMode }),
        ...(adminAccess && { adminAccess }),
      },
    );
  }

  confirm(
    assetId: string,
    request: ConfirmManualEnrollmentRequest,
  ): Observable<Enrollment> {
    return this.http.post<Enrollment>(
      `${this.api}/assets/${enc(assetId)}/enrollment/confirm`,
      request,
    );
  }

  retry(assetId: string): Observable<Enrollment> {
    return this.http.post<Enrollment>(
      `${this.api}/assets/${enc(assetId)}/enrollment/verify`,
      {},
    );
  }

  /** Ruta del flujo SSE de progreso (para `SseClient`). */
  eventsPath(assetId: string): string {
    return `/assets/${enc(assetId)}/enrollment/events`;
  }
}

const enc = encodeURIComponent;
