import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  MfaSetupResponse,
  MfaStatus,
  RecoveryCodesResponse,
  UserSummary,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/**
 * Verificación en dos pasos (TOTP) propia y, para un admin, el restablecimiento de la de otro.
 * El secreto y los códigos de recuperación llegan una sola vez: no se guardan aquí.
 */
@Injectable({ providedIn: 'root' })
export class MfaApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  status(): Observable<MfaStatus> {
    return this.http.get<MfaStatus>(`${this.api}/auth/mfa`);
  }

  setup(): Observable<MfaSetupResponse> {
    return this.http.post<MfaSetupResponse>(`${this.api}/auth/mfa/setup`, null);
  }

  enable(code: string): Observable<RecoveryCodesResponse> {
    return this.http.post<RecoveryCodesResponse>(`${this.api}/auth/mfa/enable`, { code });
  }

  disable(): Observable<void> {
    return this.http.post<void>(`${this.api}/auth/mfa/disable`, null);
  }

  regenerateRecoveryCodes(): Observable<RecoveryCodesResponse> {
    return this.http.post<RecoveryCodesResponse>(`${this.api}/auth/mfa/recovery-codes`, null);
  }

  /** Admin: quita la de otro usuario (perdió el dispositivo) y le cierra las sesiones. */
  reset(userId: string): Observable<UserSummary> {
    return this.http.post<UserSummary>(`${this.api}/users/${userId}/mfa/reset`, null);
  }
}
