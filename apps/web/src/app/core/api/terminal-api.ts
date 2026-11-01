import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  AccessPolicyRule,
  AssetAccess,
  AssetTerminalStatus,
  CreateAccessPolicyRequest,
  CreateTerminalSessionResponse,
  TerminalAction,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/** Terminal web (DESIGN §11) y políticas de acceso (sesión 22). */
@Injectable({ providedIn: 'root' })
export class TerminalApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  /** ¿Puedo abrir terminal en el asset y está disponible? */
  status(assetId: string): Observable<AssetTerminalStatus> {
    return this.http.get<AssetTerminalStatus>(
      `${this.api}/assets/${encodeURIComponent(assetId)}/terminal`,
    );
  }

  /**
   * Ticket de un solo uso (pide reautenticación si caducó: lo resuelve el interceptor). Con
   * `action`, la sesión ejecuta ese comando fijo en solo lectura en lugar de la shell.
   */
  open(
    assetId: string,
    action: TerminalAction | null = null,
  ): Observable<CreateTerminalSessionResponse> {
    return this.http.post<CreateTerminalSessionResponse>(
      `${this.api}/terminal/sessions`,
      action ? { assetId, action } : { assetId },
    );
  }

  rules(filter: { assetId?: string } = {}): Observable<AccessPolicyRule[]> {
    return this.http.get<AccessPolicyRule[]>(`${this.api}/access-policies`, {
      params: filter.assetId ? { assetId: filter.assetId } : {},
    });
  }

  grant(body: CreateAccessPolicyRequest): Observable<AccessPolicyRule> {
    return this.http.post<AccessPolicyRule>(`${this.api}/access-policies`, body);
  }

  revoke(id: string): Observable<void> {
    return this.http.delete<void>(`${this.api}/access-policies/${encodeURIComponent(id)}`);
  }

  assetAccess(assetId: string): Observable<AssetAccess> {
    return this.http.get<AssetAccess>(
      `${this.api}/assets/${encodeURIComponent(assetId)}/access`,
    );
  }
}
