import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  CreateVaultEntryRequest,
  ReplaceVaultSecretRequest,
  RevealVaultSecretRequest,
  RevealVaultSecretResponse,
  UpdateVaultEntryRequest,
  VaultEntry,
  VaultEntryList,
  VaultSettings,
  VaultStatus,
  VaultVersion,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/**
 * Caja fuerte de credenciales (QoL-7). Ninguna respuesta lleva el valor salvo `reveal` (solo
 * admin, con reautenticación: el interceptor abre el diálogo y repite la petición).
 */
@Injectable({ providedIn: 'root' })
export class VaultApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  private entry(id: string): string {
    return `${this.api}/vault/entries/${encodeURIComponent(id)}`;
  }

  list(query: { assetId?: string; deleted?: boolean; q?: string } = {}): Observable<VaultEntryList> {
    let params = new HttpParams();
    if (query.assetId) params = params.set('assetId', query.assetId);
    if (query.deleted) params = params.set('deleted', 'true');
    if (query.q?.trim()) params = params.set('q', query.q.trim());
    return this.http.get<VaultEntryList>(`${this.api}/vault/entries`, { params });
  }

  create(body: CreateVaultEntryRequest): Observable<VaultEntry> {
    return this.http.post<VaultEntry>(`${this.api}/vault/entries`, body);
  }

  update(id: string, body: UpdateVaultEntryRequest): Observable<VaultEntry> {
    return this.http.patch<VaultEntry>(this.entry(id), body);
  }

  replaceSecret(id: string, body: ReplaceVaultSecretRequest): Observable<VaultEntry> {
    return this.http.put<VaultEntry>(`${this.entry(id)}/secret`, body);
  }

  markRotated(id: string): Observable<VaultEntry> {
    return this.http.post<VaultEntry>(`${this.entry(id)}/rotated`, {});
  }

  remove(id: string): Observable<VaultEntry> {
    return this.http.delete<VaultEntry>(this.entry(id));
  }

  restore(id: string): Observable<VaultEntry> {
    return this.http.post<VaultEntry>(`${this.entry(id)}/restore`, {});
  }

  versions(id: string): Observable<VaultVersion[]> {
    return this.http.get<VaultVersion[]>(`${this.entry(id)}/versions`);
  }

  restoreVersion(id: string, version: number): Observable<VaultEntry> {
    return this.http.post<VaultEntry>(`${this.entry(id)}/versions/${version}/restore`, {});
  }

  /** La única respuesta con el valor: no la guardes en ningún estado que dure. */
  reveal(id: string, body: RevealVaultSecretRequest): Observable<RevealVaultSecretResponse> {
    return this.http.post<RevealVaultSecretResponse>(`${this.entry(id)}/reveal`, body);
  }

  status(): Observable<VaultStatus> {
    return this.http.get<VaultStatus>(`${this.api}/vault/status`);
  }

  settings(): Observable<VaultSettings> {
    return this.http.get<VaultSettings>(`${this.api}/vault/settings`);
  }

  updateSettings(body: VaultSettings): Observable<VaultSettings> {
    return this.http.put<VaultSettings>(`${this.api}/vault/settings`, body);
  }
}
