import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type { SecretProviderInfo } from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/** Ajustes: estado de los proveedores de secretos (solo admin). */
@Injectable({ providedIn: 'root' })
export class SettingsApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  secretProviders(): Observable<SecretProviderInfo[]> {
    return this.http.get<SecretProviderInfo[]>(
      `${this.api}/secrets/providers`,
    );
  }
}
