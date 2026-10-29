import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  CreateUserRequest,
  TemporaryPasswordResponse,
  UpdateUserRequest,
  UserSummary,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/** Gestión de usuarios (solo admin). Las contraseñas temporales llegan una sola vez. */
@Injectable({ providedIn: 'root' })
export class UsersApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  list(): Observable<UserSummary[]> {
    return this.http.get<UserSummary[]>(`${this.api}/users`);
  }

  create(body: CreateUserRequest): Observable<TemporaryPasswordResponse> {
    return this.http.post<TemporaryPasswordResponse>(`${this.api}/users`, body);
  }

  update(id: string, body: UpdateUserRequest): Observable<UserSummary> {
    return this.http.patch<UserSummary>(`${this.api}/users/${id}`, body);
  }

  deactivate(id: string): Observable<UserSummary> {
    return this.http.post<UserSummary>(`${this.api}/users/${id}/deactivate`, null);
  }

  reactivate(id: string): Observable<UserSummary> {
    return this.http.post<UserSummary>(`${this.api}/users/${id}/reactivate`, null);
  }

  resetPassword(id: string): Observable<TemporaryPasswordResponse> {
    return this.http.post<TemporaryPasswordResponse>(
      `${this.api}/users/${id}/reset-password`,
      null,
    );
  }
}
