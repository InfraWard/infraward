import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  JobRunListQuery,
  JobRunSummary,
  JobStatus,
  Page,
  WorkerReplica,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';
import { toParams } from './query-params';

/** Historial de ejecuciones de jobs (Actividad). */
@Injectable({ providedIn: 'root' })
export class JobsApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  list(query: JobRunListQuery = {}): Observable<Page<JobRunSummary>> {
    return this.http.get<Page<JobRunSummary>>(`${this.api}/jobs`, {
      params: toParams(query),
    });
  }

  /** Réplicas del worker conectadas (qué colas consume cada una y cuál es el líder). */
  workers(): Observable<WorkerReplica[]> {
    return this.http.get<WorkerReplica[]>(`${this.api}/jobs/workers`);
  }

  /** Estado y progreso de un job en la cola (mientras BullMQ lo conserve). */
  status(id: string): Observable<JobStatus> {
    return this.http.get<JobStatus>(
      `${this.api}/jobs/${encodeURIComponent(id)}`,
    );
  }
}
