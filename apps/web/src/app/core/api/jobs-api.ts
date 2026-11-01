import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  JobRunListQuery,
  JobRunLog,
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

  /** Recolecciones, descubrimientos y escaneos de un asset (los de su imagen si es un contenedor). */
  assetRuns(
    assetId: string,
    query: Pick<JobRunListQuery, 'state' | 'name' | 'limit' | 'offset'> = {},
  ): Observable<Page<JobRunSummary>> {
    return this.http.get<Page<JobRunSummary>>(
      `${this.api}/assets/${encodeURIComponent(assetId)}/runs`,
      { params: toParams(query) },
    );
  }

  /** Log de una ejecución del asset (pasos, comandos, stderr de lo que falló y resultado). */
  runLog(assetId: string, runId: string): Observable<JobRunLog> {
    return this.http.get<JobRunLog>(
      `${this.api}/assets/${encodeURIComponent(assetId)}/runs/${encodeURIComponent(runId)}/log`,
    );
  }

  /** Una ejecución del historial (detalle de la Actividad), con su origen y sus tareas. */
  run(id: string): Observable<JobRunSummary> {
    return this.http.get<JobRunSummary>(
      `${this.api}/jobs/runs/${encodeURIComponent(id)}`,
    );
  }

  /** Log de cualquier ejecución (también de las que no trabajan sobre un asset). */
  jobRunLog(id: string): Observable<JobRunLog> {
    return this.http.get<JobRunLog>(
      `${this.api}/jobs/runs/${encodeURIComponent(id)}/log`,
    );
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
