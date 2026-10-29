import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import {
  widgetRequestParams,
  type DashboardDocument,
  type DashboardLayout,
  type DashboardSummary,
  type DashboardWidget,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

@Injectable({ providedIn: 'root' })
export class DashboardApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  /** Con `projectId`, solo lo de ese proyecto. */
  summary(projectId?: string): Observable<DashboardSummary> {
    return this.http.get<DashboardSummary>(`${this.api}/dashboard`, {
      params: projectId ? { projectId } : {},
    });
  }

  /** Datos de un widget (`project` sustituye al proyecto del widget). */
  widget<T>(
    widget: Pick<DashboardWidget, 'type' | 'filters' | 'options'>,
    project?: string,
  ): Observable<T> {
    return this.http.get<T>(`${this.api}/dashboard/widgets/${widget.type}`, {
      params: widgetRequestParams(widget, project),
    });
  }

  /** Tu panel o el de un proyecto (con `projectId`). */
  get(projectId?: string): Observable<DashboardDocument> {
    return this.http.get<DashboardDocument>(this.url(projectId));
  }

  save(
    layout: DashboardLayout,
    version: number,
    projectId?: string,
  ): Observable<DashboardDocument> {
    return this.http.put<DashboardDocument>(this.url(projectId), {
      layout,
      version,
    });
  }

  /** Vuelve al por defecto (o a la plantilla del proyecto). */
  reset(projectId?: string): Observable<DashboardDocument> {
    return this.http.delete<DashboardDocument>(this.url(projectId));
  }

  private url(projectId?: string): string {
    return projectId
      ? `${this.api}/projects/${projectId}/dashboard`
      : `${this.api}/dashboards/me`;
  }
}
