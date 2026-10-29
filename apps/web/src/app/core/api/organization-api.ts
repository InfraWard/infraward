import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  Asset,
  AssetProjects,
  AssetSummary,
  CreateProjectRequest,
  Page,
  Project,
  ProjectDetail,
  ProjectMembershipMode,
  ProjectWithStats,
  TagInfo,
  UpdateAssetRequest,
  UpdateProjectRequest,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';
import { toParams } from './query-params';

/**
 * Organización del inventario (DESIGN §5): nombre visible, tags y sus colores, notas y
 * proyectos. Leer lo puede cualquiera; cambiar, `assets.write` o `projects.write`.
 */
@Injectable({ providedIn: 'root' })
export class OrganizationApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  /** Nombre visible (`displayName`, null = el descubierto), tags o notas. */
  updateAsset(id: string, body: UpdateAssetRequest): Observable<Asset> {
    return this.http.patch<Asset>(`${this.api}/assets/${enc(id)}`, body);
  }

  /** Assets por nombre (visible o descubierto), para elegir uno. */
  searchAssets(q: string, limit = 20): Observable<Page<AssetSummary>> {
    return this.http.get<Page<AssetSummary>>(`${this.api}/assets`, {
      params: toParams({ q, limit }),
    });
  }

  tags(): Observable<TagInfo[]> {
    return this.http.get<TagInfo[]>(`${this.api}/tags`);
  }

  setTagColor(tag: string, color: string | null): Observable<TagInfo> {
    return this.http.put<TagInfo>(`${this.api}/tags/${enc(tag)}/style`, {
      color,
    });
  }

  /** Borra el tag de todos los assets (y su color). */
  deleteTag(tag: string): Observable<{ assets: number }> {
    return this.http.delete<{ assets: number }>(`${this.api}/tags/${enc(tag)}`);
  }

  projects(): Observable<ProjectWithStats[]> {
    return this.http.get<ProjectWithStats[]>(`${this.api}/projects`);
  }

  project(id: string): Observable<ProjectDetail> {
    return this.http.get<ProjectDetail>(`${this.api}/projects/${enc(id)}`);
  }

  createProject(body: CreateProjectRequest): Observable<Project> {
    return this.http.post<Project>(`${this.api}/projects`, body);
  }

  updateProject(id: string, body: UpdateProjectRequest): Observable<Project> {
    return this.http.patch<Project>(`${this.api}/projects/${enc(id)}`, body);
  }

  deleteProject(id: string): Observable<void> {
    return this.http.delete<void>(`${this.api}/projects/${enc(id)}`);
  }

  setMember(
    projectId: string,
    assetId: string,
    mode: ProjectMembershipMode,
  ): Observable<ProjectDetail> {
    return this.http.put<ProjectDetail>(
      `${this.api}/projects/${enc(projectId)}/members/${enc(assetId)}`,
      { mode },
    );
  }

  removeMember(projectId: string, assetId: string): Observable<ProjectDetail> {
    return this.http.delete<ProjectDetail>(
      `${this.api}/projects/${enc(projectId)}/members/${enc(assetId)}`,
    );
  }

  assetProjects(assetId: string): Observable<AssetProjects> {
    return this.http.get<AssetProjects>(
      `${this.api}/assets/${enc(assetId)}/projects`,
    );
  }
}

const enc = encodeURIComponent;
