import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import type {
  AssetPolicy,
  CreateInventoryPolicyRequest,
  EnqueueJobResponse,
  InventoryPolicyFields,
  InventoryPolicyList,
  InventoryPolicyRule,
  UpdateGlobalPolicyRequest,
  NotificationPage,
  NotificationUnreadCount,
} from '@infraward/shared-types';
import type { Observable } from 'rxjs';
import { API_BASE_URL } from './api-base-url';

/**
 * Mantenimiento del inventario (DESIGN §10): política de inventario, reconciliación y
 * notificaciones. Los cambios son solo para admin.
 */
@Injectable({ providedIn: 'root' })
export class MaintenanceApi {
  private readonly http = inject(HttpClient);
  private readonly api = inject(API_BASE_URL);

  policies(): Observable<InventoryPolicyList> {
    return this.http.get<InventoryPolicyList>(`${this.api}/inventory-policies`);
  }

  updateGlobal(
    values: UpdateGlobalPolicyRequest,
  ): Observable<InventoryPolicyRule> {
    return this.http.put<InventoryPolicyRule>(
      `${this.api}/inventory-policies/global`,
      values,
    );
  }

  createRule(
    rule: CreateInventoryPolicyRequest,
  ): Observable<InventoryPolicyRule> {
    return this.http.post<InventoryPolicyRule>(
      `${this.api}/inventory-policies`,
      rule,
    );
  }

  updateRule(
    id: string,
    fields: InventoryPolicyFields,
  ): Observable<InventoryPolicyRule> {
    return this.http.patch<InventoryPolicyRule>(
      `${this.api}/inventory-policies/${enc(id)}`,
      fields,
    );
  }

  removeRule(id: string): Observable<void> {
    return this.http.delete<void>(`${this.api}/inventory-policies/${enc(id)}`);
  }

  assetPolicy(assetId: string): Observable<AssetPolicy> {
    return this.http.get<AssetPolicy>(
      `${this.api}/assets/${enc(assetId)}/policy`,
    );
  }

  setAssetPolicy(
    assetId: string,
    fields: InventoryPolicyFields,
  ): Observable<AssetPolicy> {
    return this.http.put<AssetPolicy>(
      `${this.api}/assets/${enc(assetId)}/policy`,
      fields,
    );
  }

  removeAssetPolicy(assetId: string): Observable<AssetPolicy> {
    return this.http.delete<AssetPolicy>(
      `${this.api}/assets/${enc(assetId)}/policy`,
    );
  }

  /** Reconcilia ahora las raíces vencidas o, con `assetId`, ese nodo raíz. */
  reconcile(assetId?: string): Observable<EnqueueJobResponse> {
    return this.http.post<EnqueueJobResponse>(
      `${this.api}/inventory/reconcile`,
      assetId ? { assetId } : {},
    );
  }

  notifications(limit = 20): Observable<NotificationPage> {
    return this.http.get<NotificationPage>(`${this.api}/notifications`, {
      params: { limit },
    });
  }

  unreadNotifications(): Observable<NotificationUnreadCount> {
    return this.http.get<NotificationUnreadCount>(
      `${this.api}/notifications/unread-count`,
    );
  }

  markNotificationsSeen(): Observable<NotificationUnreadCount> {
    return this.http.post<NotificationUnreadCount>(
      `${this.api}/notifications/seen`,
      {},
    );
  }
}

const enc = encodeURIComponent;
