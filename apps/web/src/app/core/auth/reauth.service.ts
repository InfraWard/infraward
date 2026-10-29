import { Injectable, signal } from '@angular/core';
import type { RecentAuthError, SensitiveAction } from '@infraward/shared-types';

/** Lo que pide la API para una acción sensible (403 `recent_auth_required` o `mfa_required_for_action`). */
export interface ReauthPrompt {
  action: SensitiveAction;
  /** `totp`: código; `oidc`: nuevo login en el proveedor; `setup`: antes tiene que activar TOTP. */
  kind: 'totp' | 'oidc' | 'setup';
}

/**
 * Reautenticación reciente (step-up, DESIGN §14). El interceptor la pide al recibir el 403 de una
 * acción sensible; el diálogo (`app-reauth-dialog`, en el shell) la resuelve y, si el usuario
 * confirma su identidad con un código, el interceptor repite la petición. Con OIDC el navegador
 * sale al proveedor y la promesa no se resuelve (la página se va).
 */
@Injectable({ providedIn: 'root' })
export class ReauthService {
  readonly prompt = signal<ReauthPrompt | null>(null);
  private pending: Promise<boolean> | null = null;
  private resolve: ((ok: boolean) => void) | null = null;

  /** Pide confirmar la identidad; varias peticiones a la vez comparten el mismo diálogo. */
  request(error: Pick<RecentAuthError, 'code' | 'action' | 'method'>): Promise<boolean> {
    if (this.pending) return this.pending;
    this.prompt.set({
      action: error.action,
      kind:
        error.code === 'mfa_required_for_action'
          ? 'setup'
          : error.method === 'oidc'
            ? 'oidc'
            : 'totp',
    });
    this.pending = new Promise<boolean>((resolve) => (this.resolve = resolve));
    return this.pending;
  }

  /** El diálogo termina: `true` si la identidad quedó confirmada (se repite la petición). */
  complete(ok: boolean): void {
    this.prompt.set(null);
    const resolve = this.resolve;
    this.pending = null;
    this.resolve = null;
    resolve?.(ok);
  }
}
