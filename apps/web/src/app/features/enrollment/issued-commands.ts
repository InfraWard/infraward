import { Injectable } from '@angular/core';
import type { IssuedEnrollment } from '@infraward/shared-types';

/**
 * Comandos recién emitidos, por asset. La API los devuelve una sola vez (llevan el token): se
 * guardan solo en memoria, nunca en el almacenamiento del navegador. Al recargar se pierden y
 * hay que generar otro.
 */
@Injectable({ providedIn: 'root' })
export class IssuedCommands {
  private readonly byAsset = new Map<string, IssuedEnrollment>();

  set(issued: IssuedEnrollment): void {
    this.byAsset.set(issued.assetId, issued);
  }

  /** Solo si sigue siendo el enrolamiento vigente (no uno sustituido después). */
  get(assetId: string, enrollmentId?: string): IssuedEnrollment | null {
    const issued = this.byAsset.get(assetId) ?? null;
    if (issued && enrollmentId && issued.id !== enrollmentId) return null;
    return issued;
  }

  clear(assetId: string): void {
    this.byAsset.delete(assetId);
  }
}
