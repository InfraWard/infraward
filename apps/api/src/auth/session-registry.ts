import { Injectable } from '@nestjs/common';

/**
 * Conexiones largas (SSE) abiertas por cada sesión, para cortarlas en cuanto la sesión se revoca:
 * el guard solo se ejecuta al conectar. En memoria: con varias réplicas de la API haría falta
 * avisar por pub/sub de Redis (PROGRESS.md). Las terminales (sesión 22) no dependen de esto:
 * escuchan aquí los cierres y los cambios de usuario y avisan al gateway por Redis.
 */
@Injectable()
export class SessionRegistry {
  private readonly streams = new Map<string, Set<() => void>>();
  private readonly closedListeners = new Set<(sessionIds: readonly string[]) => void>();
  private readonly userListeners = new Set<(userId: string) => void>();

  /** Se llama tras borrar sesiones (logout, desactivar, contraseña, MFA…). */
  onSessionsClosed(listener: (sessionIds: readonly string[]) => void): () => void {
    this.closedListeners.add(listener);
    return () => this.closedListeners.delete(listener);
  }

  /** Se llama cuando cambia lo que puede hacer un usuario (rol) sin cerrar sus sesiones. */
  onUserChanged(listener: (userId: string) => void): () => void {
    this.userListeners.add(listener);
    return () => this.userListeners.delete(listener);
  }

  userChanged(userId: string): void {
    for (const listener of this.userListeners) safely(() => listener(userId));
  }

  /** Registra cómo cerrar un flujo de la sesión; devuelve la función para quitarlo. */
  register(sessionId: string, close: () => void): () => void {
    let set = this.streams.get(sessionId);
    if (!set) {
      set = new Set();
      this.streams.set(sessionId, set);
    }
    set.add(close);
    return () => {
      const current = this.streams.get(sessionId);
      current?.delete(close);
      if (current?.size === 0) this.streams.delete(sessionId);
    };
  }

  /** Cierra todos los flujos de esas sesiones (ya revocadas). */
  closeSessions(sessionIds: readonly string[]): void {
    if (sessionIds.length > 0)
      for (const listener of this.closedListeners) safely(() => listener(sessionIds));
    for (const id of sessionIds) {
      const set = this.streams.get(id);
      if (!set) continue;
      this.streams.delete(id);
      for (const close of set) {
        try {
          close();
        } catch {
          // Un flujo ya cerrado no impide cerrar los demás.
        }
      }
    }
  }

  /** Flujos abiertos (para los tests). */
  openStreams(sessionId: string): number {
    return this.streams.get(sessionId)?.size ?? 0;
  }
}

function safely(fn: () => void): void {
  try {
    fn();
  } catch {
    // Un oyente que falla no impide avisar a los demás.
  }
}
