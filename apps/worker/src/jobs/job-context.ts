import type { Job } from 'bullmq';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { RunLog } from './run-log.js';

/** Por qué se aborta un job en curso. */
export type AbortReason = 'shutdown' | 'lock-lost';

/** Recurso con caducidad que el job mantiene vivo mientras corre (huecos del host, locks…). */
export interface JobLease {
  renew(): Promise<void>;
  release(): Promise<void>;
}

/**
 * Lo que sabe el código de un job sobre su ejecución (DESIGN §20), sin pasarlo por parámetros:
 * su señal de aborto (la usan los procesos hijos), el token del lock de BullMQ, el fencing token y
 * los recursos que hay que renovar y soltar al terminar.
 */
export interface JobContext {
  job: Job;
  token: string | undefined;
  /** Réplica que lo ejecuta. */
  worker: string;
  signal: AbortSignal;
  /** Fencing token (`job_runs.attempt`); null en jobs sin fila en la Actividad. */
  attempt: number | null;
  /** Generación de la BD de Trivy que usa este job (la que abrió al empezar). */
  trivyCache?: string;
  leases: JobLease[];
  /** Log de este intento (DESIGN §20, «Log de cada ejecución»); solo en jobs con fila. */
  log?: RunLog;
}

const storage = new AsyncLocalStorage<JobContext>();

export function runInJobContext<T>(
  context: JobContext,
  fn: () => Promise<T>,
): Promise<T> {
  return storage.run(context, fn);
}

/** El job en curso (undefined fuera de un job: arranque, tests, tareas del líder). */
export function currentJob(): JobContext | undefined {
  return storage.getStore();
}

/** Motivo del aborto del job en curso, o null si no se ha abortado. */
export function abortReason(): AbortReason | null {
  const signal = storage.getStore()?.signal;
  return signal?.aborted ? (signal.reason as AbortReason) : null;
}

/**
 * Control de flujo, no un fallo: los `guard` de los procesadores lo dejan pasar tal cual (sin
 * marcar nada como fallido ni avisar) y la envoltura de `process` lo resuelve.
 */
export class JobInterrupted extends Error {}

/** El host está ocupado: el job vuelve a la cola retrasado, sin gastar un intento. */
export class HostBusy extends JobInterrupted {
  constructor(
    message: string,
    readonly delayMs: number,
  ) {
    super(message);
  }
}

/** Otra ejecución del mismo job (una réplica que lo retomó) ya escribió: esta no escribe nada. */
export class SupersededError extends JobInterrupted {
  constructor() {
    super('Otra ejecución de este job lo ha sustituido: no se guarda nada');
  }
}

/** El job se abortó (parada de la réplica o lock perdido). */
export class JobAborted extends JobInterrupted {
  constructor(readonly reason: AbortReason) {
    super(
      reason === 'shutdown'
        ? 'Abortado: la réplica se está parando'
        : 'Abortado: el lock del job se perdió',
    );
  }
}

/**
 * ¿Hay que dejar pasar este error sin tratarlo como fallo del job? Sí si es control de flujo o si
 * el job se ha abortado (el error es la consecuencia: un proceso hijo muerto, una conexión cortada).
 */
export function isInterruption(error: unknown): boolean {
  return error instanceof JobInterrupted || abortReason() !== null;
}

/** Lanza `JobAborted` si el job en curso se ha abortado (bucles largos entre pasos). */
export function throwIfAborted(): void {
  const reason = abortReason();
  if (reason) throw new JobAborted(reason);
}
