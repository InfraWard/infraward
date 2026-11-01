import type { JobRunSummary } from './jobs.js';

/**
 * Log de cada ejecución (DESIGN §20, «Log de cada ejecución»): pasos, comandos con su duración, stderr de lo que falla y
 * el resultado, sin secretos (el worker los censura antes de guardar) y con un tope por ejecución.
 * Se borra pasados `COLLECTION_LOG_RETENTION_DAYS` días (30 por defecto).
 */
export const JOB_LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export type JobLogLevel = (typeof JOB_LOG_LEVELS)[number];

/**
 * Qué es cada línea: un paso del job (el mensaje de progreso), un comando lanzado por el worker
 * (ssh, ansible-playbook, trivy…), una línea de su salida (tareas de Ansible, stderr) o el resultado.
 */
export const JOB_LOG_KINDS = ['step', 'command', 'output', 'result'] as const;
export type JobLogKind = (typeof JOB_LOG_KINDS)[number];

export interface JobLogEntry {
  /** ISO 8601. */
  at: string;
  level: JobLogLevel;
  kind: JobLogKind;
  message: string;
  /** Duración del comando (solo `command`). */
  durationMs?: number;
  /** Código de salida del comando (null: no terminó, por tiempo o señal). */
  exitCode?: number | null;
  /** Progreso del job al dar el paso (solo `step`). */
  progress?: number;
}

/** El log de un intento: cada vez que una réplica empieza el job (reintentos, relevos). */
export interface JobRunLogAttempt {
  attempt: number;
  /** Réplica que lo ejecutó. */
  worker: string | null;
  startedAt: string;
  updatedAt: string;
  /** Se llegó al tope de tamaño: faltan `dropped` líneas (las del final se conservan). */
  truncated: boolean;
  dropped: number;
  /** Tamaño aproximado guardado (bytes). */
  bytes: number;
  entries: JobLogEntry[];
}

export interface JobRunLog {
  run: JobRunSummary;
  /** Del más antiguo al más reciente. Vacío si el job no dejó log o ya caducó. */
  attempts: JobRunLogAttempt[];
}
