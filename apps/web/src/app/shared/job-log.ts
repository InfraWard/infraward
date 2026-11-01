import { Component, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import type {
  JobLogEntry,
  JobLogLevel,
  JobRunLog,
  JobRunLogAttempt,
} from '@infraward/shared-types';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import {
  formatDuration,
  isRunning,
  JOB_STATE_LABELS,
  JOB_STATE_SEVERITY,
  type TagSeverity,
} from './labels';

export const LOG_LEVEL_LABELS: Record<JobLogLevel, string> = {
  debug: 'DEBUG',
  info: 'INFO',
  warn: 'AVISO',
  error: 'ERROR',
};

/** «+0:03.2» desde el inicio del intento (minutos:segundos). */
export function logOffset(at: string, start: string): string {
  const ms = Math.max(0, Date.parse(at) - Date.parse(start));
  if (!Number.isFinite(ms)) return '';
  const totalSeconds = ms / 1000;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = (totalSeconds % 60).toFixed(1).padStart(4, '0');
  return `+${minutes}:${seconds}`;
}

/** Líneas que se pintan: sin las de detalle (`debug`) salvo que se pidan. */
export function visibleEntries(
  attempt: JobRunLogAttempt,
  showDebug: boolean,
): JobLogEntry[] {
  return showDebug
    ? attempt.entries
    : attempt.entries.filter((e) => e.level !== 'debug');
}

/**
 * Log de una ejecución (DESIGN §20, «Log de cada ejecución»): estado, duración y réplica, el
 * error si falló y un visor monoespaciado por niveles con un bloque por intento. Lo usan la
 * pestaña «Recolecciones» de la ficha y el detalle de la Actividad; quien lo usa lo carga y lo
 * refresca.
 */
@Component({
  selector: 'app-job-log',
  imports: [FormsModule, CheckboxModule, MessageModule, TagModule],
  template: `
    @let current = log().run;
    <div class="summary">
      @if (!compact()) {
        <p-tag [value]="stateLabels[current.state]" [severity]="stateSeverity[current.state]" data-log-state />
        <span class="muted">Duración: {{ duration(current.durationMs) }}</span>
        @if (current.worker) {
          <span class="muted">Réplica: <code>{{ current.worker }}</code></span>
        }
        @if (isRunning(current)) {
          <span class="muted"><i class="bi bi-arrow-repeat spin" aria-hidden="true"></i> Actualizándose…</span>
        }
      }
      <span class="debug-toggle">
        <p-checkbox [binary]="true" [ngModel]="showDebug()" (ngModelChange)="showDebug.set($event)" [inputId]="debugId" data-log-debug />
        <label [for]="debugId">Ver detalle</label>
      </span>
    </div>
    @if (!compact() && current.state === 'failed' && current.error) {
      <p-message severity="error" icon="bi bi-x-octagon" styleClass="mb" data-log-error>{{ current.error }}</p-message>
    }
    @for (attempt of log().attempts; track attempt.attempt) {
      @if (log().attempts.length > 1) {
        <h4 class="attempt">Intento {{ attempt.attempt }}@if (attempt.worker) { en {{ attempt.worker }}}</h4>
      }
      @if (attempt.truncated) {
        <p-message severity="warn" icon="bi bi-scissors" styleClass="mb">
          Se llegó al tamaño máximo del log: se omitieron {{ attempt.dropped }} líneas.
        </p-message>
      }
      <pre class="log" role="log" [attr.aria-label]="'Log del intento ' + attempt.attempt" data-log>@for (e of entries(attempt); track $index) {<span [class]="'line level-' + e.level + ' kind-' + e.kind"><span class="time">{{ offset(e.at, attempt.startedAt) }}</span> <span class="level">{{ levelLabels[e.level] }}</span> <span class="msg">{{ e.kind === 'command' ? '$ ' : '' }}{{ e.message }}</span>@if (e.durationMs !== undefined) {<span class="meta"> ({{ duration(e.durationMs) }}{{ exitText(e) }})</span>}</span>}</pre>
    } @empty {
      <p class="muted" data-log-empty>
        @if (isRunning(current)) {
          Aún no hay log: la ejecución está en cola.
        } @else {
          Esta ejecución no tiene log (ya caducó o es de antes de que se guardaran).
        }
      </p>
    }
  `,
  styles: `
    .muted {
      color: var(--p-text-muted-color);
    }
    h4.attempt {
      margin: 1rem 0 0.4rem;
      font-size: 0.95rem;
    }
    .summary {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
      margin-bottom: 0.75rem;
    }
    .debug-toggle {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      margin-left: auto;
    }
    .debug-toggle label {
      cursor: pointer;
    }
    :host ::ng-deep .mb {
      margin-bottom: 0.75rem;
    }
    .log {
      margin: 0;
      padding: 0.75rem;
      max-height: 32rem;
      overflow: auto;
      border-radius: 6px;
      background: #0f172a;
      color: #e2e8f0;
      font-family: var(--p-font-family-mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
      font-size: 0.8rem;
      line-height: 1.45;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .line {
      display: block;
    }
    .time {
      color: #64748b;
    }
    .level {
      display: inline-block;
      min-width: 3.4rem;
      font-weight: 600;
    }
    .level-debug {
      color: #94a3b8;
    }
    .level-info .level {
      color: #38bdf8;
    }
    .level-warn {
      color: #fcd34d;
    }
    .level-error {
      color: #fca5a5;
      background: rgba(239, 68, 68, 0.12);
    }
    .kind-command .msg {
      color: #a7f3d0;
    }
    .kind-result .msg {
      font-weight: 600;
    }
    .meta {
      color: #94a3b8;
    }
    .spin {
      display: inline-block;
      animation: spin 1.2s linear infinite;
    }
    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }
    @media (prefers-reduced-motion: reduce) {
      .spin {
        animation: none;
      }
    }
  `,
})
export class JobLogView {
  private static nextId = 0;

  readonly log = input.required<JobRunLog>();
  /**
   * Sin estado, duración, réplica ni error encima del log: para cuando la página ya los enseña
   * (el detalle de la Actividad).
   */
  readonly compact = input(false);

  protected readonly debugId = `log-debug-${JobLogView.nextId++}`;
  protected readonly stateLabels: Readonly<Record<string, string>> = JOB_STATE_LABELS;
  protected readonly stateSeverity: Readonly<Record<string, TagSeverity>> = JOB_STATE_SEVERITY;
  protected readonly levelLabels = LOG_LEVEL_LABELS;
  protected readonly duration = formatDuration;
  protected readonly isRunning = isRunning;
  protected readonly offset = logOffset;
  protected readonly showDebug = signal(false);

  protected entries(attempt: JobRunLogAttempt): JobLogEntry[] {
    return visibleEntries(attempt, this.showDebug());
  }

  protected exitText(entry: JobLogEntry): string {
    if (entry.exitCode === undefined || entry.exitCode === 0) return '';
    return entry.exitCode === null ? ', sin terminar' : `, código ${entry.exitCode}`;
  }
}
