import type {
  JobLogEntry,
  JobLogKind,
  JobLogLevel,
} from '@infraward/shared-types';
import { basename } from 'node:path';
import { currentJob } from './job-context.js';
import { redactSecrets } from './redact.js';

/** Tope de cada línea (caracteres): un stderr enorme no se come el log entero. */
export const ENTRY_MAX_CHARS = 4000;
/** Bytes que se reservan para el final (resultado o fallo) aunque se haya llegado al tope. */
const TAIL_RESERVE_BYTES = 16 * 1024;
/** Líneas de salida de un comando que se guardan como mucho (las últimas). */
export const OUTPUT_MAX_LINES = 40;

/** Lo que mide una línea en el JSON guardado (aproximado: texto + campos). */
function entrySize(entry: JobLogEntry): number {
  return Buffer.byteLength(entry.message, 'utf8') + 96;
}

/** Recorta por el final con «…» (tras censurar: el corte no deja medio secreto a la vista). */
export function clipText(text: string, max = ENTRY_MAX_CHARS): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/**
 * Log de un intento de un job (DESIGN §20, «Log de cada ejecución»), en memoria hasta que
 * `JobRunLogs` lo guarda. Todo pasa por la censura de secretos y por el tope de tamaño: al
 * llegar al tope se descartan las líneas siguientes (se cuentan), salvo las del final (resultado
 * o fallo), que tienen un hueco reservado.
 */
export class RunLog {
  readonly entries: JobLogEntry[] = [];
  readonly startedAt = new Date();
  bytes = 0;
  dropped = 0;
  /** Cambió desde el último guardado. */
  dirty = true;
  private readonly onChange: () => void;

  constructor(
    readonly maxBytes: number,
    onChange: () => void = () => undefined,
  ) {
    this.onChange = onChange;
  }

  get truncated(): boolean {
    return this.dropped > 0;
  }

  add(
    level: JobLogLevel,
    kind: JobLogKind,
    message: string,
    extra: Pick<JobLogEntry, 'durationMs' | 'exitCode' | 'progress'> = {},
  ): void {
    const entry: JobLogEntry = {
      at: new Date().toISOString(),
      level,
      kind,
      message: clipText(redactSecrets(message)),
      ...extra,
    };
    const size = entrySize(entry);
    // El resultado cabe en el hueco reservado; lo demás, solo hasta el tope sin la reserva.
    const limit =
      kind === 'result' ? this.maxBytes : this.maxBytes - TAIL_RESERVE_BYTES;
    if (this.bytes + size > Math.max(limit, 0)) {
      this.dropped++;
      this.dirty = true;
      return;
    }
    this.entries.push(entry);
    this.bytes += size;
    this.dirty = true;
    this.onChange();
  }

  info(message: string, kind: JobLogKind = 'step'): void {
    this.add('info', kind, message);
  }

  warn(message: string, kind: JobLogKind = 'output'): void {
    this.add('warn', kind, message);
  }

  error(message: string, kind: JobLogKind = 'result'): void {
    this.add('error', kind, message);
  }

  step(progress: number, message: string): void {
    this.add('info', 'step', message, { progress });
  }
}

/** Log del job en curso (undefined fuera de un job o en jobs sin log). */
export function runLog(): RunLog | undefined {
  return currentJob()?.log;
}

/** Argumentos de `ssh` que llevan valor (para encontrar el destino y el comando remoto). */
const SSH_VALUE_FLAGS = new Set([
  '-b',
  '-c',
  '-D',
  '-E',
  '-e',
  '-F',
  '-I',
  '-i',
  '-J',
  '-L',
  '-l',
  '-m',
  '-O',
  '-o',
  '-p',
  '-Q',
  '-R',
  '-S',
  '-W',
  '-w',
]);

/**
 * Cómo se muestra un comando en el log: sin las rutas temporales del job ni scripts enteros.
 * - `ssh`: `ssh usuario@host:puerto <comando remoto>` (o `ssh -O exit`, el maestro…);
 * - `ansible-playbook`: el playbook y la conexión (`ssh`/`pct`);
 * - el resto: el binario y sus argumentos, cada uno recortado.
 */
export function describeCommand(file: string, args: readonly string[]): string {
  const bin = basename(file);
  if (bin === 'ssh') return describeSsh(args);
  if (bin === 'ssh-keyscan') {
    const port = args[args.indexOf('-p') + 1];
    return `ssh-keyscan ${args.at(-1) ?? ''}${args.includes('-p') && port ? `:${port}` : ''}`;
  }
  if (bin.startsWith('ansible-playbook')) {
    const playbook = args.findLast((a) => a.endsWith('.yml'));
    const vars = args[args.indexOf('-e') + 1] ?? '';
    const via = /"infraward_via":"(\w+)"/.exec(vars)?.[1];
    return `${bin} ${playbook ? basename(playbook) : ''}${via ? ` (conexión ${via})` : ''}`.trim();
  }
  return clipText(
    [bin, ...args.map((a) => clipText(shortPath(a), 120))].join(' '),
    600,
  );
}

function describeSsh(args: readonly string[]): string {
  let user: string | undefined;
  let port: string | undefined;
  let control: string | undefined;
  let master = false;
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--') {
      i++;
      break;
    }
    if (SSH_VALUE_FLAGS.has(a)) {
      const value = args[++i] ?? '';
      if (a === '-l') user = value;
      else if (a === '-p') port = value;
      else if (a === '-O') control = value;
      continue;
    }
    if (a === '-M' || a === '-fN' || a === '-N') master = true;
    if (!a.startsWith('-')) break;
  }
  const host = args[i] ?? '';
  const remote = args.slice(i + 1).join(' ');
  const target = `${user ? `${user}@` : ''}${host}${port ? `:${port}` : ''}`;
  if (control) return `ssh -O ${control} ${target}`.trim();
  if (master && !remote) return `ssh (conexión maestra) ${target}`;
  return clipText(`ssh ${target} ${clipText(remote, 500)}`.trim(), 600);
}

/** Las rutas del tmpfs del job (`/dev/shm/infraward-XXXX/known_hosts`) se quedan en el nombre. */
function shortPath(arg: string): string {
  return /^\/(?:dev\/shm|tmp|var\/tmp)\//.test(arg)
    ? `…/${basename(arg)}`
    : arg;
}

/**
 * Líneas útiles de la salida de `ansible-playbook` (callback por defecto): tareas, su resultado
 * por host (sin el JSON de los `ok`) y el resumen. Las de fallo llevan su mensaje (censurado al
 * añadirse al log).
 */
export function ansibleLines(
  stdout: string,
): { level: JobLogLevel; text: string }[] {
  const out: { level: JobLogLevel; text: string }[] = [];
  let recap = false;
  for (const raw of stdout.split('\n')) {
    const line = raw.trimEnd();
    if (!line.trim()) continue;
    const task = /^(TASK|PLAY|RUNNING HANDLER) \[(.*)\]/.exec(line);
    if (task) {
      if (task[1] !== 'PLAY')
        out.push({ level: 'debug', text: `Tarea: ${task[2]}` });
      continue;
    }
    if (/^PLAY RECAP/.test(line)) {
      recap = true;
      continue;
    }
    if (recap) {
      out.push({
        level: /failed=[1-9]|unreachable=[1-9]/.test(line) ? 'warn' : 'info',
        text: `Resumen: ${line.replace(/\s+/g, ' ').trim()}`,
      });
      continue;
    }
    const status =
      /^(fatal|failed|unreachable|ok|changed|skipping|\.\.\.ignoring)[:!]?\s*\[([^\]]*)\]/.exec(
        line,
      );
    if (status) {
      const what = status[1]!;
      if (what === 'fatal' || what === 'failed' || what === 'unreachable')
        out.push({ level: 'error', text: ansibleFailure(line) });
      else if (what === '...ignoring')
        out.push({
          level: 'warn',
          text: 'Fallo ignorado (la tarea lo admite)',
        });
      continue;
    }
    if (/^\[WARNING\]|^\[DEPRECATION WARNING\]|^ERROR!/.test(line))
      out.push({
        level: line.startsWith('ERROR') ? 'error' : 'warn',
        text: line,
      });
  }
  return out;
}

/** Las últimas líneas no vacías de un stderr (lo del final es lo que explica el fallo). */
export function tailLines(text: string, max = OUTPUT_MAX_LINES): string[] {
  const lines = text
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l.trim());
  return lines.length > max
    ? [
        `(${lines.length - max} líneas anteriores omitidas)`,
        ...lines.slice(-max),
      ]
    : lines;
}

/**
 * Una línea `fatal: [host]: FAILED! => {…}`: el `msg` y el final de `stderr` del JSON, no el JSON
 * entero (puede traer la salida del módulo). Si no es JSON, la línea tal cual (se recorta luego).
 */
export function ansibleFailure(line: string): string {
  const json = line.indexOf('=> {');
  if (json < 0) return line;
  const head = line.slice(0, json).trim();
  try {
    const parsed = JSON.parse(line.slice(json + 3)) as {
      msg?: unknown;
      stderr?: unknown;
      rc?: unknown;
    };
    const parts = [head];
    if (typeof parsed.msg === 'string') parts.push(parsed.msg);
    if (typeof parsed.rc === 'number') parts.push(`(código ${parsed.rc})`);
    if (typeof parsed.stderr === 'string' && parsed.stderr.trim())
      parts.push(`stderr: ${parsed.stderr.trim().slice(-1000)}`);
    return parts.join(' ');
  } catch {
    return head;
  }
}
