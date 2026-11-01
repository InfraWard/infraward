import type { ProcessRunner, ProcessStreamer } from '../ssh/ssh-client.js';
import { ansibleLines, describeCommand, runLog, tailLines } from './run-log.js';

/**
 * Comandos de control del maestro SSH: van al log con nivel `debug` (son ruido salvo que fallen,
 * y `-O check` «falla» a propósito cuando el maestro ya no está).
 */
function isControl(args: readonly string[]): boolean {
  const i = args.indexOf('-O');
  return i >= 0 && ['check', 'exit'].includes(args[i + 1] ?? '');
}

/**
 * Envuelve el `ProcessRunner` del worker para que cada proceso que lanza un job (ssh-keyscan,
 * ssh, ansible-playbook, trivy…) deje en su log (DESIGN §20, «Log de cada ejecución») el comando
 * (sin rutas temporales ni scripts enteros), su duración, el código de salida y, si falla, el
 * final de su stderr. De ansible-playbook, además, las tareas y el resumen. Nunca su stdout (son
 * los datos del servidor). Fuera de un job (o sin log) no hace nada.
 */
export function loggedRunner(inner: ProcessRunner): ProcessRunner {
  return async (file, args, timeoutMs, options) => {
    const log = runLog();
    if (!log) return inner(file, args, timeoutMs, options);
    const started = Date.now();
    const command = describeCommand(file, args);
    const control = isControl(args);
    try {
      const result = await inner(file, args, timeoutMs, options);
      const durationMs = Date.now() - started;
      const failed = result.code !== 0 && !control;
      log.add(
        failed ? 'warn' : control ? 'debug' : 'info',
        'command',
        command,
        {
          durationMs,
          exitCode: result.code,
        },
      );
      if (
        file.endsWith('ansible-playbook') ||
        file.includes('ansible-playbook')
      )
        for (const line of ansibleLines(result.stdout))
          log.add(line.level, 'output', line.text);
      if (failed) {
        if (result.code === null)
          log.add(
            'error',
            'output',
            `Sin terminar: superó ${Math.round(timeoutMs / 1000)} s o se abortó`,
          );
        for (const line of tailLines(result.stderr))
          log.add('warn', 'output', line);
      }
      return result;
    } catch (error) {
      log.add(
        'error',
        'command',
        `${command}: no se pudo lanzar (${(error as Error).name})`,
        {
          durationMs: Date.now() - started,
          exitCode: null,
        },
      );
      throw error;
    }
  };
}

/** Lo mismo para las descargas a disco (`docker save`, BDs de paquetes): el tamaño, no el contenido. */
export function loggedStreamer(inner: ProcessStreamer): ProcessStreamer {
  return async (file, args, dest, limits) => {
    const log = runLog();
    if (!log) return inner(file, args, dest, limits);
    const started = Date.now();
    const command = describeCommand(file, args);
    try {
      const result = await inner(file, args, dest, limits);
      const failed = result.code !== 0;
      log.add(
        failed ? 'warn' : 'info',
        'command',
        `${command} → ${formatBytes(result.bytes)}`,
        {
          durationMs: Date.now() - started,
          exitCode: result.code,
        },
      );
      if (result.limit)
        log.add(
          'error',
          'output',
          result.limit === 'size'
            ? 'Cortado: superó el tamaño máximo'
            : 'Cortado: superó el tiempo máximo',
        );
      if (failed)
        for (const line of tailLines(result.stderr))
          log.add('warn', 'output', line);
      return result;
    } catch (error) {
      log.add(
        'error',
        'command',
        `${command}: falló (${(error as Error).name})`,
        {
          durationMs: Date.now() - started,
          exitCode: null,
        },
      );
      throw error;
    }
  };
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}
