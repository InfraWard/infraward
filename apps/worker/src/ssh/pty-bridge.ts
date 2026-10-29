import { spawn, type ChildProcess } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';

/**
 * Puente PTY en Python (solo la biblioteca estándar: `python3` ya va en la imagen por Ansible),
 * en lugar de un módulo nativo. Arranca el comando en un pseudoterminal propio y hace de puente:
 * - stdin → PTY y PTY → stdout, en bruto;
 * - fd 3: líneas `<columnas> <filas>` para redimensionar (TIOCSWINSZ; el núcleo avisa con
 *   SIGWINCH al programa, que en ssh envía el window-change al servidor);
 * - fin de stdin (el cliente se fue) o SIGTERM/SIGHUP: cierra el PTY (el comando recibe SIGHUP)
 *   y, si no termina en 3 s, lo mata;
 * - sale con el código del comando (128 + señal si murió por una).
 * Argumentos: columnas, filas y el comando (`execvp`, sin shell en medio).
 */
export const PTY_BRIDGE_SCRIPT = String.raw`
import errno, fcntl, os, pty, select, signal, struct, sys, termios, time

cols, rows = int(sys.argv[1]), int(sys.argv[2])
argv = sys.argv[3:]

def winsize(fd, c, r):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', r, c, 0, 0))

pid, master = pty.fork()
if pid == 0:
    try:
        winsize(0, cols, rows)
        os.execvp(argv[0], argv)
    finally:
        os._exit(127)

closing = [False]
def close_pty(*_):
    closing[0] = True
signal.signal(signal.SIGTERM, close_pty)
signal.signal(signal.SIGHUP, close_pty)

def write_all(fd, data):
    while data:
        try:
            n = os.write(fd, data)
        except OSError as e:
            if e.errno == errno.EINTR:
                continue
            raise
        data = data[n:]

inputs = [master, 0, 3]
ctl = b''
while not closing[0]:
    try:
        ready, _, _ = select.select(inputs, [], [], 1.0)
    except InterruptedError:
        continue
    if master in ready:
        try:
            data = os.read(master, 65536)
        except OSError:
            data = b''
        if not data:
            break
        write_all(1, data)
    if 0 in ready:
        data = os.read(0, 65536)
        if not data:
            break
        write_all(master, data)
    if 3 in ready:
        data = os.read(3, 4096)
        if not data:
            inputs.remove(3)
        ctl += data
        while b'\n' in ctl:
            line, ctl = ctl.split(b'\n', 1)
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                c, r = int(parts[0]), int(parts[1])
                if 0 < c <= 1000 and 0 < r <= 500:
                    winsize(master, c, r)
                    try:
                        os.killpg(os.getpgid(pid), signal.SIGWINCH)
                    except OSError:
                        pass

try:
    os.close(master)
except OSError:
    pass
deadline = time.time() + 3
status = None
while status is None:
    done, st = os.waitpid(pid, os.WNOHANG)
    if done:
        status = st
    elif time.time() > deadline:
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
    else:
        time.sleep(0.05)
if os.WIFEXITED(status):
    sys.exit(os.WEXITSTATUS(status))
sys.exit(128 + os.WTERMSIG(status))
`;

/** Proceso con PTY: lo que escribe el usuario entra por `write`; la salida, por `onData`. */
export interface PtyProcess {
  readonly pid: number | undefined;
  write(data: Buffer | string): void;
  resize(cols: number, rows: number): void;
  /** Cierre ordenado: el comando recibe SIGHUP (como al cerrar una terminal). */
  hangup(): void;
  /** Mata el grupo entero (puente y comando). */
  kill(): void;
  onData(listener: (data: Buffer) => void): void;
  /** Código de salida del comando (null si el puente murió por una señal). */
  onExit(listener: (code: number | null) => void): void;
}

export interface PtySpawnOptions {
  cols: number;
  rows: number;
  env: NodeJS.ProcessEnv;
  /** Binario de Python (por defecto `python3`). */
  python?: string;
}

/** Lanza `argv` en un PTY propio (proceso en su propio grupo: se mata entero). */
export function spawnPty(argv: readonly string[], options: PtySpawnOptions): PtyProcess {
  const child: ChildProcess = spawn(
    options.python ?? 'python3',
    ['-I', '-c', PTY_BRIDGE_SCRIPT, String(options.cols), String(options.rows), ...argv],
    { stdio: ['pipe', 'pipe', 'pipe', 'pipe'], detached: true, env: options.env },
  );
  const stdin = child.stdin as Writable;
  const ctl = child.stdio[3] as Writable;
  // Un EPIPE al escribir tras la salida no debe tumbar el proceso.
  stdin.on('error', () => undefined);
  ctl.on('error', () => undefined);
  (child.stderr as Readable).resume();
  const signalGroup = (signal: NodeJS.Signals) => {
    if (child.pid === undefined || child.exitCode !== null) return;
    try {
      process.kill(-child.pid, signal);
    } catch {
      // Ya terminó.
    }
  };
  return {
    pid: child.pid,
    write: (data) => {
      if (stdin.writable) stdin.write(data);
    },
    resize: (cols, rows) => {
      if (ctl.writable) ctl.write(`${cols} ${rows}\n`);
    },
    hangup: () => {
      if (child.pid !== undefined && child.exitCode === null) child.kill('SIGHUP');
    },
    kill: () => signalGroup('SIGKILL'),
    onData: (listener) => (child.stdout as Readable).on('data', listener),
    onExit: (listener) => {
      let done = false;
      const finish = (code: number | null) => {
        if (done) return;
        done = true;
        listener(code);
      };
      child.on('exit', (code) => finish(code));
      child.on('error', () => finish(null));
    },
  };
}
