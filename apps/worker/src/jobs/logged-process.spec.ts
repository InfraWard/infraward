import type { Job } from 'bullmq';
import { runInJobContext } from './job-context.js';
import { formatBytes, loggedRunner, loggedStreamer } from './logged-process.js';
import { RunLog } from './run-log.js';
import type { ProcessRunner, ProcessStreamer } from '../ssh/ssh-client.js';

function inJob<T>(log: RunLog, fn: () => Promise<T>): Promise<T> {
  return runInJobContext(
    {
      job: { id: 'j' } as Job,
      token: undefined,
      worker: 'w',
      signal: new AbortController().signal,
      attempt: 1,
      leases: [],
      log,
    },
    fn,
  );
}

describe('loggedRunner', () => {
  it('fuera de un job no registra nada', async () => {
    const inner = vi.fn<ProcessRunner>(async () => ({
      stdout: 'x',
      stderr: '',
      code: 0,
    }));
    await expect(loggedRunner(inner)('ssh', [], 1000)).resolves.toEqual({
      stdout: 'x',
      stderr: '',
      code: 0,
    });
    expect(inner).toHaveBeenCalledOnce();
  });

  it('comando con duración; nunca el stdout', async () => {
    const log = new RunLog(64 * 1024);
    const inner: ProcessRunner = async () => ({
      stdout: 'DATOS-DEL-SERVIDOR',
      stderr: '',
      code: 0,
    });
    await inJob(log, () =>
      loggedRunner(inner)('ssh-keyscan', ['-p', '22', '--', 'h'], 1000),
    );
    expect(log.entries).toHaveLength(1);
    expect(log.entries[0]).toMatchObject({
      level: 'info',
      kind: 'command',
      message: 'ssh-keyscan h:22',
      exitCode: 0,
    });
    expect(log.entries[0]!.durationMs).toBeGreaterThanOrEqual(0);
    expect(JSON.stringify(log.entries)).not.toContain('DATOS-DEL-SERVIDOR');
  });

  it('si falla: aviso, final del stderr censurado y, sin terminar, el motivo', async () => {
    const log = new RunLog(64 * 1024);
    const inner: ProcessRunner = async () => ({
      stdout: '',
      stderr: 'conectando\nERROR token=abc123 rechazado\n',
      code: null,
    });
    await inJob(log, () => loggedRunner(inner)('trivy', ['image', 'x'], 5000));
    expect(log.entries.map((e) => [e.level, e.message])).toEqual([
      ['warn', 'trivy image x'],
      ['error', 'Sin terminar: superó 5 s o se abortó'],
      ['warn', 'conectando'],
      ['warn', 'ERROR token=[censurado] rechazado'],
    ]);
  });

  it('ansible-playbook: añade las tareas y el resumen', async () => {
    const log = new RunLog(64 * 1024);
    const inner: ProcessRunner = async () => ({
      stdout:
        'TASK [Facts] ***\nok: [target]\nPLAY RECAP ***\ntarget : ok=1 failed=0\n',
      stderr: '',
      code: 0,
    });
    await inJob(log, () =>
      loggedRunner(inner)(
        'ansible-playbook',
        ['-i', 'inv', '/a/collect/collect.yml'],
        1000,
      ),
    );
    expect(log.entries.map((e) => e.message)).toEqual([
      'ansible-playbook collect.yml',
      'Tarea: Facts',
      'Resumen: target : ok=1 failed=0',
    ]);
  });

  it('el control del maestro (-O check/exit) va como detalle aunque «falle»', async () => {
    const log = new RunLog(64 * 1024);
    const inner: ProcessRunner = async () => ({
      stdout: '',
      stderr: 'No ControlPath',
      code: 255,
    });
    await inJob(log, () =>
      loggedRunner(inner)('ssh', ['-O', 'check', '-l', 'u', '--', 'h'], 1000),
    );
    expect(log.entries).toEqual([
      expect.objectContaining({ level: 'debug', message: 'ssh -O check u@h' }),
    ]);
  });

  it('si no se puede lanzar, lo registra y relanza', async () => {
    const log = new RunLog(64 * 1024);
    const inner: ProcessRunner = async () => {
      throw new TypeError('spawn ENOENT');
    };
    await expect(
      inJob(log, () => loggedRunner(inner)('nmap', [], 1000)),
    ).rejects.toThrow('spawn ENOENT');
    expect(log.entries[0]).toMatchObject({
      level: 'error',
      message: 'nmap: no se pudo lanzar (TypeError)',
    });
  });
});

describe('loggedStreamer', () => {
  it('el tamaño descargado y el corte por límite', async () => {
    const log = new RunLog(64 * 1024);
    const inner: ProcessStreamer = async () => ({
      code: null,
      bytes: 3 * 1024 * 1024,
      stderr: 'cortado',
      limit: 'size',
    });
    await inJob(log, () =>
      loggedStreamer(inner)(
        'ssh',
        ['-l', 'u', '--', 'h', 'docker-save x'],
        '/dev/shm/o',
        {
          maxBytes: 1,
          timeoutMs: 1,
        },
      ),
    );
    expect(log.entries.map((e) => [e.level, e.message])).toEqual([
      ['warn', 'ssh u@h docker-save x → 3.0 MiB'],
      ['error', 'Cortado: superó el tamaño máximo'],
      ['warn', 'cortado'],
    ]);
  });

  it('formatBytes', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KiB');
  });
});
