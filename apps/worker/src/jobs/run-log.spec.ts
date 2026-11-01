import type { Job } from 'bullmq';
import { runInJobContext } from './job-context.js';
import {
  ansibleFailure,
  ansibleLines,
  describeCommand,
  ENTRY_MAX_CHARS,
  RunLog,
  runLog,
  tailLines,
} from './run-log.js';

describe('RunLog', () => {
  it('censura y recorta cada línea, y avisa de cada cambio', () => {
    const onChange = vi.fn();
    const log = new RunLog(256 * 1024, onChange);
    log.info('Conectando con password=secreta');
    log.warn('x'.repeat(ENTRY_MAX_CHARS + 50));
    expect(log.entries[0]).toMatchObject({
      level: 'info',
      kind: 'step',
      message: 'Conectando con password=[censurado]',
    });
    expect(log.entries[1]!.message).toHaveLength(ENTRY_MAX_CHARS);
    expect(log.entries[1]!.message.endsWith('…')).toBe(true);
    expect(onChange).toHaveBeenCalledTimes(2);
    expect(log.dirty).toBe(true);
  });

  it('con el tope alcanzado descarta líneas, pero el resultado cabe en la reserva', () => {
    const log = new RunLog(32 * 1024);
    for (let i = 0; i < 100; i++) log.add('info', 'output', 'y'.repeat(1000));
    const kept = log.entries.length;
    expect(kept).toBeLessThan(100);
    expect(log.dropped).toBe(100 - kept);
    expect(log.truncated).toBe(true);
    log.add('error', 'result', 'Fallido: algo');
    expect(log.entries.at(-1)).toMatchObject({
      kind: 'result',
      message: 'Fallido: algo',
    });
    expect(log.bytes).toBeLessThanOrEqual(32 * 1024);
  });

  it('runLog() devuelve el del job en curso (y nada fuera de un job)', async () => {
    expect(runLog()).toBeUndefined();
    const log = new RunLog(64 * 1024);
    await runInJobContext(
      {
        job: { id: 'j' } as Job,
        token: undefined,
        worker: 'w',
        signal: new AbortController().signal,
        attempt: 1,
        leases: [],
        log,
      },
      async () => {
        expect(runLog()).toBe(log);
      },
    );
  });
});

describe('describeCommand', () => {
  it('ssh: usuario@host:puerto y el comando remoto, sin rutas del tmpfs', () => {
    const args = [
      '-F',
      '/dev/null',
      '-i',
      '/dev/shm/infraward-ssh-abc/id',
      '-o',
      'UserKnownHostsFile=/dev/shm/infraward-ssh-abc/known_hosts',
      '-E',
      '/dev/shm/infraward-ssh-abc/ssh-1.log',
      '-o',
      'LogLevel=ERROR',
      '-p',
      '2222',
      '-l',
      'inventory',
      '--',
      '10.0.0.5',
      'sudo -n infraward-query os-release',
    ];
    expect(describeCommand('ssh', args)).toBe(
      'ssh inventory@10.0.0.5:2222 sudo -n infraward-query os-release',
    );
  });

  it('ssh: maestro y control', () => {
    expect(
      describeCommand('ssh', [
        '-o',
        'ControlMaster=yes',
        '-N',
        '-f',
        '-p',
        '22',
        '-l',
        'u',
        '--',
        'h',
      ]),
    ).toBe('ssh (conexión maestra) u@h:22');
    expect(
      describeCommand('ssh', [
        '-F',
        '/dev/null',
        '-O',
        'exit',
        '-p',
        '22',
        '-l',
        'u',
        '--',
        'h',
      ]),
    ).toBe('ssh -O exit u@h:22');
  });

  it('ssh-keyscan, ansible-playbook y otros', () => {
    expect(
      describeCommand('ssh-keyscan', [
        '-T',
        '10',
        '-p',
        '22',
        '-t',
        'ed25519',
        '--',
        'h.example',
      ]),
    ).toBe('ssh-keyscan h.example:22');
    expect(
      describeCommand('/usr/bin/ansible-playbook', [
        '-i',
        '/dev/shm/x/inventory.json',
        '-e',
        JSON.stringify({
          infraward_output: '/dev/shm/x/o.json',
          infraward_via: 'pct',
          script: 'muy largo',
        }),
        '/app/ansible/collect/collect.yml',
      ]),
    ).toBe('ansible-playbook collect.yml (conexión pct)');
    expect(
      describeCommand('trivy', [
        'rootfs',
        '--cache-dir',
        '/tmp/trivy/abc',
        '/dev/shm/root',
      ]),
    ).toBe('trivy rootfs --cache-dir …/abc …/root');
  });
});

describe('salida de ansible-playbook', () => {
  const stdout = [
    'PLAY [Recolección] ***',
    '',
    'TASK [Facts del sistema] ***',
    'ok: [target]',
    'TASK [Paquetes] ***',
    'fatal: [target]: FAILED! => {"changed": false, "msg": "No hay python", "rc": 127, "stderr": "sh: python3: not found\\n", "stdout": "datos"}',
    '...ignoring',
    '[WARNING]: Platform linux on host target is using the discovered Python',
    'PLAY RECAP ***',
    'target : ok=3 changed=0 unreachable=0 failed=1 skipped=0',
  ].join('\n');

  it('tareas, fallos (sin el JSON entero), avisos y resumen', () => {
    expect(ansibleLines(stdout)).toEqual([
      { level: 'debug', text: 'Tarea: Facts del sistema' },
      { level: 'debug', text: 'Tarea: Paquetes' },
      {
        level: 'error',
        text: 'fatal: [target]: FAILED! No hay python (código 127) stderr: sh: python3: not found',
      },
      {
        level: 'warn',
        text: '[WARNING]: Platform linux on host target is using the discovered Python',
      },
      {
        level: 'warn',
        text: 'Resumen: target : ok=3 changed=0 unreachable=0 failed=1 skipped=0',
      },
    ]);
  });

  it('un fallo sin JSON va tal cual; con JSON roto, solo la cabecera', () => {
    expect(ansibleFailure('fatal: [target]: UNREACHABLE!')).toBe(
      'fatal: [target]: UNREACHABLE!',
    );
    expect(ansibleFailure('fatal: [t]: FAILED! => {roto')).toBe(
      'fatal: [t]: FAILED!',
    );
  });
});

describe('tailLines', () => {
  it('las últimas líneas no vacías', () => {
    const text = Array.from({ length: 50 }, (_, i) => `l${i}`).join('\n\n');
    const lines = tailLines(text, 3);
    expect(lines).toEqual([
      '(47 líneas anteriores omitidas)',
      'l47',
      'l48',
      'l49',
    ]);
  });
});
