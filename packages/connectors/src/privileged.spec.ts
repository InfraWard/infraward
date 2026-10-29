import { describe, expect, it } from 'vitest';
import { DockerDiscoverer } from './docker/docker.js';
import type { HostExec, PrivilegedQuery } from './index.js';
import {
  chunks,
  expandQuery,
  helperArgv,
  INFRAWARD_QUERY_HELPER,
  isSudoDenial,
  MAX_INSPECT_ARGS,
  QueryRejectedError,
} from './privileged.js';

describe('privileged', () => {
  it('el ayudante recibe el nombre y los argumentos; nunca una ruta de pvesh', () => {
    expect(
      helperArgv({ name: 'pve-guest-config', args: ['qemu', 'pve', '200'] }),
    ).toEqual([
      INFRAWARD_QUERY_HELPER,
      'pve-guest-config',
      'qemu',
      'pve',
      '200',
    ]);
    expect(
      expandQuery({ name: 'pve-guest-config', args: ['qemu', 'pve', '200'] }),
    ).toEqual([
      'pvesh',
      'get',
      '/nodes/pve/qemu/200/config',
      '--output-format',
      'json',
    ]);
  });

  it.each<PrivilegedQuery>([
    { name: 'docker-save', args: ['-o', '/etc/passwd'] },
    { name: 'docker-save', args: [] },
    { name: 'pve-lxc-interfaces', args: ['pve', '../1'] },
    { name: 'ss', args: ['-a'] },
    { name: 'toString' as PrivilegedQuery['name'] },
    { name: 'pct-exec', args: ['100'] },
  ])('rechaza %j antes de conectar', (query) => {
    expect(() => helperArgv(query)).toThrow(QueryRejectedError);
  });

  it('trocea los inspect en grupos de MAX_INSPECT_ARGS', async () => {
    expect(chunks([1, 2, 3], 2)).toEqual([[1, 2], [3]]);
    const ids = Array.from({ length: MAX_INSPECT_ARGS + 10 }, (_, i) =>
      i.toString(16).padStart(64, '0'),
    );
    const sizes: number[] = [];
    const host: HostExec = {
      run: () => Promise.reject(new Error('no')),
      query: (q) => {
        helperArgv(q);
        if (q.name === 'docker-ps')
          return Promise.resolve({
            code: 0,
            stdout: ids.join('\n'),
            stderr: '',
          });
        if (q.name === 'docker-inspect-containers') sizes.push(q.args!.length);
        return Promise.resolve({ code: 0, stdout: '', stderr: '' });
      },
    };
    await new DockerDiscoverer().discover(
      { id: 'h', name: 'h', facts: {} },
      host,
    );
    expect(sizes).toEqual([MAX_INSPECT_ARGS, 10]);
  });

  it.each([
    ['sudo: a password is required', 1, true],
    ['sudo: interactive authentication is required', 1, true],
    ["sudo-rs: I'm sorry inventory. I'm afraid I can't do that", 1, true],
    ['infraward-query: rechazado: consulta desconocida', 64, true],
    ['', 64, true],
    ['Cannot connect to the Docker daemon', 1, false],
  ] as const)('isSudoDenial(%j, %i) = %s', (stderr, code, denied) => {
    expect(isSudoDenial(stderr, code)).toBe(denied);
  });
});
