import {
  expandQuery,
  INFRAWARD_QUERY_HELPER,
  NGINX_ROUTES_SCRIPT,
  PROCESS_PACKAGES_SCRIPT,
  SSHD_AUTH_SCRIPT,
  type PrivilegedQueryName,
} from '@infraward/connectors';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const PLAYBOOK = readFileSync(
  new URL('../../../../ansible/collect/collect.yml', import.meta.url),
  'utf8',
);

/**
 * El playbook pide al ayudante de root cada consulta por su nombre (`query`) y, en un CT por pct
 * exec, ejecuta el comando real (`argv`): los dos tienen que ser los de `PRIVILEGED_QUERIES`.
 */
describe('collect.yml', () => {
  const items = [
    ...PLAYBOOK.matchAll(
      /^ {8}- \{ key: (\S+), bin: (\S+), query: (\S+), argv: \[(.*)\] \}$/gm,
    ),
  ].map(([, key, bin, query, argv]) => ({
    key,
    bin,
    query: query as PrivilegedQueryName,
    argv: argv
      .split(', ')
      .map((a) => a.replace(/^"\{% raw %\}(.*)\{% endraw %\}"$/, '$1'))
      .map((a) =>
        a === '"{{ infraward_nginx_filter }}"'
          ? NGINX_ROUTES_SCRIPT
          : a === '"{{ infraward_process_filter }}"'
            ? PROCESS_PACKAGES_SCRIPT
            : a === '"{{ infraward_sshd_filter }}"'
              ? SSHD_AUTH_SCRIPT
              : a,
      ),
  }));

  it('cada consulta del ayudante es exactamente la de PRIVILEGED_QUERIES', () => {
    expect(items.map((i) => i.key)).toEqual([
      'pveversion',
      'plesk',
      'docker',
      'ss',
      'dmidecode',
      'nginx',
      'processes',
      'sshd',
    ]);
    for (const item of items) {
      expect(expandQuery({ name: item.query }), item.key).toEqual(item.argv);
      // nginx: `sh -c <filtro> sh nginx -T`; procesos: `sh -c <script> sh` (sin comando).
      expect(
        item.argv[0] === 'sh' ? (item.argv[4] ?? 'sh') : item.argv[0],
      ).toBe(item.bin);
    }
  });

  it('los scripts de nginx y de procesos se pueden pasar a Ansible sin que los interprete Jinja', () => {
    expect(NGINX_ROUTES_SCRIPT).not.toMatch(/\{\{|\{%|\{#/);
    expect(PROCESS_PACKAGES_SCRIPT).not.toMatch(/\{\{|\{%|\{#/);
    expect(SSHD_AUTH_SCRIPT).not.toMatch(/\{\{|\{%|\{#/);
  });

  it('por SSH, solo `sudo -n <ayudante> <consulta>`; nunca become', () => {
    expect(PLAYBOOK).toContain(
      `infraward_query_prefix: [sudo, -n, ${INFRAWARD_QUERY_HELPER}]`,
    );
    expect(PLAYBOOK).toContain(
      'argv: "{{ (infraward_query_prefix + [item.query]) if infraward_query_prefix else item.argv }}"',
    );
    expect(PLAYBOOK).not.toMatch(/^\s*become:/m);
  });
});
