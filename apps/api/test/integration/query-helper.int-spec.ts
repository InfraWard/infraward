import {
  expandQuery,
  parseProcessPackages,
  parseSshdAuth,
  INFRAWARD_QUERY_HELPER,
  LEGACY_PLESK_QUERY_HELPER,
  QUERY_REJECTED_EXIT,
  type PrivilegedQueryName,
} from '@infraward/connectors';
import {
  SSH_CA_CONFIG_VERSION,
  SUDOERS_VERSION,
} from '@infraward/shared-types';
import { generateSshKeyPair } from '@infraward/secrets';
import { randomUUID } from 'node:crypto';
import {
  embeddedCommand,
  keyComment,
  unenrollCommand,
} from '../../src/enrollment/commands.js';
import { EnrollScriptTemplate } from '../../src/enrollment/script-template.js';
import {
  ATTACKS,
  expectedCalls,
  HELPER_BINARIES,
  NGINX_SECRET_CONFIG,
  CONTAINER_PODMAN_UID,
  PODMAN_UID,
  PODMAN_USER,
  PVE_FILES,
  SAMPLES,
} from '../support/query-helper-cases.js';
import { startSshd, type SshdVariant, type TestSshd } from './support/sshd.js';

const CALLS = '/tmp/infraward-calls';

/**
 * El sudoers v4+ y el ayudante de root que instala el script de alta, con sudo clásico (Debian 13)
 * y con sudo-rs (Ubuntu 26.04): el usuario de inventario puede lanzar las consultas de la lista
 * cerrada, con el argv exacto, y nada más (ni otras rutas de pvesh, ni `docker save -o`, ni
 * comandos encadenados, ni ningún comando sin el ayudante). Los binarios de Docker, Proxmox, Plesk
 * y compañía son falsos (en /usr/local/bin, que va antes en el PATH del ayudante) y anotan su argv.
 */
describe.each<SshdVariant>(['debian', 'sudo-rs'])(
  'Ayudante de root con %s (integración)',
  (variant) => {
    let sshd: TestSshd;
    const template = EnrollScriptTemplate.load();
    const id = randomUUID();
    const { publicKey } = generateSshKeyPair(keyComment(id));

    /** Como `inventory`: `sudo -n <argv…>`, sin shell en medio. */
    const asInventory = (argv: string[]) =>
      sshd.exec(['runuser', '-u', 'inventory', '--', 'sudo', '-n', ...argv]);
    const calls = async () => {
      const r = await sshd.root(
        `[ -f ${CALLS} ] && cat ${CALLS}; rm -f ${CALLS}`,
      );
      return r.stdout ? r.stdout.split('\0').slice(0, -1) : null;
    };

    beforeAll(async () => {
      sshd = await startSshd(variant);
      const stubs = HELPER_BINARIES.map(
        (name) =>
          `printf '#!/bin/sh\\nprintf "%%s\\\\0" ${name} "$@" > ${CALLS}\\n' > /usr/local/bin/${name}; chmod 755 /usr/local/bin/${name}`,
      ).join('; ');
      const pve = PVE_FILES.map(
        (f) => `mkdir -p "$(dirname /etc/pve/${f})" && touch /etc/pve/${f}`,
      ).join('; ');
      // Un ayudante de Plesk de la v3 que la actualización tiene que borrar.
      const legacy = `mkdir -p /usr/local/libexec/infraward && printf '#!/bin/sh\\n' > ${LEGACY_PLESK_QUERY_HELPER} && chmod 755 ${LEGACY_PLESK_QUERY_HELPER}`;
      // Podman rootless (v8): `nobody` en la lista de usuarios (el alta sin --podman-users no la toca).
      const podmanUsers = `mkdir -p /etc/infraward && printf '%s\\n' ${PODMAN_USER} > /etc/infraward/podman-users`;
      const setup = await sshd.root(
        `${stubs}; ${pve}; ${legacy}; ${podmanUsers}`,
      );
      expect(setup.code, setup.stderr).toBe(0);

      const script = template.render({
        mode: 'embedded',
        apiUrl: '',
        token: '',
        authMode: 'static_key',
        publicKey,
        keyComment: keyComment(id),
        sudoersVersion: SUDOERS_VERSION,
        caKeys: [],
        caVersion: SSH_CA_CONFIG_VERSION,
        issuedAt: Math.floor(Date.now() / 1000),
      });
      const r = await sshd.root(embeddedCommand(script));
      expect(r.code, r.stderr).toBe(0);
    }, 600_000);
    afterAll(async () => {
      await sshd?.stop();
    });

    it(`es ${variant === 'sudo-rs' ? 'sudo-rs' : 'sudo clásico'}`, async () => {
      const v = await sshd.root('sudo -V 2>&1 | head -n 1');
      expect(v.stdout).toMatch(
        variant === 'sudo-rs' ? /^sudo-rs / : /^Sudo version 1\.9\./,
      );
    });

    it('sudoers v4: visudo lo acepta y solo permite el ayudante', async () => {
      // Nuestro fichero (en la imagen de Ubuntu, el /etc/sudoers base viene con 0644 y
      // `visudo -c` sin más se queja de él, no del nuestro).
      const check = await sshd.root(
        'visudo -cf /etc/sudoers.d/infraward-inventory',
      );
      expect(check.code, check.stdout + check.stderr).toBe(0);
      expect(
        (
          await sshd.root("stat -c '%a' /etc/sudoers.d/infraward-inventory")
        ).stdout.trim(),
      ).toBe('440');
      const file = (await sshd.root('cat /etc/sudoers.d/infraward-inventory'))
        .stdout;
      expect(file).toContain(`# infraward-sudoers-version: ${SUDOERS_VERSION}`);
      const rules = file
        .split('\n')
        .filter((l) => l && !l.startsWith('#') && !l.startsWith('Defaults'));
      expect(rules).toEqual([
        `inventory ALL=(root) NOPASSWD: ${INFRAWARD_QUERY_HELPER}`,
      ]);
      expect(
        (await sshd.root('cat /etc/infraward/sudoers-version')).stdout.trim(),
      ).toBe(String(SUDOERS_VERSION));
    });

    it('el ayudante es de root (0755) e inventory no puede tocarlo; el de la v3 se ha borrado', async () => {
      expect(
        (
          await sshd.root(
            `stat -c '%U:%G %a' ${INFRAWARD_QUERY_HELPER} /usr/local/libexec/infraward`,
          )
        ).stdout
          .trim()
          .split('\n'),
      ).toEqual(['root:root 755', 'root:root 755']);
      for (const attempt of [
        `echo id >> ${INFRAWARD_QUERY_HELPER}`,
        `cp /bin/sh ${INFRAWARD_QUERY_HELPER}`,
        `mv ${INFRAWARD_QUERY_HELPER} /tmp/x`,
        `touch /usr/local/libexec/infraward/otro`,
      ]) {
        const r = await sshd.exec([
          'runuser',
          '-u',
          'inventory',
          '--',
          'sh',
          '-c',
          attempt,
        ]);
        expect(r.code, attempt).not.toBe(0);
      }
      expect(
        (await sshd.root(`test -e ${LEGACY_PLESK_QUERY_HELPER}`)).code,
      ).not.toBe(0);
    });

    it('todas las consultas de la lista pasan por sudo con el argv exacto', async () => {
      for (const [name, list] of Object.entries(SAMPLES)) {
        // El uid de nobody de la máquina que lanza el test puede no ser el del contenedor (macOS).
        for (const args of list.map((l) =>
          l.map((a) => (a === PODMAN_UID ? CONTAINER_PODMAN_UID : a)),
        )) {
          const r = await asInventory([INFRAWARD_QUERY_HELPER, name, ...args]);
          expect(r.code, `${name} ${args.join(' ')}: ${r.stderr}`).toBe(0);
          expect(await calls(), name).toEqual(
            expectedCalls(
              expandQuery({ name: name as PrivilegedQueryName, args }),
              'real',
            ),
          );
        }
      }
    });

    it('nginx -T por sudo: el filtro (sh y awk del sistema) no deja salir ningún secreto', async () => {
      const conf = Buffer.from(NGINX_SECRET_CONFIG).toString('base64');
      const setup = await sshd.root(
        `printf '%s' '${conf}' | base64 -d > /tmp/nginx-test.conf && printf '#!/bin/sh\\ncat /tmp/nginx-test.conf\\n' > /usr/local/bin/nginx`,
      );
      expect(setup.code, setup.stderr).toBe(0);
      const r = await asInventory([INFRAWARD_QUERY_HELPER, 'nginx-routes']);
      expect(r.code, r.stderr).toBe(0);
      expect(r.stdout).not.toMatch(/centinela|Authorization|htpasswd|usuario|ssl_certificate|\$token/);
      expect(r.stdout.split('\n')).toEqual(
        expect.arrayContaining([
          'N app.example.com',
          'P proxy_pass http://127.0.0.1:8080',
          'V $server 192.168.1.20',
        ]),
      );
    });

    it('procesos por sudo (v6): el sshd real con el paquete de su ejecutable y sus librerías (dpkg del sistema)', async () => {
      // El `ss` falso anuncia el sshd de verdad del contenedor; el resto (/proc, dpkg) es real.
      const setup = await sshd.root(
        `pid=$(for d in /proc/[0-9]*; do [ "$(cat $d/comm 2>/dev/null)" = sshd ] && echo \${d#/proc/} && break; done) && [ -n "$pid" ] && printf '#!/bin/sh\\necho "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\\\\"sshd\\\\",pid=%s,fd=3))"\\n' "$pid" > /usr/local/bin/ss && chmod 755 /usr/local/bin/ss`,
      );
      expect(setup.code, setup.stderr).toBe(0);
      const r = await asInventory([INFRAWARD_QUERY_HELPER, 'process-packages']);
      expect(r.code, r.stderr).toBe(0);
      const [proc] = parseProcessPackages(r.stdout);
      expect(proc, r.stdout).toMatchObject({ name: 'sshd', exePackage: 'openssh-server' });
      expect(proc!.libPackages).toEqual(expect.arrayContaining([expect.stringMatching(/^libc6/)]));
      // Solo nombres: ni rutas ni entorno.
      expect(r.stdout).not.toMatch(/\/usr|\/lib|PATH=/);
      await sshd.root(`rm -f /usr/local/bin/ss; printf '#!/bin/sh\\nprintf "%%s\\\\0" ss "$@" > ${CALLS}\\n' > /usr/local/bin/ss; chmod 755 /usr/local/bin/ss`);
    });

    it('sshd -T por sudo (v7): la configuración efectiva del sshd real, solo las tres opciones', async () => {
      const stub = await sshd.root('mv /usr/local/bin/sshd /usr/local/bin/sshd.stub');
      expect(stub.code, stub.stderr).toBe(0);
      try {
        const before = await asInventory([INFRAWARD_QUERY_HELPER, 'sshd-auth']);
        expect(before.code, before.stderr).toBe(0);
        expect(parseSshdAuth(before.stdout), before.stdout).not.toBeNull();
        // Un drop-in que abre root por contraseña (primero en orden: en sshd gana el primero).
        const open = await sshd.root(
          "printf 'PermitRootLogin yes\\nPasswordAuthentication yes\\nBanner /etc/centinela\\n' > /etc/ssh/sshd_config.d/00-aaa-test.conf",
        );
        expect(open.code, open.stderr).toBe(0);
        const r = await asInventory([INFRAWARD_QUERY_HELPER, 'sshd-auth']);
        expect(r.code, r.stderr).toBe(0);
        expect(parseSshdAuth(r.stdout)).toMatchObject({
          permitRootLogin: 'yes',
          passwordAuthentication: true,
        });
        expect(r.stdout.trim().split('\n')).toHaveLength(3);
        expect(r.stdout).not.toMatch(/centinela|hostkey|\/etc/);
      } finally {
        await sshd.root(
          'rm -f /etc/ssh/sshd_config.d/00-aaa-test.conf; mv /usr/local/bin/sshd.stub /usr/local/bin/sshd',
        );
      }
    });

    it('rechaza cada intento de inyección a través de sudo sin ejecutar nada', async () => {
      for (const [name, args] of ATTACKS) {
        const r = await asInventory([INFRAWARD_QUERY_HELPER, ...args]);
        expect(r.code, `${name}: ${r.stderr}`).toBe(QUERY_REJECTED_EXIT);
        expect(r.stderr, name).toMatch(/infraward-query: rechazado: /);
        expect(await calls(), name).toBeNull();
      }
    });

    it('sin el ayudante, sudo deniega cualquier otro comando', async () => {
      for (const argv of [
        ['/usr/local/bin/docker', 'ps'],
        ['docker', 'save', '-o', '/etc/x', 'sha256:x'],
        ['/usr/local/bin/pvesh', 'get', '/access/users'],
        ['/usr/local/bin/pct', 'exec', '100', '--', 'id'],
        ['/bin/sh', '-c', 'id'],
        ['/usr/bin/id'],
        [LEGACY_PLESK_QUERY_HELPER, 'domains'],
        [`${INFRAWARD_QUERY_HELPER}/../../../../bin/sh`],
      ]) {
        const r = await asInventory(argv);
        expect(r.code, argv.join(' ')).not.toBe(0);
        expect(await calls(), argv.join(' ')).toBeNull();
      }
    });

    it('la baja quita el sudoers y el ayudante', async () => {
      const r = await sshd.root(unenrollCommand(id, 'inventory'));
      expect(r.code, r.stderr).toBe(0);
      expect(
        (
          await sshd.root(
            `ls /etc/sudoers.d/infraward-inventory ${INFRAWARD_QUERY_HELPER} /usr/local/libexec/infraward 2>&1`,
          )
        ).stdout,
      ).not.toMatch(/^\/(etc|usr)/m);
    });
  },
);
