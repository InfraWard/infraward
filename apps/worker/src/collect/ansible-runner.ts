import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  INFRAWARD_QUERY_HELPER,
  NGINX_ROUTES_SCRIPT,
  PROCESS_PACKAGES_SCRIPT,
  PODMAN_USERS_SCRIPT,
  SSHD_AUTH_SCRIPT,
  isSudoDenial,
  type CollectTarget,
} from '@infraward/connectors';
import type { AssetConnection } from '@infraward/shared-types';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { EnvironmentVariables } from '../config/env.validation.js';
import type { ScannedHostKey } from '../ssh/host-keys.js';
import {
  PROCESS_RUNNER,
  shellQuote,
  SshClient,
  sshOptions,
  type ProcessResult,
  type ProcessRunner,
  type SshIdentity,
} from '../ssh/ssh-client.js';
import type { RawCollection } from './normalize.js';

/** `ansible/` del monorepo (desde `src/collect/` y desde `dist/collect/`). */
const DEFAULT_ANSIBLE_DIR = fileURLToPath(
  new URL('../../../../ansible', import.meta.url),
);

/** Tamaño máximo del JSON de salida (los paquetes de un servidor grande ocupan pocos MiB). */
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

/** Valores que van al inventario de Ansible: nunca deben poder interpretarse como plantilla. */
const SAFE_HOST = /^[A-Za-z0-9.:-]{1,253}$/;
const SAFE_USER = /^[a-z_][a-z0-9_-]{0,31}$/;

/** Fallo de la recolección con un mensaje apto para guardarse y mostrarse (sin secretos). */
export class CollectionError extends Error {}

/**
 * Lanza `ansible/collect/collect.yml` contra un servidor. Usa la misma clave temporal, el mismo
 * known_hosts fijado y las mismas opciones de `ssh` que la verificación del alta
 * (`SshClient.withMaterial`): todo vive en un directorio 700 en tmpfs que se borra siempre.
 * Ninguna variable de Ansible contiene el secreto, solo la ruta del fichero de la clave.
 */
@Injectable()
export class AnsibleRunner {
  private readonly playbookBin: string;
  private readonly ansibleDir: string;
  private readonly timeoutSeconds: number;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    private readonly ssh: SshClient,
    @Inject(PROCESS_RUNNER) private readonly run: ProcessRunner,
  ) {
    this.playbookBin = config.get('ANSIBLE_PLAYBOOK_BIN', { infer: true });
    this.ansibleDir = resolve(
      config.get('ANSIBLE_DIR', { infer: true }) ?? DEFAULT_ANSIBLE_DIR,
    );
    this.timeoutSeconds = config.get('COLLECT_TIMEOUT', { infer: true });
  }

  /**
   * Sin `via`, recoge el servidor `target`. Con `via` (`pct`), `target` es el nodo Proxmox y se
   * recoge el CT `via.vmid` desde él con la conexión `infraward_pct` (sin SSH en el CT).
   */
  async collect(
    target: AssetConnection,
    identity: SshIdentity,
    hostKey: ScannedHostKey,
    via?: CollectTarget,
  ): Promise<RawCollection> {
    if (!SAFE_HOST.test(target.host) || !SAFE_USER.test(target.user))
      throw new CollectionError(
        'Host o usuario de conexión con caracteres no permitidos',
      );
    if (via && !(Number.isInteger(via.vmid) && via.vmid >= 100))
      throw new CollectionError('vmid de CT no válido');
    return this.ssh.withMaterial(
      target,
      identity,
      hostKey,
      async (material) => {
        const { dir } = material;
        const inventory = join(dir, 'inventory.json');
        const output = join(dir, 'collect.json');
        await mkdir(join(dir, 'ansible'), { mode: 0o700 });
        await mkdir(join(dir, 'tmp'), { mode: 0o700 });
        const sshArgs = sshOptions(
          material,
          hostKey,
          this.ssh.connectTimeoutSeconds,
        );
        await writeFile(
          inventory,
          JSON.stringify({
            all: {
              hosts: {
                target: {
                  ansible_host: target.host,
                  ansible_port: target.port,
                  ansible_user: target.user,
                  ansible_ssh_common_args: sshArgs.map(shellQuote).join(' '),
                  ...(via && {
                    ansible_connection: 'infraward_pct',
                    infraward_pct_vmid: via.vmid,
                    // `pct exec` sin tty: los módulos van por stdin.
                    ansible_ssh_use_tty: false,
                  }),
                },
              },
            },
          }),
          { mode: 0o600, flag: 'wx' },
        );
        const result = await this.run(
          this.playbookBin,
          [
            '-i',
            inventory,
            '-e',
            // Por `-e`: ganan a los `vars` del play (que son los valores por defecto).
            JSON.stringify({
              infraward_output: output,
              infraward_via: via ? 'pct' : 'ssh',
              // En el CT, `pct exec` ya es root: el comando real, sin sudo ni ayudante (el CT
              // no tiene el sudoers de InfraWard).
              infraward_query_prefix: via
                ? []
                : ['sudo', '-n', INFRAWARD_QUERY_HELPER],
              // En un CT, el filtro de nginx -T se ejecuta dentro (por SSH, en el ayudante).
              infraward_nginx_filter: NGINX_ROUTES_SCRIPT,
              infraward_process_filter: PROCESS_PACKAGES_SCRIPT,
              infraward_sshd_filter: SSHD_AUTH_SCRIPT,
              infraward_podman_users_filter: PODMAN_USERS_SCRIPT,
            }),
            join(this.ansibleDir, 'collect', 'collect.yml'),
          ],
          this.timeoutSeconds * 1000,
          {
            maxBuffer: 16 * 1024 * 1024,
            env: {
              // Ansible exige un locale UTF-8.
              LC_ALL: 'C.UTF-8',
              HOME: dir,
              ANSIBLE_CONFIG: join(this.ansibleDir, 'collect', 'ansible.cfg'),
              ANSIBLE_HOME: join(dir, 'ansible'),
              ANSIBLE_LOCAL_TEMP: join(dir, 'tmp'),
              ANSIBLE_NOCOLOR: '1',
            },
          },
        );
        if (result.code !== 0)
          throw new CollectionError(describeFailure(result, via));
        const size = await stat(output).catch(() => null);
        if (!size)
          throw new CollectionError('Ansible terminó sin dejar el resultado');
        if (size.size > MAX_OUTPUT_BYTES)
          throw new CollectionError(
            'El resultado de la recolección es demasiado grande',
          );
        try {
          return JSON.parse(await readFile(output, 'utf8')) as RawCollection;
        } catch {
          throw new CollectionError(
            'El resultado de la recolección no es JSON válido',
          );
        }
      },
    );
  }
}

/**
 * Mensaje de error a partir de la salida de Ansible: el `msg` de la primera línea `fatal:`
 * (recortado), traducido en los casos conocidos. Nunca se devuelve la salida entera.
 */
export function describeFailure(
  result: ProcessResult,
  via?: CollectTarget,
): string {
  if (result.code === null) return 'La recolección superó el tiempo máximo';
  const fatal = `${result.stdout}\n${result.stderr}`
    .split('\n')
    .find((l) => /^fatal: \[|^ERROR!?:? /.test(l.trim()));
  let msg = '';
  if (fatal) {
    const json = fatal.indexOf('=> {');
    if (json >= 0) {
      try {
        const parsed = JSON.parse(fatal.slice(json + 3)) as { msg?: unknown };
        msg = typeof parsed.msg === 'string' ? parsed.msg : '';
      } catch {
        msg = '';
      }
    } else {
      msg = fatal.trim();
    }
  }
  if (
    /Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(
      msg,
    )
  )
    return 'La host key del servidor no coincide con la fijada; posible suplantación';
  if (via && /not running/i.test(msg))
    return `El CT ${via.vmid} no está en marcha`;
  if (via && isSudoDenial(msg))
    return 'El sudoers del nodo no permite pct exec (hace falta el ayudante de la v4): vuelve a ejecutar el script de alta en el nodo';
  if (/python/i.test(msg) && /not found|no such file|no python/i.test(msg))
    return via
      ? `Ansible necesita python3 dentro del CT ${via.vmid}: instálalo y reintenta`
      : 'Ansible necesita python3 en el servidor: instálalo y reintenta';
  if (/Permission denied \(publickey/i.test(msg))
    return 'El servidor rechazó la clave de InfraWard (Permission denied)';
  if (/UTF-8/.test(msg) && /locale/i.test(msg))
    return 'Ansible necesita un locale UTF-8 en el worker';
  if (/Failed to create temporary directory/i.test(msg))
    // `[target -> localhost]`: la tarea delegada en el worker (el JSON del resultado).
    return /^fatal: \[[^\]]*-> localhost\]/.test(fatal?.trim() ?? '')
      ? 'El worker no pudo crear el directorio temporal de Ansible (raíz de solo lectura o sin espacio en el tmpfs del job)'
      : 'Ansible no pudo crear su directorio temporal en el servidor: comprueba que el home del usuario de InfraWard existe y es suyo';
  const clean = msg.replace(/\s+/g, ' ').trim();
  return clean
    ? `Fallo en la recolección: ${clip(clean, MAX_FAILURE_CHARS)}`
    : `Fallo en la recolección (código ${result.code})`;
}

/** Tope del mensaje genérico: cabe en el log y en `failedReason` sin volcar la salida entera. */
const MAX_FAILURE_CHARS = 500;

/** Recorta por palabras y marca el corte con «…» (un corte a secas parece el mensaje entero). */
function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const space = cut.lastIndexOf(' ');
  return `${(space > max * 0.8 ? cut.slice(0, space) : cut).trimEnd()}…`;
}
