import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  helperArgv,
  type HostExec,
  type PrivilegedQuery,
} from '@infraward/connectors';
import { ENROLL_SSH_USER, type AssetConnection } from '@infraward/shared-types';
import { generateSshKeyPair } from '@infraward/secrets';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createWriteStream, existsSync } from 'node:fs';
import { mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { EnvironmentVariables } from '../config/env.validation.js';
import { currentJob } from '../jobs/job-context.js';
import {
  hostKeyAlgorithms,
  knownHostsLine,
  parseKeyscan,
  type ScannedHostKey,
} from './host-keys.js';
import { spawnPty, type PtyProcess } from './pty-bridge.js';

export interface ProcessResult {
  stdout: string;
  stderr: string;
  /** Código de salida; null si el proceso no terminó (timeout o señal). */
  code: number | null;
}

export interface ProcessOptions {
  /** Variables añadidas al entorno mínimo (`PATH`, `LC_ALL`). Nunca secretos. */
  env?: Record<string, string>;
  /** Límite de stdout/stderr en bytes (1 MiB por defecto). */
  maxBuffer?: number;
  /**
   * El proceso deja un hijo en segundo plano (`ssh -f`): sin stdio (el hijo heredaría las
   * tuberías y nunca se daría por terminado) y se resuelve al salir el proceso, sin salida.
   */
  background?: boolean;
}

/** Ejecuta un binario con argumentos en array (nunca por shell). Se sustituye en los tests. */
export type ProcessRunner = (
  file: string,
  args: string[],
  timeoutMs: number,
  options?: ProcessOptions,
) => Promise<ProcessResult>;

export const PROCESS_RUNNER = Symbol('PROCESS_RUNNER');

/**
 * Señal de aborto del job en curso para un proceso que se lanza ahora (DESIGN §20). Lo que se
 * lanza después del aborto es limpieza (cerrar el maestro SSH, borrar temporales): va sin señal.
 */
function jobSignal(): AbortSignal | undefined {
  const signal = currentJob()?.signal;
  return signal && !signal.aborted ? signal : undefined;
}

/**
 * Mata el grupo de procesos del hijo (se lanza con `detached`: ansible-playbook, ssh, trivy y sus
 * propios hijos) al abortarse el job o agotarse el tiempo. Devuelve la función que lo desengancha.
 */
function killGroupOn(
  child: ChildProcess,
  signal: AbortSignal | undefined,
  timeoutMs: number,
  onTimeout?: () => void,
): () => void {
  const kill = () => {
    if (child.pid === undefined || child.exitCode !== null) return;
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {
      child.kill('SIGKILL');
    }
  };
  const timer = setTimeout(() => {
    onTimeout?.();
    kill();
  }, timeoutMs);
  signal?.addEventListener('abort', kill, { once: true });
  return () => {
    clearTimeout(timer);
    signal?.removeEventListener('abort', kill);
  };
}

export const execFileRunner: ProcessRunner = (
  file,
  args,
  timeoutMs,
  options = {},
) =>
  new Promise((resolve) => {
    // Entorno mínimo: sin SSH_AUTH_SOCK ni configuración del usuario del worker.
    const env = {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      LC_ALL: 'C',
      ...options.env,
    };
    if (options.background) {
      // El maestro SSH sobrevive al proceso que lo lanza: ni grupo ni señal (lo cierra su dueño).
      const child = spawn(file, args, { stdio: 'ignore', env });
      const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
      child.on('error', () => {
        clearTimeout(timer);
        resolve({ stdout: '', stderr: '', code: null });
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        resolve({ stdout: '', stderr: '', code });
      });
      return;
    }
    let detach = () => undefined as void;
    const execOptions = {
      encoding: 'utf8' as const,
      maxBuffer: options.maxBuffer ?? 1024 * 1024,
      env,
      // Grupo propio: al abortar o agotarse el tiempo se matan también sus hijos (execFile se lo
      // pasa a spawn, aunque sus tipos no lo declaren).
      detached: true,
    };
    const child = execFile(
      file,
      args,
      execOptions,
      (error, stdout, stderr) => {
        detach();
        const code =
          error === null
            ? 0
            : typeof error.code === 'number'
              ? error.code
              : null;
        resolve({ stdout, stderr, code });
      },
    );
    detach = killGroupOn(child, jobSignal(), timeoutMs);
  });

/** Límites de una descarga a disco. */
export interface StreamLimits {
  maxBytes: number;
  timeoutMs: number;
}

/** Resultado de volcar la salida estándar de un proceso a un fichero. */
export interface StreamResult {
  /** Código de salida; null si no terminó (límite, timeout o señal). */
  code: number | null;
  /** Bytes escritos en el fichero. */
  bytes: number;
  /** Stderr recortado (máx. 64 KiB). */
  stderr: string;
  /** Límite que cortó la descarga (el proceso se mata), o null. */
  limit: 'size' | 'time' | null;
}

/** Lanza un binario y vuelca su stdout en `dest` sin pasar por memoria. Se sustituye en los tests. */
export type ProcessStreamer = (
  file: string,
  args: string[],
  dest: string,
  limits: StreamLimits,
) => Promise<StreamResult>;

export const PROCESS_STREAMER = Symbol('PROCESS_STREAMER');

const MAX_STREAM_STDERR = 64 * 1024;

export const spawnStreamer: ProcessStreamer = (file, args, dest, limits) =>
  new Promise((resolve, reject) => {
    const out = createWriteStream(dest, { flags: 'wx', mode: 0o600 });
    const child = spawn(file, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LC_ALL: 'C' },
      detached: true,
    });
    let bytes = 0;
    let stderr = '';
    let limit: StreamResult['limit'] = null;
    const stop = (why: 'size' | 'time') => {
      if (limit) return;
      limit = why;
      child.kill('SIGKILL');
    };
    // Tiempo agotado o job abortado (p. ej. un docker save al parar la réplica): fuera el grupo.
    const detach = killGroupOn(child, jobSignal(), limits.timeoutMs, () => {
      limit ??= 'time';
    });
    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > limits.maxBytes) stop('size');
    });
    child.stdout.pipe(out);
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < MAX_STREAM_STDERR)
        stderr += chunk.toString('utf8').slice(0, MAX_STREAM_STDERR);
    });
    // Si no se puede escribir (fichero existente, disco lleno…), se corta la descarga.
    let outError: Error | null = null;
    out.on('error', (error) => {
      outError ??= error;
      child.kill('SIGKILL');
    });
    const written = new Promise<void>((done) => out.on('close', done));
    child.on('error', (error) => {
      detach();
      out.destroy();
      reject(error);
    });
    child.on('close', (code) => {
      detach();
      void written.then(() =>
        outError
          ? reject(outError)
          : resolve({ code: limit ? null : code, bytes, stderr, limit }),
      );
    });
  });

/**
 * `HostExec` del worker: además de comandos, descargas a disco de una consulta del ayudante de
 * root (p. ej. `docker-save`) o de un comando sin privilegios (p. ej. `cat` de las BDs de
 * paquetes, legibles por todos).
 */
export interface StreamingHostExec extends HostExec {
  streamToFile(
    query: PrivilegedQuery,
    dest: string,
    limits: StreamLimits,
  ): Promise<StreamResult>;
  streamArgvToFile(
    argv: string[],
    dest: string,
    limits: StreamLimits,
  ): Promise<StreamResult>;
}

/** Error de conexión con un mensaje apto para guardarse y mostrarse (nunca lleva secretos). */
export class SshError extends Error {}

/**
 * Con qué se autentica el worker:
 * - `key`: clave privada estática del asset (resuelta del proveedor de secretos).
 * - `certificate`: par efímero generado en el tmpfs del job y firmado por la CA SSH del
 *   proveedor (`sign`); el certificado dura `ttlSeconds` y se vuelve a firmar antes de abrir una
 *   conexión si le quedan menos de `renewMarginSeconds`.
 */
export type SshIdentity =
  | { kind: 'key'; privateKey: string }
  | {
      kind: 'certificate';
      sign(publicKey: string): Promise<string>;
      ttlSeconds: number;
      renewMarginSeconds: number;
    };

/**
 * ControlPersist del maestro: cuánto sigue vivo sin clientes. Entre tareas de Ansible no hay
 * huecos tan largos; si el worker muriera, el maestro no se quedaría para siempre.
 */
const CONTROL_PERSIST_SECONDS = 120;

/**
 * Longitud máxima de la ruta del socket del maestro: los sockets unix admiten 104 bytes (macOS)
 * o 108 (Linux) y ssh le añade un sufijo temporal de 17 al crearlo.
 */
const MAX_CONTROL_PATH = 80;

/** Ficheros temporales de una conexión: viven en un directorio 700 en tmpfs. */
export interface SshMaterial {
  /** Directorio del job (700); se borra entero al terminar. */
  dir: string;
  /** Clave privada (600): la estática o la efímera del job. */
  keyFile: string;
  /** Certificado de la clave efímera (modo CA); null con clave estática. */
  certFile: string | null;
  /** known_hosts con solo la host key fijada. */
  knownHosts: string;
  /**
   * Socket del ControlMaster del job: todas las conexiones del job van por la del maestro (una
   * sola autenticación, y el certificado solo se comprueba ahí).
   */
  controlPath: string;
  /** Antes de abrir una conexión nueva: firma otro certificado si al actual le queda poco. */
  beforeConnect(): Promise<void>;
}

/**
 * Opciones de `ssh` comunes a la verificación y a Ansible: solo la clave (y su certificado)
 * indicada, sin agente ni contraseña, host key fijada (`StrictHostKeyChecking=yes`, nunca `no`
 * ni `accept-new`) y multiplexadas sobre el maestro del job.
 */
export function sshOptions(
  material: SshMaterial,
  hostKey: ScannedHostKey,
  timeoutSeconds: number,
  multiplex = true,
): string[] {
  return [
    '-F',
    '/dev/null',
    '-i',
    material.keyFile,
    ...[
      ...(material.certFile ? [`CertificateFile=${material.certFile}`] : []),
      ...(multiplex
        ? ['ControlMaster=auto', `ControlPath=${material.controlPath}`]
        : ['ControlMaster=no', 'ControlPath=none']),
      'IdentitiesOnly=yes',
      'IdentityAgent=none',
      'BatchMode=yes',
      'PasswordAuthentication=no',
      'KbdInteractiveAuthentication=no',
      'StrictHostKeyChecking=yes',
      `UserKnownHostsFile=${material.knownHosts}`,
      'GlobalKnownHostsFile=/dev/null',
      'UpdateHostKeys=no',
      `HostKeyAlgorithms=${hostKeyAlgorithms(hostKey)}`,
      `ConnectTimeout=${timeoutSeconds}`,
    ].flatMap((o) => ['-o', o]),
  ];
}

/**
 * Conexiones SSH del worker con el binario `ssh` (el mismo que usará Ansible). La clave privada
 * (estática, o efímera con su certificado en modo CA) solo existe en un fichero 600 dentro de un
 * directorio 700 en tmpfs, que se borra siempre. La host key se fija en un known_hosts temporal
 * con solo la clave elegida y `StrictHostKeyChecking=yes`: nunca se acepta una clave sin
 * comprobar. Cada job abre un ControlMaster: una sola autenticación por job.
 */
@Injectable()
export class SshClient {
  private readonly logger = new Logger(SshClient.name);
  private readonly tmpBase: string;
  private readonly timeoutSeconds: number;

  constructor(
    config: ConfigService<EnvironmentVariables, true>,
    @Inject(PROCESS_RUNNER) private readonly run: ProcessRunner,
    @Optional()
    @Inject(PROCESS_STREAMER)
    private readonly streamer: ProcessStreamer = spawnStreamer,
  ) {
    this.timeoutSeconds = config.get('SSH_CONNECT_TIMEOUT', { infer: true });
    const configured = config.get('WORKER_TMP_DIR', { infer: true });
    if (configured) {
      this.tmpBase = configured;
    } else if (existsSync('/dev/shm')) {
      this.tmpBase = '/dev/shm';
    } else {
      this.tmpBase = tmpdir();
      this.logger.warn(
        `No hay /dev/shm: las claves temporales irán a ${this.tmpBase} (define WORKER_TMP_DIR con un tmpfs)`,
      );
    }
  }

  /**
   * Host keys que ofrece el servidor (sin autenticarse). `types`: solo esos tipos (cada tipo es
   * una conexión sin autenticar, y OpenSSH ≥ 9.8 penaliza las que se acumulan:
   * `PerSourcePenalties noauth`).
   */
  async scanHostKeys(
    host: string,
    port: number,
    types: readonly string[] = ['ed25519', 'ecdsa', 'rsa'],
  ): Promise<ScannedHostKey[]> {
    const result = await this.run(
      'ssh-keyscan',
      [
        '-T',
        String(this.timeoutSeconds),
        '-p',
        String(port),
        '-t',
        types.join(','),
        '--',
        host,
      ],
      (this.timeoutSeconds + 5) * 1000,
    );
    const keys = parseKeyscan(result.stdout);
    if (keys.length === 0) {
      throw new SshError(
        `No se pudo leer la host key de ${host}:${port}${describe(result)}`,
      );
    }
    return keys;
  }

  get connectTimeoutSeconds(): number {
    return this.timeoutSeconds;
  }

  /**
   * Prepara la clave (la estática, o una efímera con su certificado) y el known_hosts en un
   * directorio 700 en tmpfs, abre el ControlMaster del job, llama a `fn` y, pase lo que pase,
   * cierra el maestro y borra el directorio (también si `fn` falla o se agota el tiempo). Con
   * `master: false` (la terminal: una sola conexión) no hay maestro.
   */
  async withMaterial<T>(
    target: AssetConnection,
    identity: SshIdentity,
    hostKey: ScannedHostKey,
    fn: (material: SshMaterial) => Promise<T>,
    options: { master?: boolean; prefix?: string } = {},
  ): Promise<T> {
    const master = options.master ?? true;
    const dir = await mkdtemp(join(this.tmpBase, options.prefix ?? 'infraward-ssh-'));
    let socketDir: string | undefined;
    try {
      const keyFile = join(dir, 'id');
      const certFile =
        identity.kind === 'certificate' ? join(dir, 'id-cert.pub') : null;
      let privateKey: string;
      let beforeConnect = () => Promise.resolve();
      if (identity.kind === 'certificate') {
        // Par efímero: solo existe en este directorio y mientras dure el job.
        const pair = generateSshKeyPair('infraward-efimera');
        privateKey = pair.privateKey;
        let validUntil = 0;
        beforeConnect = async () => {
          if (Date.now() < validUntil - identity.renewMarginSeconds * 1000)
            return;
          const signedAt = Date.now();
          const certificate = await identity.sign(pair.publicKey);
          // rename atómico: un ssh que arranque ahora lee el certificado entero.
          await writeFile(`${certFile!}.tmp`, `${certificate}\n`, {
            mode: 0o600,
          });
          await rename(`${certFile!}.tmp`, certFile!);
          validUntil = signedAt + identity.ttlSeconds * 1000;
        };
      } else {
        privateKey = identity.privateKey;
      }
      // El socket va con el resto si la ruta cabe (en /dev/shm siempre); si no (p. ej. el temporal
      // de macOS), en un directorio 700 corto aparte. El socket no contiene secretos.
      if (join(dir, 'cm').length > MAX_CONTROL_PATH)
        socketDir = await mkdtemp('/tmp/iw-');
      const material: SshMaterial = {
        dir,
        keyFile,
        certFile,
        knownHosts: join(dir, 'known_hosts'),
        controlPath: join(socketDir ?? dir, 'cm'),
        beforeConnect,
      };
      await writeFile(keyFile, privateKey, { mode: 0o600, flag: 'wx' });
      await writeFile(
        material.knownHosts,
        knownHostsLine(target.host, target.port, hostKey),
        { mode: 0o600, flag: 'wx' },
      );
      if (!master) return await fn(material);
      await this.openMaster(material, target, hostKey);
      try {
        return await fn(material);
      } finally {
        await this.closeMaster(material, target);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
      if (socketDir) await rm(socketDir, { recursive: true, force: true });
    }
  }

  /**
   * Sesión interactiva con PTY (la terminal del gateway, DESIGN §11): una sola conexión sin
   * maestro, `ssh -tt` dentro de un PTY local (el puente de Python) para que el tamaño de la
   * ventana llegue al servidor, con la host key fijada y el certificado de la persona. La clave y
   * el certificado se borran en cuanto llega el primer byte (ya autenticado) y, en cualquier caso,
   * al terminar. Nunca con el usuario `inventory`, que es de solo lectura.
   */
  async interactive(
    target: AssetConnection,
    identity: SshIdentity,
    hostKey: ScannedHostKey,
    options: InteractiveOptions,
    onStart: (pty: PtyProcess) => void,
  ): Promise<InteractiveResult> {
    if (target.user === ENROLL_SSH_USER)
      throw new SshError('La terminal nunca entra con el usuario de inventario');
    return this.withMaterial(
      target,
      identity,
      hostKey,
      async (material) => {
        await material.beforeConnect();
        const log = join(material.dir, 'ssh.log');
        const args = [
          ...sshOptions(material, hostKey, this.timeoutSeconds, false),
          '-E',
          log,
          ...[
            'LogLevel=ERROR',
            'ServerAliveInterval=30',
            'ServerAliveCountMax=4',
            'RequestTTY=force',
          ].flatMap((o) => ['-o', o]),
          '-tt',
          '-p',
          String(target.port),
          '-l',
          target.user,
          '--',
          target.host,
          ...(options.command ? [options.command.map(shellQuote).join(' ')] : []),
        ];
        const pty = spawnPty(['ssh', ...args], {
          cols: options.cols,
          rows: options.rows,
          env: { PATH: process.env.PATH, TERM: options.term ?? 'xterm-256color' },
        });
        const secrets = [material.keyFile, ...(material.certFile ? [material.certFile] : [])];
        let wiped = false;
        pty.onData(() => {
          if (wiped) return;
          wiped = true;
          void Promise.all(secrets.map((f) => rm(f, { force: true })));
        });
        const exited = new Promise<number | null>((resolve) => pty.onExit(resolve));
        onStart(pty);
        const code = await exited;
        const sshLog = await readFile(log, 'utf8').catch(() => '');
        const connectError =
          code === 255 && sshLog.trim()
            ? `Fallo al conectar por SSH con ${target.user}@${target.host}:${target.port}${describe({ stdout: '', stderr: sshLog, code })}${/Permission denied/.test(sshLog) && material.certFile ? CERT_HINT : ''}`
            : null;
        return { exitCode: code, connectError };
      },
      // Prefijo propio: el limpiador del worker borra los `infraward-ssh-*` antiguos y una
      // terminal puede durar horas.
      { master: false, prefix: 'infraward-term-' },
    );
  }

  /**
   * Abre el maestro del job (`ssh -M -N -f`): la única autenticación del job. Va en segundo plano
   * y vive mientras haya clientes (y `CONTROL_PERSIST_SECONDS` sin ellos); `closeMaster` lo cierra.
   */
  private async openMaster(
    material: SshMaterial,
    target: AssetConnection,
    hostKey: ScannedHostKey,
  ): Promise<void> {
    await material.beforeConnect();
    const log = join(material.dir, `ssh-${randomUUID()}.log`);
    const result = await this.run(
      'ssh',
      [
        // Antes que las opciones comunes: en ssh gana la primera aparición de cada opción.
        ...[
          'ControlMaster=yes',
          `ControlPersist=${CONTROL_PERSIST_SECONDS}`,
        ].flatMap((o) => ['-o', o]),
        ...sshOptions(material, hostKey, this.timeoutSeconds),
        '-E',
        log,
        '-o',
        'LogLevel=ERROR',
        '-N',
        '-f',
        '-p',
        String(target.port),
        '-l',
        target.user,
        '--',
        target.host,
      ],
      (this.timeoutSeconds + 10) * 1000,
      { background: true },
    );
    await this.checkConnection(
      log,
      result.code === 0 ? 0 : 255,
      target,
      material.certFile ? CERT_HINT : '',
    );
    if (result.code !== 0)
      throw new SshError(
        `Fallo al conectar por SSH con ${target.user}@${target.host}:${target.port}${describe(result)}`,
      );
  }

  /**
   * Cierra el maestro (`-O exit`). Si no responde, mata su proceso: ningún `ssh` del job puede
   * sobrevivir al borrado de su directorio.
   */
  private async closeMaster(
    material: SshMaterial,
    target: AssetConnection,
  ): Promise<void> {
    const control = (op: string) =>
      this.run(
        'ssh',
        [
          '-F',
          '/dev/null',
          '-o',
          `ControlPath=${material.controlPath}`,
          '-O',
          op,
          '-p',
          String(target.port),
          '-l',
          target.user,
          '--',
          target.host,
        ],
        5000,
      ).catch(() => ({ stdout: '', stderr: '', code: null }) as ProcessResult);
    const check = await control('check');
    const pid = Number(/pid=(\d+)/.exec(check.stderr)?.[1]);
    await control('exit');
    if (!Number.isInteger(pid) || pid <= 0) return;
    for (let i = 0; i < 20 && alive(pid); i++)
      await new Promise((r) => setTimeout(r, 100));
    if (alive(pid)) {
      this.logger.warn(`El maestro SSH (pid ${pid}) no se cerró: se mata`);
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        // Ya no existe.
      }
    }
  }

  /**
   * Abre una «sesión» con la clave y la host key fijada (mismo material temporal para todos los
   * comandos) y da a `fn` un `HostExec` que ejecuta cada argv por SSH y cada consulta como
   * `sudo -n infraward-query <consulta> <args…>` (sudoers v4; la consulta se valida antes).
   * Los argumentos se entrecomillan para el shell remoto: llegan tal cual al ayudante.
   */
  async session<T>(
    target: AssetConnection,
    identity: SshIdentity,
    hostKey: ScannedHostKey,
    fn: (host: StreamingHostExec) => Promise<T>,
    commandTimeoutSeconds = 60,
  ): Promise<T> {
    const remote = (argv: string[]) => argv.map(shellQuote).join(' ');
    const privileged = (query: PrivilegedQuery) =>
      remote(['sudo', '-n', ...helperArgv(query)]);
    return this.withMaterial(target, identity, hostKey, (material) => {
      const run = (command: string) =>
        this.runSsh(
          material,
          target,
          hostKey,
          command,
          (this.timeoutSeconds + commandTimeoutSeconds) * 1000,
          { maxBuffer: 16 * 1024 * 1024 },
        );
      const stream = async (
        command: string,
        dest: string,
        limits: StreamLimits,
      ) => {
        await material.beforeConnect();
        const log = join(material.dir, `ssh-${randomUUID()}.log`);
        const result = await this.streamer(
          'ssh',
          this.sshArgs(material, target, hostKey, log, command, [
            // Las imágenes sin comprimir se comprimen bien en el canal.
            'Compression=yes',
          ]),
          dest,
          limits,
        );
        await this.checkConnection(log, result.code, target);
        return result;
      };
      return fn({
        run: (argv) => run(remote(argv)),
        query: async (query) => run(privileged(query)),
        streamToFile: (query, dest, limits) =>
          stream(privileged(query), dest, limits),
        streamArgvToFile: (argv, dest, limits) =>
          stream(remote(argv), dest, limits),
      });
    });
  }

  /** Ejecuta `command` en el servidor y devuelve su salida estándar. */
  async exec(
    target: AssetConnection,
    identity: SshIdentity,
    hostKey: ScannedHostKey,
    command: string,
  ): Promise<string> {
    return this.withMaterial(target, identity, hostKey, async (material) => {
      const result = await this.runSsh(
        material,
        target,
        hostKey,
        command,
        (this.timeoutSeconds + 30) * 1000,
      );
      if (result.code !== 0) {
        throw new SshError(
          `El comando remoto falló en ${target.user}@${target.host}:${target.port}${describe(result)}`,
        );
      }
      return result.stdout;
    });
  }

  /**
   * Ejecuta `command` por ssh. Los mensajes propios de ssh van a un log en el directorio del
   * material (`-E`), no al stderr del comando: así un código 255 del comando remoto (p. ej.
   * `pvesh`) no se confunde con un fallo de conexión, host key o clave, que sí deja log.
   */
  private async runSsh(
    material: SshMaterial,
    target: AssetConnection,
    hostKey: ScannedHostKey,
    command: string,
    timeoutMs: number,
    options?: ProcessOptions,
  ): Promise<ProcessResult> {
    await material.beforeConnect();
    // Un log por llamada: una sesión puede lanzar varios comandos a la vez.
    const log = join(material.dir, `ssh-${randomUUID()}.log`);
    const result = await this.run(
      'ssh',
      this.sshArgs(material, target, hostKey, log, command),
      timeoutMs,
      options,
    );
    await this.checkConnection(log, result.code, target);
    return result;
  }

  private sshArgs(
    material: SshMaterial,
    target: AssetConnection,
    hostKey: ScannedHostKey,
    log: string,
    command: string,
    extraOptions: string[] = [],
  ): string[] {
    return [
      ...sshOptions(material, hostKey, this.timeoutSeconds),
      '-E',
      log,
      ...['LogLevel=ERROR', ...extraOptions].flatMap((o) => ['-o', o]),
      '-p',
      String(target.port),
      '-l',
      target.user,
      '--',
      target.host,
      command,
    ];
  }

  /**
   * 255 con log de ssh = fallo de conexión, host key o clave (no del comando). Borra el log.
   * `hint`: se añade si el servidor rechaza la autenticación (p. ej. el motivo típico en modo CA).
   */
  private async checkConnection(
    log: string,
    code: number | null,
    target: AssetConnection,
    hint = '',
  ): Promise<void> {
    const sshLog = await readFile(log, 'utf8').catch(() => '');
    await rm(log, { force: true });
    if (code === 255 && sshLog.trim()) {
      const denied = /Permission denied/.test(sshLog);
      throw new SshError(
        `Fallo al conectar por SSH con ${target.user}@${target.host}:${target.port}${describe({ stdout: '', stderr: sshLog, code })}${denied ? hint : ''}`,
      );
    }
  }
}

/** Opciones de una sesión interactiva. */
export interface InteractiveOptions {
  /** argv remoto (se entrecomilla); null = shell de login de la cuenta. */
  command: string[] | null;
  cols: number;
  rows: number;
  /** TERM que pide ssh al servidor (por defecto xterm-256color, el de xterm.js). */
  term?: string;
}

export interface InteractiveResult {
  /** Código de salida de ssh (el del comando remoto, o 255 si falló la conexión). */
  exitCode: number | null;
  /** Fallo de conexión, host key o autenticación (apto para mostrarse); null si conectó. */
  connectError: string | null;
}

/**
 * El servidor rechazó el certificado. sshd no le dice el motivo al cliente; lo más habitual es el
 * reloj (los certificados duran minutos) o que el script en modo CA no se ejecutó.
 */
const CERT_HINT =
  '. Con certificado: comprueba que el reloj del servidor está en hora (sshd registra «Certificate invalid: not yet valid» o «expired») y que el script de alta en modo CA se ejecutó sin errores';

/** ¿Sigue vivo el proceso? (señal 0: solo comprueba). */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Comillas de shell POSIX (para el shell de login remoto de ssh y para Ansible, que usa shlex). */
export function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_./=:,@+-]+$/.test(arg)
    ? arg
    : `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** Última línea útil de stderr (p. ej. `Permission denied (publickey).`), recortada. */
export function describe(result: ProcessResult): string {
  const lines = result.stderr
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  const last = lines.at(-1);
  if (result.code === null) return ' (tiempo agotado)';
  return last ? `: ${last.slice(0, 300)}` : ` (código ${result.code})`;
}
