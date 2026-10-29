import {
  INFRAWARD_QUERY_HELPER,
  LEGACY_PLESK_QUERY_HELPER,
} from '@infraward/connectors';
import {
  ADMIN_ACCESS_USER,
  ENROLL_SSH_USER,
  type SshAuthMode,
} from '@infraward/shared-types';
import { dirname } from 'node:path';
import { gzipSync } from 'node:zlib';

// Comandos que se muestran al admin. Todos los valores que se interpolan están validados antes
// (URL, token base64url, uuid, usuario POSIX, clave pública), así que no rompen las comillas.

/** Comentario de la clave pública: identifica la línea de cada asset en `authorized_keys`. */
export function keyComment(assetId: string): string {
  return `${ENROLL_SSH_USER}@infraward:${assetId}`;
}

export function enrollUrl(publicUrl: string, token: string): string {
  return `${publicUrl.replace(/\/+$/, '')}/enroll/${token}`;
}

/**
 * Intérprete al final de la tubería. Con `--install-sudo` el servidor puede no tener sudo
 * (Proxmox): se ejecuta como root y sin `sudo`.
 */
function runner(installSudo: boolean): string {
  return installSudo ? 'bash -s -- --install-sudo' : 'sudo bash';
}

/** `curl … | sudo bash`: crea el usuario, instala la clave y el sudoers y avisa a la API. */
export function installCommand(
  publicUrl: string,
  token: string,
  installSudo = false,
): string {
  return `curl -fsSL ${enrollUrl(publicUrl, token)} | ${runner(installSudo)}`;
}

/**
 * Script embebido (servidores sin acceso a la API: VPN, NAT): gzip + base64 en el propio
 * comando. El alfabeto base64 no puede cerrar las comillas simples.
 */
export function embeddedCommand(script: string, installSudo = false): string {
  const payload = gzipSync(script, { level: 9 }).toString('base64');
  return `echo '${payload}' | base64 -d | gunzip | ${runner(installSudo)}`;
}

/** Alternativa manual (DESIGN §7): añadir la clave a la cuenta del usuario indicado. */
export function manualCommand(publicKey: string): string {
  return `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${publicKey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`;
}

/** Ficheros que instala el script en modo CA (DESIGN §7). */
const SSH_CA_FILES = [
  '/etc/ssh/sshd_config.d/00-infraward.conf',
  '/etc/ssh/infraward/trusted_user_ca_keys',
  `/etc/ssh/infraward/principals/${ENROLL_SSH_USER}`,
  '/etc/infraward/ssh-ca-version',
];

/** Ficheros del acceso interactivo de administración (DESIGN §7; solo en modo CA). */
const ADMIN_ACCESS_FILES = [
  '/etc/ssh/sshd_config.d/01-infraward-admin.conf',
  '/etc/sudoers.d/infraward-admin',
  `/etc/ssh/infraward/principals/${ADMIN_ACCESS_USER}`,
  '/etc/infraward/admin-access-version',
];
const ADMIN_CREATED_MARK = '/etc/infraward/admin-access-created-user';

/**
 * Recarga de sshd tras validar la configuración (systemd, OpenRC o la señal HUP), como el
 * script de alta. Con `\$` porque va dentro de `sh -c "…"`.
 */
const RELOAD_SSHD =
  'sshd -t && { systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || ' +
  'rc-service sshd reload 2>/dev/null || kill -HUP \\$(cat /run/sshd.pid); }';

/**
 * Comando de baja: quita la línea de la clave del asset. Si era el usuario dedicado y no le
 * quedan claves de InfraWard, borra también el sudoers y el ayudante de root; el usuario solo si no le queda ninguna
 * otra clave (una línea añadida a mano por el administrador no se pierde). En modo CA quita la
 * confianza en la CA de InfraWard (drop-in de sshd, claves de la CA y principals) y recarga
 * sshd tras validarlo. Esa configuración es del usuario `inventory`: si otro asset en modo CA
 * apunta al mismo servidor, también deja de entrar.
 */
export function unenrollCommand(
  assetId: string,
  sshUser: string,
  authMode: SshAuthMode = 'static_key',
): string {
  const auth = `~${sshUser}/.ssh/authorized_keys`;
  const removeKey = `sed -i '/ ${keyComment(assetId)}$/d' ${auth}`;
  if (sshUser !== ENROLL_SSH_USER) return `sudo ${removeKey}`;
  // El acceso de administración (si lo había) confía en la misma CA: se retira con ella. La
  // cuenta solo se borra si la creó InfraWard; si no se puede (procesos vivos), se bloquea.
  const removeAdmin =
    `rm -f ${ADMIN_ACCESS_FILES.join(' ')}; ` +
    `[ ! -f ${ADMIN_CREATED_MARK} ] || { userdel -r ${ADMIN_ACCESS_USER} 2>/dev/null || usermod -L -e 1 ${ADMIN_ACCESS_USER}; rm -f ${ADMIN_CREATED_MARK}; }; `;
  const removeCa =
    authMode === 'ca_certificate'
      ? `${removeAdmin}rm -f ${SSH_CA_FILES.join(' ')}; rmdir /etc/ssh/infraward/principals /etc/ssh/infraward 2>/dev/null; ${RELOAD_SSHD}; `
      : '';
  return (
    // Entre comillas dobles solo hay que escapar los `$`.
    `sudo sh -c "${removeCa}[ ! -f ${auth} ] || ${removeKey.replaceAll('$', '\\$')}; ` +
    `grep -qs '${ENROLL_SSH_USER}@infraward:' ${auth} || ` +
    `{ rm -f /etc/sudoers.d/infraward-${ENROLL_SSH_USER} /etc/infraward/sudoers-version ${INFRAWARD_QUERY_HELPER} ${LEGACY_PLESK_QUERY_HELPER}; ` +
    `rmdir /etc/infraward ${dirname(INFRAWARD_QUERY_HELPER)} 2>/dev/null; ` +
    `grep -qsvE '^[[:space:]]*(#|\\$)' ${auth} || userdel -r ${ENROLL_SSH_USER}; }"`
  );
}
