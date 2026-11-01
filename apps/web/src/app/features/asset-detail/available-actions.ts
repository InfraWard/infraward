import {
  ENROLL_SSH_USER,
  scanDisabledReason,
  type Asset,
  type AssetRuntimeState,
  type Permission,
} from '@infraward/shared-types';

/** Acciones de la ficha (cada una exige el permiso de ACTION_PERMISSION). */
export type AssetActionId =
  | 'collect'
  | 'scan'
  | 'enrollment'
  | 'regenerate'
  | 'migrate-ca'
  | 'retire'
  | 'purge';

/** Permiso que exige cada acción (el mismo que comprueba la API). */
export const ACTION_PERMISSION: Record<AssetActionId, Permission> = {
  collect: 'assets.operate',
  scan: 'assets.operate',
  enrollment: 'assets.write',
  regenerate: 'assets.write',
  'migrate-ca': 'assets.write',
  retire: 'assets.write',
  purge: 'assets.purge',
};

export interface AssetAction {
  id: AssetActionId;
  /** Motivo por el que no se puede ahora (botón deshabilitado con tooltip); null si se puede. */
  disabledReason: string | null;
}

/**
 * Qué acciones tiene sentido ofrecer para un asset, con las mismas reglas que la API (que da 409
 * si no): recoger un servidor dado de alta o un CT activo y en marcha; escanear servidores con
 * conexión y CT (su SBOM), contenedores, imágenes y hosts Docker; continuar o regenerar el alta de un servidor pendiente (o con el
 * sudoers o la CA SSH desactualizados); pasar a certificados de la CA un servidor activo con
 * clave estática dado de alta con el script; dar de baja lo que no está retirado; purgar siempre
 * (a un retirado solo le queda purgar).
 */
export function availableActions(
  asset: Pick<Asset, 'type' | 'status' | 'roles' | 'connection' | 'sshAuth'> &
    Partial<Pick<Asset, 'effectivePolicy'>>,
  context: {
    runtimeState: AssetRuntimeState | null;
    sudoersOutdated: boolean;
    sshCaOutdated?: boolean;
    /** ¿Hay un proveedor sano con CA SSH? null/undefined mientras no se sabe. */
    caAvailable?: boolean | null;
  },
): AssetAction[] {
  const actions: AssetAction[] = [];
  // Política de inventario (§10): con el escaneo desactivado, tampoco bajo demanda.
  const scanOff = asset.effectivePolicy?.values?.scanEnabled === false;
  const add = (id: AssetActionId, disabledReason: string | null = null) =>
    actions.push({
      id,
      disabledReason:
        id === 'scan' && scanOff && !disabledReason
          ? scanDisabledReason(asset.effectivePolicy)
          : disabledReason,
    });
  const active = asset.status === 'active';
  // Retirado: ya no se trabaja con él; solo queda borrarlo del todo.
  if (asset.status === 'retired') return [{ id: 'purge', disabledReason: null }];

  // Un servidor manual sin conexión no se puede recoger.
  if (asset.type === 'lxc' || (asset.type === 'server' && asset.connection)) {
    if (!active) add('collect', 'Solo se recogen assets activos');
    else if (asset.type === 'lxc' && context.runtimeState === 'stopped')
      add('collect', 'El CT está parado');
    else add('collect');
  }

  const dockerHost =
    asset.roles.includes('docker-host') || asset.roles.includes('podman-host');
  if (asset.type === 'container')
    add('scan', active ? null : 'Solo se escanean contenedores activos');
  else if (asset.type === 'image') add('scan');
  else if (asset.type === 'lxc' || (asset.type === 'server' && asset.connection)) {
    // Pendiente de alta: aún no hay forma de entrar (se escanea al recogerlo).
    if (asset.status !== 'pending_enrollment')
      add(
      'scan',
      !active
        ? 'Solo se escanean assets activos'
        : asset.type === 'lxc' && context.runtimeState === 'stopped'
          ? 'El CT está parado'
          : null,
      );
  } else if (dockerHost) add('scan', active ? null : 'El host no está activo');

  if (asset.type === 'server' && asset.connection) {
    if (asset.status === 'pending_enrollment') {
      add('enrollment');
      add('regenerate');
    } else if (active && (context.sudoersOutdated || context.sshCaOutdated))
      add('regenerate');
    // El script en modo CA configura sshd para el usuario dedicado: solo altas con el script.
    if (
      active &&
      asset.sshAuth === 'static_key' &&
      asset.connection.user === ENROLL_SSH_USER
    )
      add(
        'migrate-ca',
        context.caAvailable === false
          ? 'Ningún proveedor de secretos activo tiene CA SSH (configura OpenBao: SECRETS_PROVIDERS=openbao,…)'
          : context.caAvailable == null
            ? 'Comprobando los proveedores de secretos…'
            : null,
      );
  }

  add('retire');
  add('purge');
  return actions;
}
