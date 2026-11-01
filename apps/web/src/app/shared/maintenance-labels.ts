import {
  SCAN_EXCLUDABLE_TYPE_LABELS,
  scanExclusionText,
  type InventoryRuleField,
  type ScanExclusions,
  type InventoryPolicySource,
  type NotificationKind,
  type SnapshotChangeKind,
  type SnapshotSource,
} from '@infraward/shared-types';
import type { TagSeverity } from './labels';

// Textos de la política de inventario, los snapshots y las notificaciones (DESIGN §10).

export const POLICY_FIELD_LABELS: Record<InventoryRuleField, string> = {
  reconcileIntervalMinutes: 'Reconciliación',
  scanEnabled: 'Escaneo de vulnerabilidades',
  scanPeriodic: 'Escaneo automático',
  scanExclusions: 'Excluido del escaneo',
};

/** «cada 6 h», «cada 90 min», «cada 2 días», «nunca». */
export function formatInterval(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined) return 'heredado';
  if (minutes <= 0) return 'nunca';
  if (minutes % 1440 === 0) {
    const days = minutes / 1440;
    return `cada ${days} ${days === 1 ? 'día' : 'días'}`;
  }
  if (minutes % 60 === 0) return `cada ${minutes / 60} h`;
  return `cada ${minutes} min`;
}

/** «imágenes de contenedor · bitnami/* · 2 assets», o «nada». */
export function scanExclusionsSummary(ex: ScanExclusions | null | undefined): string {
  const parts = [
    ...(ex?.types ?? []).map((t) => SCAN_EXCLUDABLE_TYPE_LABELS[t]),
    ...(ex?.namePatterns ?? []),
    ...(ex?.assetIds?.length
      ? [`${ex.assetIds.length} ${ex.assetIds.length === 1 ? 'asset' : 'assets'}`]
      : []),
  ];
  return parts.length ? parts.join(' · ') : 'nada';
}

/** Valor de un campo para mostrarlo. */
export function policyValueLabel(
  field: InventoryRuleField,
  value: number | boolean | ScanExclusions | null | undefined,
): string {
  if (field === 'scanExclusions')
    return scanExclusionsSummary(value as ScanExclusions | null | undefined);
  if (value === null || value === undefined) return 'heredado';
  if (field === 'reconcileIntervalMinutes')
    return formatInterval(value as number);
  if (field === 'scanEnabled') return value ? 'activado' : 'desactivado';
  return value ? 'sí' : 'solo bajo demanda';
}

/**
 * «propia», «heredada de pve», «por la etiqueta prod», «por el proyecto Homelab», «de quienes
 * la usan», «global».
 */
export function policySourceLabel(source: InventoryPolicySource): string {
  switch (source.kind) {
    case 'own':
      return 'propia';
    case 'inherited':
      return `heredada de ${source.assetName ?? 'un nodo superior'}`;
    case 'tag':
      return `por la etiqueta ${source.tag}`;
    case 'project':
      return `por el proyecto ${source.projectName ?? 'del asset'}`;
    case 'holders':
      return 'de los hosts y contenedores que la usan';
    case 'global':
      return 'global';
    case 'excluded':
      return `excluido por ${scanExclusionText(source)}`;
  }
}

export const SNAPSHOT_SOURCE_LABELS: Record<SnapshotSource, string> = {
  collect: 'Recolección',
  discover: 'Descubrimiento',
};

export const CHANGE_KIND_LABELS: Record<SnapshotChangeKind, string> = {
  added: 'Añadido',
  removed: 'Quitado',
  changed: 'Cambiado',
};

export const CHANGE_KIND_SEVERITY: Record<SnapshotChangeKind, TagSeverity> = {
  added: 'success',
  removed: 'danger',
  changed: 'info',
};

/** Secciones de primer nivel de los facts. */
export const SNAPSHOT_SECTION_LABELS: Record<string, string> = {
  roles: 'Roles',
  os: 'Sistema operativo',
  hardware: 'Hardware',
  mounts: 'Montajes',
  network: 'Red',
  packages: 'Paquetes',
  services: 'Servicios',
  ports: 'Puertos',
  detected: 'Detección',
  infraward: 'Recolección',
  machineId: 'machine-id',
  proxmox: 'Proxmox',
  docker: 'Docker',
  plesk: 'Plesk',
  certificate: 'Certificado',
  image: 'Imagen',
};

export function sectionLabel(section: string): string {
  return SNAPSHOT_SECTION_LABELS[section] ?? section;
}

/** Qué es cada tipo de notificación (filtro de los canales de alertas). */
export const NOTIFICATION_KIND_LABELS: Record<NotificationKind, string> = {
  asset_created: 'Assets nuevos',
  asset_missing: 'Assets desaparecidos',
  asset_reactivated: 'Assets que reaparecen',
  asset_retired: 'Assets retirados',
  reconcile_failed: 'Fallos de la reconciliación',
  expiry_warning: 'Caducidad de dominios y certificados',
  dns_dangling: 'Registros DNS colgantes',
  vulnerability_kev: 'CVE críticos en KEV y expuestos',
  vault_revealed: 'Credencial revelada (solo admins)',
  finding_acceptance_expired: 'Riesgo aceptado caducado',
};

export const NOTIFICATION_ICONS: Record<NotificationKind, string> = {
  asset_created: 'bi-plus-circle',
  asset_missing: 'bi-question-circle',
  asset_reactivated: 'bi-arrow-counterclockwise',
  asset_retired: 'bi-archive',
  reconcile_failed: 'bi-exclamation-triangle',
  expiry_warning: 'bi-calendar-x',
  dns_dangling: 'bi-signpost-split',
  vulnerability_kev: 'bi-shield-fill-exclamation',
  vault_revealed: 'bi-safe2',
  finding_acceptance_expired: 'bi-hourglass-bottom',
};

export const NOTIFICATION_SEVERITY: Record<NotificationKind, TagSeverity> = {
  asset_created: 'success',
  asset_missing: 'warn',
  asset_reactivated: 'info',
  asset_retired: 'secondary',
  reconcile_failed: 'danger',
  expiry_warning: 'warn',
  dns_dangling: 'danger',
  vulnerability_kev: 'danger',
  vault_revealed: 'warn',
  finding_acceptance_expired: 'warn',
};
