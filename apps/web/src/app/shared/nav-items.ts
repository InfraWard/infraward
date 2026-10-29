import type { Permission } from '@infraward/shared-types';

/** Secciones del menú lateral (y del drawer en móvil). */
export interface NavItem {
  path: string;
  label: string;
  /** Clase de Bootstrap Icons. */
  icon: string;
  /** Solo se enseña con este permiso. */
  permission?: Permission;
}

export const NAV_ITEMS: readonly NavItem[] = [
  { path: '/dashboard', label: 'Panel', icon: 'bi-speedometer2' },
  { path: '/inventory', label: 'Inventario', icon: 'bi-diagram-3' },
  { path: '/projects', label: 'Proyectos', icon: 'bi-collection' },
  { path: '/vulnerabilities', label: 'Vulnerabilidades', icon: 'bi-shield-exclamation' },
  { path: '/activity', label: 'Actividad', icon: 'bi-activity' },
  { path: '/vault', label: 'Caja fuerte', icon: 'bi-safe2', permission: 'vault.manage' },
  { path: '/settings', label: 'Ajustes', icon: 'bi-gear' },
];
