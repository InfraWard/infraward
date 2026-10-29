import type { UserRole } from '@infraward/shared-types';

/** Nombre y descripción de cada rol (los permisos, en ROLE_PERMISSIONS de shared-types). */
export const ROLE_INFO: Record<UserRole, { label: string; description: string }> = {
  admin: {
    label: 'Admin',
    description: 'Todo: además de lo del editor, purgar, gestionar usuarios y ver la auditoría.',
  },
  editor: {
    label: 'Editor',
    description:
      'Gestiona el inventario: altas, pasos a CA, cambios, bajas (no purgas) y la política, además de recolectar y escanear.',
  },
  operator: {
    label: 'Operador',
    description: 'Recolecta, descubre, escanea, re-escanea y reconcilia lo que ya existe. No da de alta ni de baja.',
  },
  auditor: {
    label: 'Auditor',
    description: 'Solo lectura más el registro de auditoría, la lista de usuarios y el estado de los secretos.',
  },
  viewer: {
    label: 'Lector',
    description: 'Solo lectura: ve el inventario y las vulnerabilidades.',
  },
};

export function roleLabel(role: UserRole): string {
  return ROLE_INFO[role]?.label ?? role;
}

export function roleSeverity(role: UserRole): 'contrast' | 'info' | 'secondary' {
  if (role === 'admin') return 'contrast';
  return role === 'editor' || role === 'operator' ? 'info' : 'secondary';
}
