import type {
  AccessPolicyRule,
  AccessSubject,
  AssetAccessEntry,
} from '@infraward/shared-types';
import { roleLabel } from './role-labels';

/** «ana@…» o «Rol Editor». */
export function accessSubjectLabel(subject: AccessSubject): string {
  return subject.type === 'user'
    ? (subject.email ?? subject.name ?? 'usuario borrado')
    : `Rol ${roleLabel(subject.role)}`;
}

/** Dónde vale la regla: «pve-pruebas y lo que contiene», «etiqueta web», «proyecto Tienda». */
export function accessTargetLabel(rule: AccessPolicyRule): string {
  switch (rule.scope) {
    case 'asset':
      return `${rule.assetName ?? 'asset borrado'} y lo que contiene`;
    case 'tag':
      return `etiqueta ${rule.tag}`;
    case 'project':
      return `proyecto ${rule.projectName ?? 'borrado'}`;
  }
}

/** Por qué alcanza a este asset. */
export function accessSourceLabel(entry: AssetAccessEntry): string {
  switch (entry.source.kind) {
    case 'own':
      return 'en este asset';
    case 'inherited':
      return `heredado de ${entry.sourceName ?? 'un antepasado'}`;
    case 'tag':
      return `por la etiqueta ${entry.source.tag}`;
    case 'project':
      return `por el proyecto ${entry.sourceName ?? ''}`.trim();
  }
}
