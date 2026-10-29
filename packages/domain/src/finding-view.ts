import { scanEnabledSql } from './inventory-policy.js';

/**
 * El finding no es de una imagen «sin uso» (ningún contenedor activo la usa): lo accionable.
 * Autocontenida sobre `f.asset_id` (no necesita el alias del dueño).
 */
export const NOT_UNUSED_IMAGE = `NOT EXISTS (
  SELECT 1 FROM assets ui
   WHERE ui.id = f.asset_id AND ui.type = 'image'
     AND NOT EXISTS (SELECT 1 FROM asset_relations ur
                       JOIN assets uc ON uc.id = ur.parent_id AND uc.status = 'active'
                      WHERE ur.child_id = ui.id AND ur.type = 'instance_of'))`;

/**
 * El dueño del finding escanea (política de inventario, §10): los de un asset con el escaneo
 * desactivado se conservan, pero salen de las listas globales. Autocontenida sobre `f.asset_id`.
 */
export const SCAN_ENABLED_OWNER = `EXISTS (
  SELECT 1 FROM assets so WHERE so.id = f.asset_id AND ${scanEnabledSql('so')})`;
