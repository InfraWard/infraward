import {
  SENSITIVE_ACTIONS,
  type AuditAction,
  type AuditCategory,
  type AuditEvent,
} from '@infraward/shared-types';

export const AUDIT_ACTION_LABELS: Record<AuditAction, string> = {
  'auth.login': 'Inicio de sesión',
  'auth.login_failed': 'Inicio de sesión fallido',
  'auth.logout': 'Cierre de sesión',
  'auth.password_changed': 'Cambio de contraseña',
  'auth.mfa_challenge': 'Código de verificación al entrar',
  'auth.mfa_enabled': 'Verificación en dos pasos activada',
  'auth.mfa_disabled': 'Verificación en dos pasos desactivada',
  'auth.mfa_recovery_regenerated': 'Códigos de recuperación nuevos',
  'auth.reauth': 'Confirmación de identidad',
  'auth.reauth_required': 'Acción sensible sin confirmar la identidad',
  'user.created': 'Alta de usuario',
  'user.updated': 'Cambio de nombre',
  'user.role_changed': 'Cambio de rol',
  'user.email_changed': 'Cambio de email',
  'user.deactivated': 'Usuario desactivado',
  'user.reactivated': 'Usuario reactivado',
  'user.password_reset': 'Contraseña restablecida',
  'user.oidc_linked': 'Enlazado al proveedor OIDC',
  'user.mfa_reset': 'Verificación en dos pasos restablecida',
  'api_token.created': 'Token de API creado',
  'api_token.revoked': 'Token de API revocado',
  'asset.created': 'Alta de asset',
  'asset.updated': 'Cambio de asset',
  'asset.renamed': 'Asset renombrado',
  'asset.tags_changed': 'Tags cambiados',
  'asset.notes_changed': 'Notas cambiadas',
  'tag.style_changed': 'Color de tag',
  'tag.deleted': 'Tag borrado',
  'project.created': 'Proyecto creado',
  'project.updated': 'Proyecto cambiado',
  'project.deleted': 'Proyecto borrado',
  'project.member_set': 'Asset en un proyecto',
  'project.member_removed': 'Asset quitado de un proyecto',
  'project.dashboard_updated': 'Panel del proyecto guardado',
  'project.dashboard_reset': 'Panel del proyecto restablecido',
  'asset.retired': 'Baja de asset',
  'asset.purged': 'Purga de asset',
  'asset.bulk_tags': 'Tags en lote',
  'asset.bulk_project': 'Proyecto en lote',
  'asset.bulk_collect': 'Recolección en lote',
  'asset.bulk_scan': 'Escaneo en lote',
  'asset.bulk_policy': 'Política en lote',
  'asset.bulk_retire': 'Baja en lote',
  'enrollment.started': 'Comando de alta',
  'enrollment.ca_requested': 'Paso a CA',
  'enrollment.admin_access_requested': 'Acceso de administración en el comando de alta',
  'policy.global_updated': 'Política global',
  'policy.rule_created': 'Regla creada',
  'policy.rule_updated': 'Regla cambiada',
  'policy.rule_deleted': 'Regla borrada',
  'policy.asset_set': 'Regla de asset',
  'policy.asset_cleared': 'Regla de asset quitada',
  'inventory.reconcile_requested': 'Reconciliación manual',
  'vulnerabilities.rescan_requested': 'Re-escaneo de afectados',
  'vulnerabilities.intel_refresh_requested': 'Descarga de KEV y EPSS',
  'vulnerabilities.reevaluate_requested': 'Re-evaluación de los SBOMs',
  'connector.created': 'Conector creado',
  'connector.token_replaced': 'Token de conector reemplazado',
  'connector.tested': 'Prueba de conector',
  'connector.sync_requested': 'Sincronización de conector',
  'connector.deleted': 'Conector dado de baja',
  'dns.check_accepted': 'Registro DNS marcado como esperado',
  'dns.check_reopened': 'Aviso de registro DNS reabierto',
  'settings.expiry_changed': 'Avisos de caducidad',
  'settings.nat_created': 'Reenvío NAT añadido',
  'settings.nat_updated': 'Reenvío NAT cambiado',
  'settings.nat_deleted': 'Reenvío NAT borrado',
  'service.path_pinned': 'Destino de un dominio fijado a mano',
  'service.path_unpinned': 'Destino de un dominio sin fijar',
  'vault.created': 'Credencial guardada en la caja fuerte',
  'vault.updated': 'Credencial de la caja fuerte cambiada',
  'vault.secret_replaced': 'Secreto de una credencial sustituido',
  'vault.rotated': 'Credencial marcada como rotada',
  'vault.deleted': 'Credencial a la papelera',
  'vault.restored': 'Credencial recuperada de la papelera',
  'vault.version_restored': 'Versión anterior de una credencial restaurada',
  'vault.revealed': 'Credencial revelada',
  'vault.purged': 'Credencial destruida tras el plazo',
  'vault.settings_changed': 'Ajustes de la caja fuerte',
  'terminal.session_requested': 'Terminal pedida',
  'terminal.session_opened': 'Terminal abierta',
  'terminal.session_closed': 'Terminal cerrada',
  'terminal.session_rejected': 'Terminal rechazada',
  'terminal.session_revoked': 'Terminal cortada',
  'access.granted': 'Acceso a la terminal concedido',
  'access.revoked': 'Acceso a la terminal retirado',
  'finding.accepted': 'Riesgo aceptado',
  'finding.reopened': 'Riesgo aceptado reabierto',
  'alerts.channel_created': 'Canal de alertas creado',
  'alerts.channel_updated': 'Canal de alertas cambiado',
  'alerts.channel_deleted': 'Canal de alertas borrado',
  'alerts.channel_tested': 'Prueba de canal de alertas',
};

export const AUDIT_CATEGORY_LABELS: Record<AuditCategory, string> = {
  auth: 'Sesiones',
  user: 'Usuarios',
  api_token: 'Tokens de API',
  asset: 'Assets',
  tag: 'Tags',
  project: 'Proyectos',
  enrollment: 'Altas',
  policy: 'Política',
  inventory: 'Inventario',
  vulnerabilities: 'Vulnerabilidades',
  connector: 'Conectores',
  dns: 'DNS',
  settings: 'Ajustes',
  service: 'Caminos de los dominios',
  vault: 'Caja fuerte',
  terminal: 'Terminal',
  access: 'Acceso a la terminal',
  finding: 'Riesgos aceptados',
  alerts: 'Alertas',
};

const TERMINAL_CLOSE_LABELS: Record<string, string> = {
  exit: 'salió la shell',
  client: 'la cerró el cliente',
  idle: 'por inactividad',
  max_duration: 'duración máxima',
  gateway_shutdown: 'parada del gateway',
  limit: 'sin cupo',
  connect_failed: 'no se pudo conectar',
  expired: 'ticket caducado',
  denied: 'denegada',
  revoked: 'cortada por InfraWard',
  gateway_lost: 'el gateway dejó de responder',
};

const ACCESS_SCOPE_LABELS: Record<string, string> = {
  asset: 'en el asset y lo que contiene',
  tag: 'por etiqueta',
  project: 'por proyecto',
};

/** Detalle de una regla de acceso: a quién y dónde. */
function accessDetail(event: AuditEvent): string[] {
  const d = event.details;
  const parts: string[] = [];
  if (typeof d['subject'] === 'string')
    parts.push(
      d['subjectType'] === 'role'
        ? `rol ${ROLE_LABELS[d['subject']] ?? d['subject']}`
        : d['subject'],
    );
  if (typeof d['scope'] === 'string') parts.push(ACCESS_SCOPE_LABELS[d['scope']] ?? d['scope']);
  if (typeof d['tag'] === 'string') parts.push(d['tag']);
  return parts;
}

/** Detalle de una sesión de terminal: cuenta, servidor, motivo y duración. */
function terminalDetail(event: AuditEvent): string[] {
  const d = event.details;
  const parts: string[] = [];
  if (typeof d['account'] === 'string') parts.push(`como ${d['account']}`);
  if (typeof d['host'] === 'string') parts.push(`por ${d['host']}`);
  if (typeof d['gateway'] === 'string') parts.push(d['gateway']);
  if (typeof d['reason'] === 'string')
    parts.push(TERMINAL_CLOSE_LABELS[d['reason']] ?? d['reason']);
  if (typeof d['exitCode'] === 'number') parts.push(`código ${d['exitCode']}`);
  if (typeof d['seconds'] === 'number') parts.push(`${Math.round(d['seconds'] / 60)} min`);
  if (typeof d['message'] === 'string') parts.push(d['message']);
  return parts;
}

const VAULT_FAILURE_LABELS: Record<string, string> = {
  not_found: 'la entrada no existe',
  deleted: 'está en la papelera',
  no_secret: 'sin secreto guardado',
  provider_error: 'el almacén no respondió',
  key_mismatch: 'clave de la caja fuerte equivocada',
  decryption_failed: 'no se pudo descifrar',
};

const VAULT_SETTING_LABELS: Record<string, string> = {
  rotationWarnDays: 'plazo de rotación (días)',
  notifyOnReveal: 'avisar a los admins',
  deleteRetentionDays: 'días en la papelera',
};

/** Detalle de un evento de la caja fuerte (nunca lleva el valor: solo qué, de qué y por qué). */
function vaultDetail(event: AuditEvent): string[] {
  const d = event.details;
  const parts: string[] = [];
  if (typeof d['assetName'] === 'string') parts.push(`de ${d['assetName']}`);
  if (d['purpose'] === 'show') parts.push('mostrada');
  if (d['purpose'] === 'copy') parts.push('copiada');
  if (typeof d['version'] === 'number' && typeof d['from'] === 'number')
    parts.push(`versión ${d['from']} → ${d['version']}`);
  else if (typeof d['version'] === 'number') parts.push(`versión ${d['version']}`);
  if (d['rotated'] === true) parts.push('rotada');
  if (d['hasValue'] === false) parts.push('sin secreto todavía');
  if (Array.isArray(d['fields'])) parts.push(`campos: ${d['fields'].join(', ')}`);
  if (typeof d['retentionDays'] === 'number')
    parts.push(`plazo de ${d['retentionDays']} días`);
  for (const [key, label] of Object.entries(VAULT_SETTING_LABELS))
    if (typeof d[key] === 'string') parts.push(`${label}: ${d[key]}`);
  if (typeof d['reason'] === 'string')
    parts.push(
      event.outcome === 'failure'
        ? (VAULT_FAILURE_LABELS[d['reason']] ?? d['reason'])
        : `motivo: «${d['reason']}»`,
    );
  if (typeof d['viaApi'] === 'string') parts.push(`con el token ${d['viaApi'].replace(/^api:/, '')}…`);
  return parts;
}

const LOGIN_FAILURE_LABELS: Record<string, string> = {
  unknown_user: 'usuario inexistente',
  bad_password: 'contraseña incorrecta',
  disabled: 'usuario desactivado',
  temp_expired: 'contraseña temporal caducada',
  bad_current: 'contraseña actual incorrecta',
  local_login_disabled: 'login local desactivado',
  state_invalid: 'state inválido o reutilizado',
  provider_error: 'error del proveedor',
  provider_unavailable: 'proveedor inaccesible',
  nonce_invalid: 'nonce inválido',
  issuer_invalid: 'issuer incorrecto',
  audience_invalid: 'audiencia incorrecta',
  token_expired: 'ID token caducado',
  signature_invalid: 'firma del ID token inválida',
  token_invalid: 'ID token inválido',
  email_missing: 'el proveedor no da el email',
  email_unverified: 'email sin verificar (ni se enlaza ni se da de alta)',
  already_linked: 'la cuenta ya está enlazada a otra identidad',
  emergency_account: 'es la cuenta de emergencia (no se enlaza)',
  no_role_mapping: 'ningún grupo con rol',
  bad_code: 'código incorrecto',
  recent_auth_required: 'sin confirmación reciente',
  mfa_required_for_action: 'sin verificación en dos pasos',
  subject_mismatch: 'otra identidad del proveedor',
  auth_time_missing: 'el proveedor no dice cuándo se autenticó',
  auth_time_stale: 'el proveedor no volvió a pedir las credenciales',
  session_closed: 'la sesión ya estaba cerrada',
};

const MFA_METHOD_LABELS: Record<string, string> = {
  totp: 'con la app',
  recovery: 'con un código de recuperación',
};

const ROLE_LABELS: Record<string, string> = { admin: 'admin', viewer: 'viewer' };

function list(value: unknown): string {
  return Array.isArray(value) ? value.join(', ') : '';
}

const POLICY_FIELD_LABELS: Record<string, string> = {
  reconcileIntervalMinutes: 'reconciliación (min)',
  scanEnabled: 'escaneo',
  scanPeriodic: 'escaneo automático',
};

function policyValue(v: unknown): string {
  if (v === null || v === undefined) return 'hereda';
  if (v === true) return 'sí';
  if (v === false) return 'no';
  return String(v);
}

const API_TOKEN_SCOPE_LABELS: Record<string, string> = {
  read: 'solo lectura',
  role: 'con los permisos del rol',
};

const BULK_PROJECT_MODE_LABELS: Record<string, string> = {
  include: 'incluidos con su contenido',
  exclude: 'excepción (excluidos)',
  inherit: 'vuelven a heredar',
};

/** Detalle de una operación en lote: cuántos y cuáles, omitidos y tareas. */
function bulkDetail(d: AuditEvent['details']): string[] {
  const parts: string[] = [];
  const names = Array.isArray(d['assets']) ? d['assets'] : [];
  const more = typeof d['moreAssets'] === 'number' ? d['moreAssets'] : 0;
  if (typeof d['count'] === 'number')
    parts.push(
      `${d['count']} asset(s)${names.length ? `: ${names.join(', ')}${more ? ` y ${more} más` : ''}` : ''}`,
    );
  if (list(d['added'])) parts.push(`añadidos: ${list(d['added'])}`);
  if (list(d['removed'])) parts.push(`quitados: ${list(d['removed'])}`);
  if (typeof d['project'] === 'string') parts.push(`proyecto «${d['project']}»`);
  if (typeof d['mode'] === 'string')
    parts.push(BULK_PROJECT_MODE_LABELS[d['mode']] ?? d['mode']);
  if (d['cleared'] === true) parts.push('regla propia quitada');
  for (const field of Object.keys(POLICY_FIELD_LABELS))
    if (field in d) parts.push(`${POLICY_FIELD_LABELS[field]}: ${policyValue(d[field])}`);
  if (typeof d['affected'] === 'number')
    parts.push(`${d['affected']} con su contenido`);
  if (typeof d['jobs'] === 'number') parts.push(`${d['jobs']} tarea(s)`);
  if (typeof d['alreadyRunning'] === 'number')
    parts.push(`${d['alreadyRunning']} ya en curso`);
  if (typeof d['skipped'] === 'number' && d['skipped'] > 0)
    parts.push(`${d['skipped']} omitido(s)`);
  return parts;
}

/** Detalle de una aceptación del riesgo: cuántos, qué CVE, motivo y caducidad. */
function findingDetail(event: AuditEvent): string[] {
  const d = event.details;
  const parts: string[] = [];
  if (typeof d['count'] === 'number') parts.push(`${d['count']} finding(s)`);
  const cves = Array.isArray(d['vulnerabilities']) ? d['vulnerabilities'] : [];
  const more = typeof d['moreVulnerabilities'] === 'number' ? d['moreVulnerabilities'] : 0;
  if (cves.length) parts.push(`${cves.join(', ')}${more ? ` y ${more} más` : ''}`);
  if (typeof d['reason'] === 'string') parts.push(`motivo: «${d['reason']}»`);
  if (typeof d['expiresAt'] === 'string')
    parts.push(`hasta el ${new Date(d['expiresAt']).toLocaleDateString('es')}`);
  else if (event.action === 'finding.accepted') parts.push('sin caducidad');
  if (typeof d['viaApi'] === 'string') parts.push(`con el token ${d['viaApi'].replace(/^api:/, '')}…`);
  return parts;
}

const ALERT_CHANNEL_TYPE_LABELS: Record<string, string> = {
  webhook: 'webhook',
  email: 'correo',
};

/** Detalle de un canal de alertas: tipo, destino (sin secretos) y qué cambió. */
function alertsDetail(event: AuditEvent): string[] {
  const d = event.details;
  const parts: string[] = [];
  if (typeof d['type'] === 'string')
    parts.push(ALERT_CHANNEL_TYPE_LABELS[d['type']] ?? d['type']);
  if (typeof d['host'] === 'string') parts.push(d['host']);
  if (typeof d['recipients'] === 'number') parts.push(`${d['recipients']} destinatario(s)`);
  if (d['enabled'] === false) parts.push('desactivado');
  if (d['secretChanged'] === true) parts.push('secreto de firma cambiado');
  if (Array.isArray(d['fields'])) parts.push(`campos: ${d['fields'].join(', ')}`);
  if (typeof d['error'] === 'string') parts.push(d['error']);
  return parts;
}

/** Detalle legible de un evento (en español, sin claves internas). */
export function auditDetail(event: AuditEvent): string {
  const d = event.details;
  const parts: string[] = [];
  if (event.action.startsWith('vault.')) return vaultDetail(event).join(' · ');
  if (event.action.startsWith('terminal.')) return terminalDetail(event).join(' · ');
  if (event.action.startsWith('access.')) return accessDetail(event).join(' · ');
  if (event.action.startsWith('finding.')) return findingDetail(event).join(' · ');
  if (event.action.startsWith('alerts.')) return alertsDetail(event).join(' · ');
  if (event.action.startsWith('asset.bulk_')) parts.push(...bulkDetail(d));
  else if (event.action.startsWith('api_token.')) {
    if (typeof d['prefix'] === 'string') parts.push(`${d['prefix']}…`);
    if (typeof d['scope'] === 'string')
      parts.push(API_TOKEN_SCOPE_LABELS[d['scope']] ?? d['scope']);
    if (typeof d['expiresAt'] === 'string')
      parts.push(`caduca el ${new Date(d['expiresAt']).toLocaleDateString('es')}`);
    if (typeof d['owner'] === 'string' && d['byOwner'] === false)
      parts.push(`de ${d['owner']}`);
  }
  if (typeof d['viaApi'] === 'string') parts.push(`con el token ${d['viaApi'].replace(/^api:/, '')}…`);
  if (parts.length && (event.action.startsWith('asset.bulk_') || event.action.startsWith('api_token.')))
    return parts.join(' · ');
  if (d['method'] === 'oidc') parts.push('OIDC');
  if (typeof d['action'] === 'string' && Object.hasOwn(SENSITIVE_ACTIONS, d['action']))
    parts.push(SENSITIVE_ACTIONS[d['action'] as keyof typeof SENSITIVE_ACTIONS]);
  // En el rechazo de una acción sensible, `method` es lo que se pide (no con qué se entró).
  for (const key of event.action === 'auth.reauth_required' ? ['mfa'] : ['method', 'mfa']) {
    const value = d[key];
    if (typeof value === 'string' && value in MFA_METHOD_LABELS) parts.push(MFA_METHOD_LABELS[value]);
  }
  if (typeof d['recoveryCodesLeft'] === 'number')
    parts.push(`quedan ${d['recoveryCodesLeft']} códigos de recuperación`);
  if (d['replaced'] === true) parts.push('cambio de dispositivo');
  if (d['sessionClosed'] === true) parts.push('demasiados intentos: vuelve a entrar');
  if (typeof d['reason'] === 'string')
    parts.push(LOGIN_FAILURE_LABELS[d['reason']] ?? d['reason']);
  if (d['from'] !== undefined && d['to'] !== undefined)
    parts.push(`${ROLE_LABELS[String(d['from'])] ?? d['from']} → ${ROLE_LABELS[String(d['to'])] ?? d['to']}`);
  if (d['nameFrom'] !== undefined && d['nameTo'] !== undefined)
    parts.push(`«${d['nameFrom']}» → «${d['nameTo']}»`);
  if (d['restored'] === true) parts.push('vuelve al nombre descubierto');
  if (list(d['added'])) parts.push(`añadidos: ${list(d['added'])}`);
  if (list(d['removed'])) parts.push(`quitados: ${list(d['removed'])}`);
  if (typeof d['lengthTo'] === 'number')
    parts.push(
      d['lengthTo'] === 0 ? 'notas borradas' : `${d['lengthTo']} caracteres`,
    );
  if (event.action === 'tag.deleted' && typeof d['assets'] === 'number')
    parts.push(`quitado de ${d['assets']} ${d['assets'] === 1 ? 'asset' : 'assets'}`);
  if ('colorTo' in d) parts.push(`color ${d['colorFrom'] ?? 'ninguno'} → ${d['colorTo'] ?? 'ninguno'}`);
  if (typeof d['project'] === 'string') parts.push(`proyecto «${d['project']}»`);
  if (typeof d['mode'] === 'string')
    parts.push(d['mode'] === 'exclude' ? 'excepción (excluido)' : 'incluido con su contenido');
  if (typeof d['members'] === 'number') parts.push(`${d['members']} fila(s) de pertenencia`);
  if (typeof d['role'] === 'string' && (event.action === 'user.created' || d['method'] === 'oidc'))
    parts.push(`rol ${d['role']}`);
  if (d['roleKept'] === 'last_admin') parts.push('se conserva: es el último admin activo');
  if (list(d['groups'])) parts.push(`grupos: ${list(d['groups'])}`);
  if (typeof d['providerError'] === 'string') parts.push(`«${d['providerError']}»`);
  if (d['providerLogout'] === true) parts.push('también en el proveedor');
  if (typeof d['sessionsRevoked'] === 'number' && d['sessionsRevoked'] > 0)
    parts.push(`${d['sessionsRevoked']} sesión(es) cerrada(s)`);
  if (typeof d['apiAccessRevoked'] === 'number' && d['apiAccessRevoked'] > 0)
    parts.push(`${d['apiAccessRevoked']} token(s) de API revocado(s)`);
  if (d['forced'] === true || d['forcedChange'] === true)
    parts.push('contraseña temporal');
  if (typeof d['affected'] === 'number')
    parts.push(`${d['affected']} asset(s) con su contenido`);
  if (Array.isArray(d['fields'])) parts.push(`campos: ${d['fields'].join(', ')}`);
  if (typeof d['statusFrom'] === 'string')
    parts.push(`estado ${d['statusFrom']} → ${d['statusTo']}`);
  if (typeof d['via'] === 'string')
    parts.push(d['via'] === 'enrollment' ? 'con script de alta' : 'a mano');
  if (typeof d['authMode'] === 'string')
    parts.push(d['authMode'] === 'ca_certificate' ? 'CA SSH' : 'clave estática');
  for (const field of Object.keys(POLICY_FIELD_LABELS)) {
    if (`${field}From` in d || `${field}To` in d)
      parts.push(
        `${POLICY_FIELD_LABELS[field]}: ${policyValue(d[`${field}From`])} → ${policyValue(d[`${field}To`])}`,
      );
  }
  if (typeof d['jobs'] === 'number')
    parts.push(`${d['jobs']} escaneo(s)${d['skipped'] ? `, ${d['skipped']} omitido(s)` : ''}`);
  if (d['scope'] === 'all') parts.push('todas las raíces vencidas');
  return parts.join(' · ');
}
