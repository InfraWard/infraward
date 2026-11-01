// Alertas fuera de la app (DESIGN §10): canales que reciben lo mismo que la campana.
import type { NotificationKind } from './inventory.js';

/** Tipos de canal: webhook genérico (POST JSON firmado) y correo (SMTP del worker). */
export const ALERT_CHANNEL_TYPES = ['webhook', 'email'] as const;
export type AlertChannelType = (typeof ALERT_CHANNEL_TYPES)[number];

export const ALERT_CHANNEL_NAME_MAX = 100;
export const ALERT_WEBHOOK_URL_MAX = 2048;
/** Secreto de firma del webhook (HMAC-SHA256): solo se escribe, nunca se devuelve. */
export const ALERT_WEBHOOK_SECRET_MIN = 16;
export const ALERT_WEBHOOK_SECRET_MAX = 256;
export const ALERT_EMAIL_RECIPIENTS_MAX = 20;
/** Canales como mucho (cada notificación sale una vez por canal). */
export const ALERT_CHANNELS_MAX = 20;

/** Cabeceras del webhook: evento, fecha (segundos Unix) y firma `sha256=<hex>` de `<fecha>.<cuerpo>`. */
export const ALERT_WEBHOOK_EVENT_HEADER = 'x-infraward-event';
export const ALERT_WEBHOOK_TIMESTAMP_HEADER = 'x-infraward-timestamp';
export const ALERT_WEBHOOK_SIGNATURE_HEADER = 'x-infraward-signature';

export interface AlertChannel {
  id: string;
  name: string;
  type: AlertChannelType;
  enabled: boolean;
  /** Tipos de notificación que recibe; null = todos. */
  kinds: NotificationKind[] | null;
  /** También las que solo ven los admins (p. ej. «credencial revelada»). */
  includeAdminOnly: boolean;
  /**
   * Webhook: solo el host. La URL completa suele llevar un token (Slack, Discord, ntfy…): se guarda
   * en el gestor de secretos y nunca vuelve a la web.
   */
  host: string | null;
  /** Correo: los destinatarios. */
  recipients: string[] | null;
  /** Webhook: hay secreto de firma (el valor nunca sale de la API). */
  hasSecret: boolean;
  /** Proveedor de secretos en el que están la URL y el secreto de firma del webhook. */
  secretProvider: string | null;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  /** Último error (sin cuerpo ni URL: código HTTP o del servidor de correo). */
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateAlertChannelRequest {
  name: string;
  type: AlertChannelType;
  enabled?: boolean;
  kinds?: NotificationKind[] | null;
  includeAdminOnly?: boolean;
  /** Webhook: la URL (se guarda en el gestor de secretos). */
  url?: string;
  recipients?: string[];
  /** Webhook: secreto de firma (opcional; sin él, el envío va sin firma). */
  secret?: string;
}

/** Cambios de un canal: el tipo no cambia; `url` la sustituye; `secret: null` quita la firma. */
export interface UpdateAlertChannelRequest {
  name?: string;
  enabled?: boolean;
  kinds?: NotificationKind[] | null;
  includeAdminOnly?: boolean;
  url?: string;
  recipients?: string[];
  secret?: string | null;
}

/** Lo que sabe la API del envío por correo (la configuración SMTP vive en el worker). */
export interface AlertsStatus {
  /** El worker tiene SMTP configurado (lo publica al arrancar); null si no se sabe. */
  smtpConfigured: boolean | null;
  /** El worker acepta webhooks a IPs privadas (ALERTS_WEBHOOK_ALLOW_PRIVATE). */
  allowPrivate: boolean | null;
  /** El worker acepta webhooks por `http:` (ALERTS_WEBHOOK_ALLOW_HTTP). */
  allowHttp: boolean | null;
}

/** Clave de Redis con el estado que publica el worker para la API (`AlertsStatus`). */
export const ALERTS_STATUS_KEY = 'infraward:alerts:status';

export interface AlertTestResult {
  ok: boolean;
  /** Código HTTP o del servidor de correo; null si fue bien. */
  error: string | null;
}

/** Envía una notificación por un canal (uno por notificación y canal; con reintentos). */
export interface AlertDeliverJobData {
  notificationId: string;
  channelId: string;
}

export interface AlertDeliverJobResult {
  ok: boolean;
  /** Canal desactivado o borrado entretanto: no se envía. */
  skipped?: boolean;
}

/** Mensaje de prueba por un canal (lo espera la API con `runQuick`). */
export interface AlertTestJobData {
  channelId: string;
}

/** Cuerpo JSON del webhook. Nunca facts, conexión ni credenciales: lo mismo que la campana. */
export interface AlertWebhookPayload {
  /** `notification` o, en la prueba, `test`. */
  event: 'notification' | 'test';
  id: string;
  kind: NotificationKind | 'test';
  message: string;
  asset: { id: string | null; name: string | null } | null;
  items: { id: string; name: string; type: string }[];
  total: number;
  createdAt: string;
  /** Enlace a la web (con ALERTS_PUBLIC_URL); null si no está configurada. */
  url: string | null;
}
