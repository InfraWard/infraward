export const SERVICE_NAMES = {
  web: 'web',
  api: 'api',
  worker: 'worker',
} as const;

export type ServiceName = (typeof SERVICE_NAMES)[keyof typeof SERVICE_NAMES];
