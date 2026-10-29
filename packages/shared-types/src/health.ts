import type { ServiceName } from './services.js';

export interface HealthStatus {
  service: ServiceName;
  status: 'ok';
  version: string;
  timestamp: string;
}
