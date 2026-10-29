import { InjectionToken } from '@angular/core';

/**
 * Prefijo de la API. En desarrollo, `ng serve` lo redirige a :3000 (proxy.conf.json), así que la
 * web y la API comparten origen y la API no necesita CORS.
 */
export const API_BASE_URL = new InjectionToken<string>('API_BASE_URL', {
  factory: () => '/api',
});
