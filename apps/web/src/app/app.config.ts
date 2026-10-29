import { registerLocaleData } from '@angular/common';
import {
  provideHttpClient,
  withFetch,
  withInterceptors,
} from '@angular/common/http';
import localeEs from '@angular/common/locales/es';
import {
  ApplicationConfig,
  inject,
  LOCALE_ID,
  provideAppInitializer,
  provideBrowserGlobalErrorListeners,
} from '@angular/core';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { provideOptimus } from '@openng/optimus-ui/config';
import { routes } from './app.routes';
import { authInterceptor } from './core/auth/auth.interceptor';
import { AuthService } from './core/auth/auth.service';
import { InfraWardPreset } from './theme';

registerLocaleData(localeEs);

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes, withComponentInputBinding()),
    provideHttpClient(withFetch(), withInterceptors([authInterceptor])),
    // La sesión vive en una cookie httpOnly: antes de la primera navegación se pregunta a la API.
    provideAppInitializer(() => inject(AuthService).restore()),
    provideOptimus({
      theme: {
        preset: InfraWardPreset,
        options: {
          // Igual que la variante `dark:` de Tailwind: sigue al sistema.
          darkModeSelector: 'system',
          cssLayer: { name: 'optimus', order: 'theme, base, optimus' },
        },
      },
    }),
    { provide: LOCALE_ID, useValue: 'es' },
  ],
};
