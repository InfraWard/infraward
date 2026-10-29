import { definePreset } from '@openng/optimus-ui-themes';
import Aura from '@openng/optimus-ui-themes/aura';

/**
 * Aura con primario teal (el del logo) y tokens propios de la app (`--p-app-*`) que cambian
 * con el modo claro/oscuro. Aura no oscurece la paleta `surface` en modo oscuro (su 50 sigue
 * siendo claro), así que los fondos y colores de estado se piden por estos tokens.
 */
export const InfraWardPreset = definePreset(Aura, {
  semantic: {
    primary: {
      50: '{teal.50}',
      100: '{teal.100}',
      200: '{teal.200}',
      300: '{teal.300}',
      400: '{teal.400}',
      500: '{teal.500}',
      600: '{teal.600}',
      700: '{teal.700}',
      800: '{teal.800}',
      900: '{teal.900}',
      950: '{teal.950}',
    },
  },
  extend: {
    colorScheme: {
      light: {
        app: {
          background: '{surface.50}',
          code: { background: '{surface.100}' },
          danger: { color: '{red.600}' },
          warn: { color: '{orange.600}' },
          success: { color: '{green.700}' },
          info: { color: '{blue.600}' },
        },
      },
      dark: {
        app: {
          background: '{surface.950}',
          code: { background: '{surface.800}' },
          danger: { color: '{red.400}' },
          warn: { color: '{orange.400}' },
          success: { color: '{green.400}' },
          info: { color: '{blue.400}' },
        },
      },
    },
  },
});
