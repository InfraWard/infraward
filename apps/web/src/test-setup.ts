// Preparación común de los tests de la web (setupFiles de `ng test`).
//
// El builder de Angular ejecuta Vitest con `isolate: false`: los ficheros de spec que caen en el
// mismo worker comparten módulos y globales. Lo que un spec deja puesto lo hereda el siguiente,
// y como el reparto de ficheros entre workers cambia de una ejecución a otra, los fallos salen
// solo a veces. Aquí se deja limpio lo que es global.
import { primeSessionForTests } from './app/core/auth/auth.service';

// Sin sesión salvo que el test la ponga con storeSession(). Si no, un AuthService nuevo arranca
// con la del último spec que la usó (p. ej. un admin, que ve la columna de selección múltiple).
beforeEach(() => primeSessionForTests(null));

// jsdom no tiene ResizeObserver (lo usan las pestañas desplazables, gráficos y la terminal).
// Uno completo y único: si cada spec pone el suyo con `??=`, gana el primero que se carga, y
// alguno no tenía unobserve, que las pestañas llaman al destruirse.
const noop = (): void => undefined;
globalThis.ResizeObserver ??= class {
  observe = noop;
  unobserve = noop;
  disconnect = noop;
};
