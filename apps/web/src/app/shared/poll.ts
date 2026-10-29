import { EMPTY, expand, timer, type Observable, switchMap } from 'rxjs';

/**
 * Pide `load` y, mientras `busy` diga que hay trabajo pendiente, lo vuelve a pedir cada
 * `intervalMs`. Sin trabajo pendiente, termina (no hay sondeo en reposo).
 */
export function pollWhile<T>(
  load: () => Observable<T>,
  busy: (value: T) => boolean,
  intervalMs: number,
): Observable<T> {
  return load().pipe(
    expand((value) =>
      busy(value) ? timer(intervalMs).pipe(switchMap(load)) : EMPTY,
    ),
  );
}
