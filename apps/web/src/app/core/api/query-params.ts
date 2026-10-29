import { HttpParams } from '@angular/common/http';

/** Query string a partir de un objeto (sin los valores vacíos). */
export function toParams(query: object): HttpParams {
  let params = new HttpParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '')
      params = params.set(key, String(value));
  }
  return params;
}
