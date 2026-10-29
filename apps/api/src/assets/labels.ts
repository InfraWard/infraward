/** Etiquetas y roles: sin espacios, empiezan por letra o número (`docker-host`, `env:prod`). */
export const LABEL = /^[\p{L}\p{N}][\p{L}\p{N}._:/-]*$/u;

/** Longitud máxima de una etiqueta o un rol, y cuántos puede tener un asset. */
export const LABEL_MAX = 64;
export const LABELS_MAX = 50;
