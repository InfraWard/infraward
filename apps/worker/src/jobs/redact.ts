/**
 * Censura de secretos en lo que va al log de una ejecución (DESIGN §20, «Log de cada
 * ejecución»). El worker nunca pone secretos en los comandos (las claves van en ficheros del
 * tmpfs del job), pero el stderr de un servidor o de una herramienta puede traer cualquier cosa:
 * todo pasa por aquí antes de guardarse. Mejor censurar de más que de menos.
 */
export const REDACTED = '[censurado]';

const RULES: [RegExp, string | ((...m: string[]) => string)][] = [
  // Claves privadas PEM/OpenSSH (enteras, o hasta el final si llegan cortadas).
  [
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
    '[clave privada censurada]',
  ],
  // Credenciales en una URL (`https://user:pass@host`).
  [/\b([a-z][a-z0-9+.-]*:\/\/)([^\s:@/]+):([^\s@/]+)@/gi, `$1$2:${REDACTED}@`],
  // Cabeceras Authorization y tokens Bearer/Basic.
  [
    /\b(authorization\s*[:=]\s*)(?:(bearer|basic|token)\s+)?[^\s"',;]+/gi,
    (_m, head: string, scheme?: string) =>
      `${head}${scheme ? `${scheme} ` : ''}${REDACTED}`,
  ],
  [/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, `$1 ${REDACTED}`],
  // `clave=valor`, `clave: valor` y `"clave": "valor"` con nombres de secreto.
  [
    /\b([A-Za-z0-9_.-]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|secret[_-]?id|client[_-]?secret|credentials?))(\s*["']?\s*[:=]\s*["']?)([^\s"',;&}]+)/gi,
    `$1$2${REDACTED}`,
  ],
  // Formatos de token conocidos.
  [/\biwt_[A-Za-z0-9_-]{8,}/g, REDACTED], // tokens de API de InfraWard
  [/\b(?:hv[sbr]|s|b)\.[A-Za-z0-9_-]{20,}/g, REDACTED], // OpenBao / Vault
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, REDACTED], // JWT
  [
    /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})/g,
    REDACTED,
  ],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, REDACTED], // AWS
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}/g, REDACTED], // Slack
];

/** El texto sin secretos reconocibles. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const [pattern, replacement] of RULES)
    out = out.replace(pattern, replacement as string);
  return out;
}
