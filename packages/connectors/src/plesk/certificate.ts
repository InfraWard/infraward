import type { CertificateFacts } from '@infraward/shared-types';
import { X509Certificate } from 'node:crypto';

export type ParsedCertificate = Pick<
  CertificateFacts,
  | 'subject'
  | 'subjectAltNames'
  | 'issuer'
  | 'notBefore'
  | 'notAfter'
  | 'fingerprint256'
  | 'selfSigned'
  | 'letsEncrypt'
>;

const PEM_CERT =
  /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

/**
 * Texto de `certificates.cert` tal como lo guarda Plesk: en las versiones actuales, codificado
 * como un formulario (`%2D%2D%2D%2D%2DBEGIN+CERTIFICATE…`); en otras, PEM tal cual. null si no
 * se puede decodificar.
 */
export function decodePleskPem(raw: string): string | null {
  if (raw.includes('-----BEGIN')) return raw;
  try {
    return decodeURIComponent(raw.replace(/\+/g, ' '));
  } catch {
    return null;
  }
}

/**
 * ¿Hay un certificado X.509? En la tabla de certificados de Plesk también hay claves públicas
 * sueltas (p. ej. «Backup sign certificate», con la que firma las copias) y solicitudes sin
 * certificado: esas no son certificados del inventario.
 */
export function hasPemCertificate(raw: string): boolean {
  return PEM_CERT.test(decodePleskPem(raw) ?? '');
}

/**
 * Datos públicos del primer certificado de un PEM. Si el texto trajera además una clave privada
 * (no debería: la consulta no la pide), se ignora: solo se lee el bloque CERTIFICATE. null si no
 * hay certificado o no se entiende.
 */
export function parseCertificate(raw: string): ParsedCertificate | null {
  const block = PEM_CERT.exec(decodePleskPem(raw) ?? '')?.[0];
  if (!block) return null;
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(block);
  } catch {
    return null;
  }
  return x509Facts(cert);
}

/** Datos públicos de un certificado ya leído (de Plesk o del 443 de un registro). */
export function x509Facts(cert: X509Certificate): ParsedCertificate {
  const subject = dn(cert.subject);
  const issuer = dn(cert.issuer);
  return {
    subject,
    subjectAltNames: (cert.subjectAltName ?? '')
      .split(/,\s*/)
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 100),
    issuer,
    notBefore: iso(cert.validFrom),
    notAfter: iso(cert.validTo),
    fingerprint256: cert.fingerprint256,
    selfSigned: cert.subject === cert.issuer && cert.verify(cert.publicKey),
    letsEncrypt: /Let's Encrypt/i.test(cert.issuer),
  };
}

/** `CN=a\nO=b` → `CN=a, O=b`. */
function dn(value: string): string | null {
  const text = value
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
    .join(', ');
  return text ? text.slice(0, 512) : null;
}

function iso(value: string): string | null {
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

/**
 * Clave natural de un certificado leído en el 443 de un registro DNS: su huella. La misma huella
 * llegada por Plesk es el mismo asset (Plesk la lleva como alias y lo adopta).
 */
export function tlsCertificateKey(fingerprint256: string): string {
  return `tls:${fingerprint256.toUpperCase()}`;
}
