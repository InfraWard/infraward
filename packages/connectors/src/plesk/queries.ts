/**
 * Consultas FIJAS de solo lectura del descubridor de Plesk a su base de datos (`psa`) con
 * `plesk db` (DESIGN §8). Van dentro del ayudante de root `infraward-query` que instala el script
 * de alta (consultas `plesk-<nombre>`, sudoers v4): el usuario de inventario no puede lanzar otra.
 * Si cambia una, cambia la versión del sudoers (un test de la API ejecuta el ayudante y exige que
 * lleve exactamente estas).
 *
 * Cada fila sale como un `JSON_OBJECT` en una línea (`-B -N -r`: sin cabecera ni escapes de
 * mysql; JSON ya escapa los saltos de línea). Solo columnas de una lista blanca: NUNCA
 * contraseñas (`accounts`, `db_users`, `DatabaseServers.admin_password`) ni la clave privada o
 * el CSR de los certificados (`pvt_key`, `csr`).
 *
 * Sin comillas dobles, `$`, `\` ni acentos graves: van entre comillas dobles en el ayudante.
 */
export const PLESK_QUERIES = {
  domains:
    "SELECT JSON_OBJECT('id', d.id, 'name', d.name, 'status', d.status, 'htype', d.htype, " +
    "'webspace', d.webspace_id, 'parent', d.parentDomainId, 'created', d.cr_date, " +
    "'owner', c.login, 'certificate', h.certificate_id) FROM domains d " +
    'LEFT JOIN clients c ON c.id = d.cl_id LEFT JOIN hosting h ON h.dom_id = d.id ORDER BY d.id',
  aliases:
    "SELECT JSON_OBJECT('id', a.id, 'name', a.name, 'status', a.status, 'domain', a.dom_id) " +
    'FROM domain_aliases a ORDER BY a.id',
  databases:
    "SELECT JSON_OBJECT('id', b.id, 'name', b.name, 'type', b.type, 'domain', b.dom_id, " +
    "'host', s.host, 'port', s.port) FROM data_bases b " +
    'LEFT JOIN DatabaseServers s ON s.id = b.db_server_id ORDER BY b.id',
  certificates:
    "SELECT JSON_OBJECT('id', c.id, 'name', c.name, 'cert', c.cert, 'domain', d.id) " +
    'FROM certificates c LEFT JOIN Repository r ON r.component_id = c.id ' +
    'LEFT JOIN domains d ON d.cert_rep_id = r.rep_id ORDER BY c.id',
} as const;
export type PleskQuery = keyof typeof PLESK_QUERIES;
