import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';

const BLOCK = 512;
/** Ficheros JSON que se guardan en memoria al leer el tar (manifest.json y el config). */
const JSON_MAX_BYTES = 4 * 1024 * 1024;
const CHUNK = 1024 * 1024;

/** El tar no es la imagen pedida (o no se puede comprobar). El mensaje es apto para enseñarlo. */
export class ImageArchiveError extends Error {
  override readonly name = 'ImageArchiveError';
}

interface ArchiveEntry {
  sha256: string;
  /** Contenido de los `.json` pequeños. */
  json?: string;
}

/**
 * Comprueba un `docker-archive` (`podman save --format docker-archive`) contra el image ID pedido
 * (DESIGN §9): el config de `manifest.json` tiene ese sha256 y cada capa, el sha256 de su
 * `rootfs.diff_ids`. Hace falta cuando la imagen sale del almacén de un usuario rootless: el tar
 * lo produce un servicio que controla él, y Trivy solo comprueba el config (con el config real de
 * una imagen pública y otras capas, ocultaría sus CVE). Una sola pasada por el tar, sin extraer.
 * @throws ImageArchiveError si no cuadra.
 */
export async function verifyImageArchive(path: string, imageId: string): Promise<void> {
  const entries = await readArchive(path);
  if (entries.has('index.json'))
    throw new ImageArchiveError('El archivo trae index.json: se esperaba un docker-archive');
  const manifestJson = entries.get('manifest.json')?.json;
  if (!manifestJson) throw new ImageArchiveError('El archivo no trae manifest.json');
  let manifest: unknown;
  try {
    manifest = JSON.parse(manifestJson);
  } catch {
    throw new ImageArchiveError('manifest.json no es JSON');
  }
  if (!Array.isArray(manifest) || manifest.length !== 1)
    throw new ImageArchiveError('manifest.json tiene que describir una sola imagen');
  const { Config: configName, Layers: layers } = manifest[0] as {
    Config?: unknown;
    Layers?: unknown;
  };
  if (typeof configName !== 'string' || !Array.isArray(layers))
    throw new ImageArchiveError('manifest.json sin Config o Layers');
  const config = entries.get(normalize(configName));
  if (!config?.json) throw new ImageArchiveError('Falta el config de la imagen');
  if (`sha256:${config.sha256}` !== imageId)
    throw new ImageArchiveError('El config no es el de la imagen pedida');
  let diffIds: unknown;
  try {
    diffIds = (JSON.parse(config.json) as { rootfs?: { diff_ids?: unknown } }).rootfs?.diff_ids;
  } catch {
    throw new ImageArchiveError('El config no es JSON');
  }
  if (!Array.isArray(diffIds) || diffIds.length !== layers.length)
    throw new ImageArchiveError('Las capas no coinciden con rootfs.diff_ids');
  layers.forEach((layer, i) => {
    const entry = typeof layer === 'string' ? entries.get(normalize(layer)) : undefined;
    if (!entry || `sha256:${entry.sha256}` !== diffIds[i])
      throw new ImageArchiveError(`La capa ${i + 1} no es la del config de la imagen`);
  });
}

/** `./a/b` → `a/b`. */
function normalize(name: string): string {
  return name.replace(/^(?:\.\/)+/, '');
}

/**
 * sha256 de cada fichero del tar (ustar, con nombres largos GNU y PAX) y el contenido de los
 * `.json` pequeños. Un nombre repetido se rechaza: cada herramienta se queda con una copia
 * distinta (la primera o la última) y lo comprobado no sería lo analizado.
 */
export async function readArchive(path: string): Promise<Map<string, ArchiveEntry>> {
  const file = await open(path, 'r');
  const entries = new Map<string, ArchiveEntry>();
  try {
    let offset = 0;
    let longName: string | null = null;
    const header = Buffer.alloc(BLOCK);
    for (;;) {
      const { bytesRead } = await file.read(header, 0, BLOCK, offset);
      if (bytesRead < BLOCK) throw new ImageArchiveError('Tar cortado');
      offset += BLOCK;
      if (header.every((b) => b === 0)) break;
      const size = octal(header.subarray(124, 136));
      const type = String.fromCharCode(header[156]!);
      const data = offset;
      offset += Math.ceil(size / BLOCK) * BLOCK;
      if (type === 'L' || type === 'x') {
        if (size > 64 * 1024) throw new ImageArchiveError('Cabecera de tar demasiado grande');
        const buf = Buffer.alloc(size);
        await file.read(buf, 0, size, data);
        const text = buf.toString('utf8');
        longName =
          type === 'L'
            ? text.replace(/\0.*$/s, '')
            : (/(?:^|\n)\d+ path=([^\n]*)\n/.exec(text)?.[1] ?? longName);
        continue;
      }
      if (type === 'g') continue;
      const name = normalize(longName ?? ustarName(header));
      longName = null;
      if (type !== '0' && type !== '\0') continue;
      if (entries.has(name)) throw new ImageArchiveError(`Fichero repetido en el tar: ${name}`);
      const hash = createHash('sha256');
      const keep = name.endsWith('.json') && size <= JSON_MAX_BYTES;
      const parts: Buffer[] = [];
      for (let done = 0; done < size; ) {
        const len = Math.min(CHUNK, size - done);
        const buf = Buffer.alloc(len);
        const { bytesRead: n } = await file.read(buf, 0, len, data + done);
        if (n < len) throw new ImageArchiveError('Tar cortado');
        hash.update(buf);
        if (keep) parts.push(buf);
        done += len;
      }
      entries.set(name, {
        sha256: hash.digest('hex'),
        ...(keep ? { json: Buffer.concat(parts).toString('utf8') } : {}),
      });
    }
  } finally {
    await file.close();
  }
  return entries;
}

function ustarName(header: Buffer): string {
  const name = cString(header.subarray(0, 100));
  const magic = header.subarray(257, 262).toString('latin1');
  const prefix = magic === 'ustar' ? cString(header.subarray(345, 500)) : '';
  return prefix ? `${prefix}/${name}` : name;
}

function cString(buf: Buffer): string {
  const end = buf.indexOf(0);
  return buf.subarray(0, end < 0 ? buf.length : end).toString('utf8');
}

/** Tamaño del tar: octal (o base 256 si lleva el bit alto, para los de más de 8 GiB). */
function octal(field: Buffer): number {
  if (field[0]! & 0x80) {
    let n = field[0]! & 0x7f;
    for (const b of field.subarray(1)) n = n * 256 + b;
    return n;
  }
  const text = cString(field).trim();
  if (!/^[0-7]*$/.test(text)) throw new ImageArchiveError('Tar no válido');
  return text ? parseInt(text, 8) : 0;
}
