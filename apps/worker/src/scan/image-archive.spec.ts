import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { ImageArchiveError, readArchive, verifyImageArchive } from './image-archive.js';

const sha = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');

/** Cabecera ustar de un fichero (con el checksum bien calculado). */
function header(name: string, size: number, type = '0'): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124);
  h.write('00000000000\0', 136);
  h.write(type, 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  h.fill(' ', 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  return h;
}

function pad(data: Buffer): Buffer {
  const rest = data.length % 512;
  return rest ? Buffer.concat([data, Buffer.alloc(512 - rest)]) : data;
}

/** Tar con esos ficheros, en ese orden (los nombres de más de 99 caracteres, con PAX). */
function tar(files: [string, string | Buffer][]): Buffer {
  const parts: Buffer[] = [];
  for (const [name, content] of files) {
    const data = Buffer.from(content);
    if (name.length > 99) {
      const record = ` path=${name}\n`;
      let len = record.length + 2;
      while (`${len}${record}`.length !== len) len++;
      const pax = Buffer.from(`${len}${record}`);
      parts.push(header('PaxHeader', pax.length, 'x'), pad(pax));
      parts.push(header(name.slice(0, 99), data.length), pad(data));
    } else parts.push(header(name, data.length), pad(data));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

/** docker-archive como el de `podman save --format docker-archive` y su image ID. */
function dockerArchive(
  layers: string[],
  tweak: (files: [string, string | Buffer][]) => [string, string | Buffer][] = (f) => f,
) {
  const config = JSON.stringify({
    architecture: 'amd64',
    rootfs: { type: 'layers', diff_ids: layers.map((l) => `sha256:${sha(l)}`) },
  });
  const configName = `${sha(config)}.json`;
  const layerNames = layers.map((l) => `${sha(l)}.tar`);
  const manifest = JSON.stringify([
    { Config: configName, RepoTags: ['localhost/app:latest'], Layers: layerNames },
  ]);
  const files: [string, string | Buffer][] = [
    ...layers.map((l, i): [string, string] => [layerNames[i]!, l]),
    [configName, config],
    ['manifest.json', manifest],
  ];
  return { imageId: `sha256:${sha(config)}`, tar: tar(tweak(files)) };
}

describe('docker-archive de un almacén rootless', () => {
  const dir = mkdtempSync(join(tmpdir(), 'image-archive-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  let n = 0;
  const write = (data: Buffer) => {
    const path = join(dir, `image-${++n}.tar`);
    writeFileSync(path, data);
    return path;
  };

  it('acepta el de la imagen pedida (config y capas)', async () => {
    const { imageId, tar } = dockerArchive(['capa base', 'capa app']);
    await expect(verifyImageArchive(write(tar), imageId)).resolves.toBeUndefined();
  });

  it('rechaza el config real con otras capas (ocultaría los CVE)', async () => {
    const { imageId, tar } = dockerArchive(['capa base', 'capa app'], (files) =>
      files.map(([name, content]) =>
        name === `${sha('capa app')}.tar` ? [name, 'capa sin vulnerabilidades'] : [name, content],
      ),
    );
    await expect(verifyImageArchive(write(tar), imageId)).rejects.toThrow(
      'La capa 2 no es la del config de la imagen',
    );
  });

  it('rechaza otra imagen', async () => {
    const { tar } = dockerArchive(['otra']);
    await expect(
      verifyImageArchive(write(tar), `sha256:${'b'.repeat(64)}`),
    ).rejects.toThrow('El config no es el de la imagen pedida');
  });

  it('rechaza nombres repetidos (cada herramienta lee una copia distinta)', async () => {
    const { imageId, tar } = dockerArchive(['capa'], (files) => [
      ...files,
      [`${sha('capa')}.tar`, 'otra capa'],
    ]);
    await expect(verifyImageArchive(write(tar), imageId)).rejects.toThrow(/repetido/);
  });

  it('rechaza un layout OCI (index.json) y un tar sin manifest.json o cortado', async () => {
    const { imageId, tar: good } = dockerArchive(['capa'], (files) => [
      ...files,
      ['index.json', '{"manifests":[]}'],
    ]);
    await expect(verifyImageArchive(write(good), imageId)).rejects.toThrow(/index\.json/);
    await expect(
      verifyImageArchive(write(tar([['otro', 'x']])), imageId),
    ).rejects.toThrow('El archivo no trae manifest.json');
    await expect(
      verifyImageArchive(write(dockerArchive(['capa']).tar.subarray(0, 700)), imageId),
    ).rejects.toBeInstanceOf(ImageArchiveError);
  });

  it('lee los nombres largos (PAX) y los `./` del principio', async () => {
    const long = `${'d'.repeat(64)}/${'e'.repeat(60)}/layer.tar`;
    const entries = await readArchive(
      write(tar([[long, 'contenido'], ['./manifest.json', '[]']])),
    );
    expect(entries.get(long)?.sha256).toBe(sha('contenido'));
    expect(entries.get('manifest.json')?.json).toBe('[]');
  });
});
