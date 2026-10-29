import type { EntityManager } from 'typeorm';
import { describe, expect, it, vi } from 'vitest';
import { clip, jobAssetId } from './job-runs.js';

function manager(rows: Record<string, unknown>[] = []) {
  const query = vi.fn(async () => rows);
  return { m: { query } as unknown as EntityManager, query };
}

describe('jobAssetId', () => {
  it('usa el assetId de los datos sin consultar la BD', async () => {
    const { m, query } = manager();
    expect(await jobAssetId(m, 'asset.collect', { assetId: 'a1' })).toBe('a1');
    expect(query).not.toHaveBeenCalled();
  });

  it('verificación de alta: el asset del enrolamiento', async () => {
    const { m, query } = manager([{ asset_id: 'a2' }]);
    expect(await jobAssetId(m, 'enrollment.verify', { enrollmentId: 'e1' })).toBe('a2');
    expect(query).toHaveBeenCalledWith(expect.stringContaining('FROM enrollments'), ['e1']);
  });

  it('escaneo: el asset image de la imagen; sin fila, null', async () => {
    const { m, query } = manager([{ asset_id: 'img' }]);
    expect(await jobAssetId(m, 'image.scan', { imageId: 'sha256:x' })).toBe('img');
    expect(query).toHaveBeenCalledWith(expect.stringContaining('FROM container_images'), [
      'sha256:x',
    ]);
    expect(await jobAssetId(manager().m, 'image.scan', { imageId: 'sha256:y' })).toBeNull();
  });

  it('ping y datos raros: null', async () => {
    const { m } = manager();
    expect(await jobAssetId(m, 'ping', { steps: 1 })).toBeNull();
    expect(await jobAssetId(m, 'asset.collect', null)).toBeNull();
  });
});

describe('clip', () => {
  it('recorta con elipsis al máximo y deja null lo vacío', () => {
    expect(clip('abcdef', 4)).toBe('abc…');
    expect(clip('abc', 4)).toBe('abc');
    expect(clip('', 4)).toBeNull();
    expect(clip(undefined, 4)).toBeNull();
  });
});
