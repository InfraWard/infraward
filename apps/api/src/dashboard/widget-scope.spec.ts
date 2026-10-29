import { describe, expect, it } from 'vitest';
import {
  assetScopeSql,
  scopeKey,
  scopeSearchQuery,
  SqlParams,
} from './widget-scope.js';

const PROJECT = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

describe('assetScopeSql', () => {
  it('sin filtros no añade nada', () => {
    const p = new SqlParams();
    expect(assetScopeSql('a', {}, p.push)).toEqual([]);
    expect(p.values).toEqual([]);
  });

  it('proyecto, tags (alguno) y tipos (alguno), todo parametrizado', () => {
    const p = new SqlParams();
    p.push('antes');
    const where = assetScopeSql(
      'a',
      { projectId: PROJECT, tags: ["prod'; DROP"], types: ['server', 'lxc'] },
      p.push,
    );
    expect(where).toEqual([
      'a.effective_projects @> ARRAY[$2::uuid]',
      'a.tags && $3::text[]',
      'a.type::text = ANY($4::text[])',
    ]);
    expect(p.values).toEqual([
      'antes',
      PROJECT,
      ["prod'; DROP"],
      ['server', 'lxc'],
    ]);
  });
});

describe('scopeSearchQuery', () => {
  it('tags y tipos como búsqueda de vulnerabilidades, con comillas si hace falta', () => {
    expect(scopeSearchQuery({})).toBeUndefined();
    expect(scopeSearchQuery({ projectId: PROJECT })).toBeUndefined();
    expect(
      scopeSearchQuery({ tags: ['prod', 'web prod'], types: ['server'] }),
    ).toBe('tag:prod tag:"web prod" tipo:server');
  });
});

describe('scopeKey', () => {
  it('no depende del orden de tags y tipos', () => {
    expect(scopeKey({ tags: ['b', 'a'], types: ['vm', 'server'] })).toBe(
      scopeKey({ tags: ['a', 'b'], types: ['server', 'vm'] }),
    );
    expect(scopeKey({ projectId: PROJECT })).not.toBe(scopeKey({}));
  });
});
