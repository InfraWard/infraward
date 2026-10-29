import { countTiles, dashboardLinks, scopeQuery } from './dashboard-links';

describe('dashboardLinks', () => {
  it('sin ámbito, los enlaces de siempre', () => {
    const links = dashboardLinks();
    expect(links.sudoers).toEqual({
      path: '/inventory',
      queryParams: { attention: 'sudoers' },
    });
    expect(links.vulnerabilities).toEqual({ path: '/vulnerabilities' });
  });

  it('con proyecto, tags y tipos, el inventario y las vulnerabilidades los conservan; la actividad no', () => {
    const links = dashboardLinks({
      project: 'p1',
      tags: ['prod', 'web prod'],
      types: ['server'],
    });
    const q = 'tag:prod tag:"web prod" tipo:server';
    expect(links.sudoers.queryParams).toEqual({
      attention: 'sudoers',
      project: 'p1',
      q,
    });
    expect(links.type('lxc').queryParams).toEqual({
      type: 'lxc',
      project: 'p1',
      q,
    });
    expect(links.status('missing').queryParams).toEqual({
      status: 'missing',
      project: 'p1',
      q,
    });
    expect(links.vulnerabilities.queryParams).toEqual({ project: 'p1', q });
    expect(links.failed.queryParams).toEqual({ state: 'failed' });
    expect(scopeQuery({})).toBeUndefined();
  });

  it('countTiles: solo lo que tiene assets y sin enlace en los tipos que no salen en el árbol', () => {
    const tiles = countTiles('type', { server: 2, volume: 1, vm: 0 });
    expect(tiles.map((t) => [t.key, t.count, !!t.link])).toEqual([
      ['server', 2, true],
      ['volume', 1, false],
    ]);
    expect(
      countTiles('status', { active: 3, retired: 1 }).map((t) => t.label),
    ).toEqual(['Activo', 'Retirado']);
  });
});
