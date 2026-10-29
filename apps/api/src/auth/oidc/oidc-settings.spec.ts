import {
  claimValues,
  parseRoleMapping,
  resolveRole,
  safeReturnPath,
} from './oidc-settings.js';

describe('parseRoleMapping', () => {
  it('grupo=rol separados por comas, con espacios y = dentro del grupo', () => {
    const mapping = parseRoleMapping(
      ' infra admins = admin ,editores=editor,a=b=viewer',
    );
    expect([...mapping]).toEqual([
      ['infra admins', 'admin'],
      ['editores', 'editor'],
      ['a=b', 'viewer'],
    ]);
  });

  it('vacío → sin mapeo', () => {
    expect(parseRoleMapping(undefined).size).toBe(0);
    expect(parseRoleMapping('  ').size).toBe(0);
  });

  it('rechaza roles desconocidos, entradas sin = y grupos con dos roles', () => {
    expect(() => parseRoleMapping('admins=root')).toThrow(/rol desconocido/);
    expect(() => parseRoleMapping('admins')).toThrow(/grupo=rol/);
    expect(() => parseRoleMapping('=admin')).toThrow(/grupo=rol/);
    expect(() => parseRoleMapping('g=admin,g=viewer')).toThrow(/dos roles/);
    expect(parseRoleMapping('g=admin,g=admin').size).toBe(1);
  });
});

describe('claimValues', () => {
  it('lista, texto o nada', () => {
    expect(claimValues({ groups: ['a', 1, 'b'] }, 'groups')).toEqual([
      'a',
      'b',
    ]);
    expect(claimValues({ groups: 'a' }, 'groups')).toEqual(['a']);
    expect(claimValues({ groups: { a: 1 } }, 'groups')).toEqual([]);
    expect(claimValues({}, 'groups')).toEqual([]);
  });

  it('ruta con puntos (Keycloak realm_access.roles)', () => {
    expect(
      claimValues({ realm_access: { roles: ['r1'] } }, 'realm_access.roles'),
    ).toEqual(['r1']);
    expect(claimValues({ realm_access: ['x'] }, 'realm_access.roles')).toEqual(
      [],
    );
  });

  it('el nombre literal tiene prioridad (claims con URL)', () => {
    const claims = { 'https://example.com/groups': ['g'] };
    expect(claimValues(claims, 'https://example.com/groups')).toEqual(['g']);
  });
});

describe('resolveRole', () => {
  const mapping = parseRoleMapping(
    'a=admin,e=editor,o=operator,au=auditor,v=viewer',
  );

  it('con varios grupos, el rol con más permisos', () => {
    expect(resolveRole(['v', 'o', 'e'], mapping, 'deny')).toEqual({
      role: 'editor',
      matched: ['v', 'o', 'e'],
    });
    expect(resolveRole(['au', 'o'], mapping, 'deny').role).toBe('operator');
    expect(resolveRole(['x', 'a'], mapping, 'deny')).toEqual({
      role: 'admin',
      matched: ['a'],
    });
  });

  it('sin grupo con rol: denegado o viewer según la configuración', () => {
    expect(resolveRole(['x'], mapping, 'deny')).toEqual({
      role: null,
      matched: [],
    });
    expect(resolveRole([], mapping, 'viewer')).toEqual({
      role: 'viewer',
      matched: [],
    });
  });
});

describe('safeReturnPath', () => {
  it('solo rutas relativas del mismo origen', () => {
    expect(safeReturnPath('/assets?x=1#y')).toBe('/assets?x=1#y');
    for (const bad of [
      undefined,
      42,
      '',
      'https://evil.example',
      '//evil.example',
      '/\\evil.example',
      '/a\nb',
      `/${'a'.repeat(3000)}`,
    ])
      expect(safeReturnPath(bad)).toBe('/');
  });
});
