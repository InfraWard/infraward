import { describe, expect, it } from 'vitest';
import { accessRuleApplies, canAccess, type AccessAssetContext } from './access.js';

const ct: AccessAssetContext = {
  assetId: 'ct',
  ancestorIds: ['node'],
  tags: ['web', 'producción'],
  projectIds: ['p1'],
};
const rule = (r: Partial<Parameters<typeof canAccess>[2][number]>) => ({
  permission: 'terminal.open' as const,
  subjectType: 'user' as const,
  userId: 'u1',
  role: null,
  scope: 'asset' as const,
  assetId: null,
  tag: null,
  projectId: null,
  ...r,
});
const editor = { id: 'u1', role: 'editor' as const };

describe('accessRuleApplies', () => {
  it('asset propio, antepasado, etiqueta y proyecto', () => {
    expect(accessRuleApplies(rule({ assetId: 'ct' }), ct)).toEqual({ kind: 'own' });
    expect(accessRuleApplies(rule({ assetId: 'node' }), ct)).toEqual({
      kind: 'inherited',
      assetId: 'node',
    });
    expect(accessRuleApplies(rule({ scope: 'tag', tag: 'producción' }), ct)).toEqual({
      kind: 'tag',
      tag: 'producción',
    });
    expect(accessRuleApplies(rule({ scope: 'project', projectId: 'p1' }), ct)).toEqual({
      kind: 'project',
      projectId: 'p1',
    });
  });

  it('no alcanza a hermanos, otras etiquetas ni otros proyectos', () => {
    expect(accessRuleApplies(rule({ assetId: 'otro' }), ct)).toBeNull();
    expect(accessRuleApplies(rule({ scope: 'tag', tag: 'Web' }), ct)).toBeNull();
    expect(accessRuleApplies(rule({ scope: 'project', projectId: 'p2' }), ct)).toBeNull();
    // Una regla en el CT no sube al nodo.
    expect(
      accessRuleApplies(rule({ assetId: 'ct' }), { ...ct, assetId: 'node', ancestorIds: [] }),
    ).toBeNull();
  });
});

describe('canAccess', () => {
  it('admin siempre; los demás solo con una regla suya o de su rol', () => {
    expect(canAccess({ id: 'a', role: 'admin' }, 'terminal.open', [], ct)).toBe(true);
    expect(canAccess(editor, 'terminal.open', [], ct)).toBe(false);
    expect(canAccess(editor, 'terminal.open', [rule({ assetId: 'node' })], ct)).toBe(true);
    expect(canAccess(editor, 'terminal.open', [rule({ userId: 'u2', assetId: 'node' })], ct)).toBe(
      false,
    );
    expect(
      canAccess(
        editor,
        'terminal.open',
        [rule({ subjectType: 'role', userId: null, role: 'editor', scope: 'tag', tag: 'web' })],
        ct,
      ),
    ).toBe(true);
    expect(
      canAccess(
        editor,
        'terminal.open',
        [rule({ subjectType: 'role', userId: null, role: 'operator', scope: 'tag', tag: 'web' })],
        ct,
      ),
    ).toBe(false);
  });
});
