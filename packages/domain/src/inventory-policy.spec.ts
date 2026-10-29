import { describe, expect, it } from 'vitest';
import {
  policyValues,
  resolvePolicies,
  type PolicyAssetInput,
  type PolicyRuleInput,
} from './inventory-policy.js';

const asset = (
  id: string,
  parentId: string | null,
  extra: Partial<PolicyAssetInput> = {},
): PolicyAssetInput => ({
  id,
  type: 'server',
  status: 'active',
  tags: [],
  parentId,
  ...extra,
});

const global: PolicyRuleInput = {
  scope: 'global',
  assetId: null,
  tag: null,
  reconcileIntervalMinutes: 360,
  scanEnabled: true,
  scanPeriodic: true,
};

const rule = (
  target: { assetId: string } | { tag: string },
  fields: Partial<
    Pick<
      PolicyRuleInput,
      'reconcileIntervalMinutes' | 'scanEnabled' | 'scanPeriodic'
    >
  >,
): PolicyRuleInput => ({
  scope: 'assetId' in target ? 'asset' : 'tag',
  assetId: 'assetId' in target ? target.assetId : null,
  tag: 'tag' in target ? target.tag : null,
  reconcileIntervalMinutes: null,
  scanEnabled: null,
  scanPeriodic: null,
  ...fields,
});

// pve → ct → web1 (contenedor) → imagen nginx (instance_of), otra raíz «solo»
const tree = [
  asset('pve', null),
  asset('ct', 'pve', { type: 'lxc' }),
  asset('web1', 'ct', { type: 'container' }),
  asset('nginx', null, { type: 'image' }),
  asset('solo', null),
];

describe('resolvePolicies', () => {
  it('sin reglas: la global en todo', () => {
    const p = resolvePolicies({
      assets: tree,
      rules: [global],
      imageHolders: new Map(),
    });
    expect(p.get('web1')).toEqual({
      values: {
        reconcileIntervalMinutes: 360,
        scanEnabled: true,
        scanPeriodic: true,
      },
      sources: {
        reconcileIntervalMinutes: { kind: 'global' },
        scanEnabled: { kind: 'global' },
        scanPeriodic: { kind: 'global' },
      },
    });
  });

  it('una regla en un nodo se hereda hacia abajo, campo a campo, salvo regla propia', () => {
    const p = resolvePolicies({
      assets: tree,
      rules: [
        global,
        rule(
          { assetId: 'pve' },
          { scanEnabled: false, reconcileIntervalMinutes: 10 },
        ),
        rule({ assetId: 'web1' }, { scanEnabled: true }),
      ],
      imageHolders: new Map(),
    });
    expect(p.get('pve')!.sources.scanEnabled).toEqual({ kind: 'own' });
    expect(p.get('ct')!.values.scanEnabled).toBe(false);
    expect(p.get('ct')!.sources.scanEnabled).toEqual({
      kind: 'inherited',
      assetId: 'pve',
    });
    expect(p.get('web1')!.values).toEqual({
      reconcileIntervalMinutes: 10,
      scanEnabled: true,
      scanPeriodic: true,
    });
    expect(p.get('web1')!.sources.scanPeriodic).toEqual({ kind: 'global' });
    expect(p.get('solo')!.values.scanEnabled).toBe(true);
  });

  it('el antepasado gana a la etiqueta; entre etiquetas, la más restrictiva', () => {
    const assets = [
      asset('pve', null),
      asset('ct', 'pve', { tags: ['lab', 'prod'] }),
      asset('x', null, { tags: ['lab', 'prod', 'slow'] }),
    ];
    const p = resolvePolicies({
      assets,
      rules: [
        global,
        rule({ assetId: 'pve' }, { scanPeriodic: true }),
        rule(
          { tag: 'lab' },
          {
            scanPeriodic: false,
            scanEnabled: false,
            reconcileIntervalMinutes: 60,
          },
        ),
        rule(
          { tag: 'prod' },
          { scanEnabled: true, reconcileIntervalMinutes: 30 },
        ),
        rule({ tag: 'slow' }, { reconcileIntervalMinutes: 0 }),
      ],
      imageHolders: new Map(),
    });
    expect(p.get('ct')!.values).toEqual({
      reconcileIntervalMinutes: 60,
      scanEnabled: false,
      scanPeriodic: true,
    });
    expect(p.get('ct')!.sources).toEqual({
      reconcileIntervalMinutes: { kind: 'tag', tag: 'lab' },
      scanEnabled: { kind: 'tag', tag: 'lab' },
      scanPeriodic: { kind: 'inherited', assetId: 'pve' },
    });
    // 0 (nunca) es lo más restrictivo
    expect(p.get('x')!.values.reconcileIntervalMinutes).toBe(0);
    expect(p.get('x')!.sources.reconcileIntervalMinutes).toEqual({
      kind: 'tag',
      tag: 'slow',
    });
  });

  it('imagen: escanea si alguno de quienes la usan lo permite; regla propia o sin usuarios, aparte', () => {
    const assets = [
      asset('h1', null),
      asset('h2', null),
      asset('h3', null, { status: 'retired' }),
      asset('img', null, { type: 'image' }),
      asset('img2', null, { type: 'image' }),
      asset('img3', null, { type: 'image' }),
      asset('img4', null, { type: 'image' }),
    ];
    const rules = [
      global,
      rule({ assetId: 'h1' }, { scanEnabled: false, scanPeriodic: false }),
      rule({ assetId: 'img3' }, { scanEnabled: false }),
    ];
    const holders = new Map([
      ['img', ['h1', 'h2']],
      ['img2', ['h1', 'h3']],
      ['img3', ['h2']],
    ]);
    const p = resolvePolicies({ assets, rules, imageHolders: holders });
    expect(p.get('img')!.values.scanEnabled).toBe(true);
    expect(p.get('img')!.sources.scanEnabled).toEqual({ kind: 'holders' });
    // h3 retirado no cuenta: solo h1, que no escanea
    expect(p.get('img2')!.values).toMatchObject({
      scanEnabled: false,
      scanPeriodic: false,
    });
    expect(p.get('img3')!.values.scanEnabled).toBe(false);
    expect(p.get('img3')!.sources.scanEnabled).toEqual({ kind: 'own' });
    expect(p.get('img4')!.sources.scanEnabled).toEqual({ kind: 'global' });
  });

  it('sin fila global usa los valores por defecto; un ciclo no cuelga', () => {
    const p = resolvePolicies({
      assets: [asset('a', 'b'), asset('b', 'a')],
      rules: [],
      imageHolders: new Map(),
    });
    expect(p.get('a')!.values.reconcileIntervalMinutes).toBe(360);
  });
});

describe('resolvePolicies con proyectos', () => {
  const projectRule = (
    projectId: string,
    fields: Partial<
      Pick<
        PolicyRuleInput,
        'reconcileIntervalMinutes' | 'scanEnabled' | 'scanPeriodic'
      >
    >,
  ): PolicyRuleInput => ({
    scope: 'project',
    assetId: null,
    tag: null,
    projectId,
    reconcileIntervalMinutes: null,
    scanEnabled: null,
    scanPeriodic: null,
    ...fields,
  });

  it('la regla del proyecto se aplica a sus assets; entre proyectos, la más restrictiva', () => {
    const p = resolvePolicies({
      assets: [
        asset('pve', null, { projects: ['homelab'] }),
        asset('ct', 'pve', { type: 'lxc', projects: ['homelab', 'prod'] }),
        asset('solo', null),
      ],
      rules: [
        global,
        projectRule('homelab', {
          scanEnabled: false,
          reconcileIntervalMinutes: 60,
        }),
        projectRule('prod', {
          scanEnabled: true,
          reconcileIntervalMinutes: 120,
        }),
      ],
      imageHolders: new Map(),
    });
    expect(p.get('pve')!.values.scanEnabled).toBe(false);
    expect(p.get('pve')!.sources.scanEnabled).toEqual({
      kind: 'project',
      projectId: 'homelab',
    });
    // homelab (false) gana a prod (true); en el intervalo, el más largo (prod, 120).
    expect(p.get('ct')!.values).toMatchObject({
      scanEnabled: false,
      reconcileIntervalMinutes: 120,
    });
    expect(p.get('ct')!.sources.reconcileIntervalMinutes).toEqual({
      kind: 'project',
      projectId: 'prod',
    });
    expect(p.get('solo')!.sources.scanEnabled).toEqual({ kind: 'global' });
  });

  it('la etiqueta gana al proyecto, y la regla de asset (propia o heredada) a los dos', () => {
    const p = resolvePolicies({
      assets: [
        asset('pve', null, { projects: ['homelab'] }),
        asset('ct', 'pve', {
          type: 'lxc',
          tags: ['critico'],
          projects: ['homelab'],
        }),
        asset('web', 'pve', { type: 'lxc', projects: ['homelab'] }),
      ],
      rules: [
        global,
        projectRule('homelab', { scanEnabled: false, scanPeriodic: false }),
        rule({ tag: 'critico' }, { scanEnabled: true }),
        rule({ assetId: 'pve' }, { scanPeriodic: true }),
      ],
      imageHolders: new Map(),
    });
    expect(p.get('ct')!.values.scanEnabled).toBe(true);
    expect(p.get('ct')!.sources.scanEnabled).toEqual({
      kind: 'tag',
      tag: 'critico',
    });
    expect(p.get('web')!.values.scanEnabled).toBe(false);
    expect(p.get('web')!.values.scanPeriodic).toBe(true);
    expect(p.get('web')!.sources.scanPeriodic).toEqual({
      kind: 'inherited',
      assetId: 'pve',
    });
  });

  it('imagen: el proyecto no se aplica directamente, sino a través de quienes la usan', () => {
    const p = resolvePolicies({
      assets: [
        asset('a', null, { projects: ['sin-escaneo'] }),
        asset('b', null, { projects: ['prod'] }),
        asset('img', null, {
          type: 'image',
          projects: ['sin-escaneo', 'prod'],
        }),
      ],
      rules: [global, projectRule('sin-escaneo', { scanEnabled: false })],
      imageHolders: new Map([['img', ['a', 'b']]]),
    });
    expect(p.get('a')!.values.scanEnabled).toBe(false);
    expect(p.get('img')!.values.scanEnabled).toBe(true);
    expect(p.get('img')!.sources.scanEnabled).toEqual({ kind: 'holders' });
  });
});

describe('resolvePolicies · exclusiones (QoL-6b)', () => {
  const ex = (
    target:
      { assetId: string } | { tag: string } | { projectId: string } | 'global',
    scanExclusions: PolicyRuleInput['scanExclusions'],
  ): PolicyRuleInput =>
    target === 'global'
      ? { ...global, scanExclusions }
      : 'projectId' in target
        ? {
            scope: 'project',
            assetId: null,
            tag: null,
            projectId: target.projectId,
            reconcileIntervalMinutes: null,
            scanEnabled: null,
            scanPeriodic: null,
            scanExclusions,
          }
        : { ...rule(target, {}), scanExclusions };
  // pve (stores nginx) → ct → web1 (instance_of nginx); redis solo en «solo».
  const assets = [
    asset('pve', null, { name: 'pve' }),
    asset('ct', 'pve', { type: 'lxc', name: 'ct-web' }),
    asset('web1', 'ct', { type: 'container', name: 'web1' }),
    asset('nginx', null, { type: 'image', name: 'nginx:1.25' }),
    asset('redis', null, { type: 'image', name: 'bitnami/redis:7' }),
    asset('solo', null, { name: 'solo', tags: ['lab'] }),
  ];
  const holders = new Map([
    ['nginx', ['pve', 'web1']],
    ['redis', ['solo']],
  ]);
  const resolve = (rules: PolicyRuleInput[]) =>
    resolvePolicies({
      assets,
      rules: rules.some((r) => r.scope === 'global')
        ? rules
        : [global, ...rules],
      imageHolders: holders,
    });

  it('por tipo en un nodo: lo que contiene hereda y sus imágenes no se escanean', () => {
    const p = resolve([ex({ assetId: 'pve' }, { types: ['image'] })]);
    expect(p.get('pve')!.values.scanEnabled).toBe(true);
    expect(p.get('ct')!.values.scanEnabled).toBe(true);
    expect(p.get('nginx')!.values.scanEnabled).toBe(false);
    expect(p.get('nginx')!.sources.scanEnabled).toEqual({
      kind: 'excluded',
      by: { kind: 'own' },
      match: { kind: 'type', type: 'image' },
      holderId: 'pve',
    });
    // La otra imagen, de otro host, sigue.
    expect(p.get('redis')!.values.scanEnabled).toBe(true);
  });

  it('imagen compartida: sigue escaneando si algún holder la deja', () => {
    const p = resolve([ex({ assetId: 'ct' }, { types: ['image'] })]);
    // web1 (bajo ct) la excluye, pero pve (stores) no.
    expect(p.get('nginx')!.values.scanEnabled).toBe(true);
    expect(p.get('nginx')!.sources.scanEnabled).toEqual({ kind: 'holders' });
  });

  it('por patrón de nombre (glob, sin mayúsculas) y por asset', () => {
    const p = resolve([
      ex('global', { namePatterns: ['BITNAMI/*'] }),
      ex({ assetId: 'pve' }, { assetIds: ['ct'] }),
    ]);
    expect(p.get('redis')!.sources.scanEnabled).toEqual({
      kind: 'excluded',
      by: { kind: 'global' },
      match: { kind: 'pattern', pattern: 'BITNAMI/*' },
    });
    expect(p.get('ct')!.values.scanEnabled).toBe(false);
    expect(p.get('ct')!.sources.scanEnabled).toMatchObject({
      by: { kind: 'inherited', assetId: 'pve' },
      match: { kind: 'asset', assetId: 'ct' },
    });
    expect(p.get('web1')!.values.scanEnabled).toBe(true);
  });

  it('por etiqueta y por proyecto; se suman y ganan a scanEnabled: true', () => {
    const p = resolvePolicies({
      assets: assets.map((a) =>
        a.id === 'ct' ? { ...a, projects: ['p1'] } : a,
      ),
      rules: [
        global,
        ex({ tag: 'lab' }, { types: ['server'] }),
        { ...ex({ projectId: 'p1' }, { types: ['lxc'] }), scanEnabled: true },
      ],
      imageHolders: holders,
    });
    expect(p.get('solo')!.sources.scanEnabled).toMatchObject({
      kind: 'excluded',
      by: { kind: 'tag', tag: 'lab' },
    });
    expect(p.get('ct')!.values.scanEnabled).toBe(false);
    expect(p.get('pve')!.values.scanEnabled).toBe(true);
    // redis solo la usa «solo», que está excluido: no la deja escanear.
    expect(p.get('redis')!.values.scanEnabled).toBe(false);
  });

  it('el resto de campos no cambia y sin exclusiones todo sigue igual', () => {
    const p = resolve([ex({ assetId: 'pve' }, { types: ['image'] })]);
    expect(p.get('nginx')!.values.scanPeriodic).toBe(false);
    expect(p.get('pve')!.values.reconcileIntervalMinutes).toBe(360);
    const none = resolve([ex({ assetId: 'pve' }, {})]);
    expect([...none.values()].every((v) => v.values.scanEnabled)).toBe(true);
  });
});

describe('policyValues', () => {
  it('sin calcular: por defecto', () => {
    expect(policyValues({})).toEqual({
      reconcileIntervalMinutes: 360,
      scanEnabled: true,
      scanPeriodic: true,
    });
  });
});
