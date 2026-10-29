import { describe, expect, it } from 'vitest';
import { InvalidSecretRefError } from './errors.js';
import { formatSecretRef, parseSecretRef } from './secret-ref.js';

describe('parseSecretRef', () => {
  it('descompone proveedor, ruta y campo', () => {
    expect(
      parseSecretRef('secret://openbao/infra/proxmox-pve1#private_key'),
    ).toEqual({
      provider: 'openbao',
      path: 'infra/proxmox-pve1',
      field: 'private_key',
    });
  });

  it('el campo es opcional', () => {
    expect(parseSecretRef('secret://local/assets/abc.def_1')).toEqual({
      provider: 'local',
      path: 'assets/abc.def_1',
    });
  });

  it('admite ids de ítem como ruta (vaultwarden)', () => {
    expect(
      parseSecretRef(
        'secret://vaultwarden/6f1c1e0a-3b4b-4c56-9b7e-1d2f3a4b5c6d#api_token',
      ).path,
    ).toBe('6f1c1e0a-3b4b-4c56-9b7e-1d2f3a4b5c6d');
  });

  it.each([
    ['', 'vacía'],
    ['local/a#b', 'sin esquema'],
    ['secrets://local/a', 'otro esquema'],
    ['SECRET://local/a', 'esquema en mayúsculas'],
    ['secret://local', 'sin ruta'],
    ['secret://local/', 'ruta vacía'],
    ['secret:///a', 'sin proveedor'],
    ['secret://Local/a', 'proveedor con mayúsculas'],
    ['secret://1local/a', 'proveedor que empieza por número'],
    ['secret://lo_cal/a', 'proveedor con guion bajo'],
    ['secret://local/a//b', 'segmento vacío'],
    ['secret://local/a/', 'barra final'],
    ['secret://local//a', 'barra inicial en la ruta'],
    ['secret://local/a/../b', 'segmento ..'],
    ['secret://local/./a', 'segmento .'],
    ['secret://local/a b', 'espacio'],
    ['secret://local/a?x=1', 'query'],
    ['secret://user@local/a', 'usuario'],
    ['secret://local:8200/a', 'puerto'],
    ['secret://local/a%2Fb', 'escape'],
    ['secret://local/a#', 'campo vacío'],
    ['secret://local/a#b#c', 'dos campos'],
    ['secret://local/a#b/c', 'campo con barra'],
    ['secret://local/ä', 'no ASCII'],
    [`secret://local/${'a'.repeat(1100)}`, 'demasiado larga'],
  ])('rechaza %j (%s)', (ref) => {
    expect(() => parseSecretRef(ref)).toThrow(InvalidSecretRefError);
  });

  it('rechaza lo que no es un texto', () => {
    expect(() => parseSecretRef(42 as unknown as string)).toThrow(
      InvalidSecretRefError,
    );
  });

  it('el error lleva el código invalid_ref', () => {
    try {
      parseSecretRef('nope');
      expect.unreachable();
    } catch (e) {
      expect((e as InvalidSecretRefError).code).toBe('invalid_ref');
    }
  });
});

describe('formatSecretRef', () => {
  it('es la inversa de parseSecretRef', () => {
    for (const ref of ['secret://local/a/b#c', 'secret://openbao/x']) {
      expect(formatSecretRef(parseSecretRef(ref))).toBe(ref);
    }
  });

  it('valida lo que construye', () => {
    expect(() => formatSecretRef({ provider: 'local', path: '../x' })).toThrow(
      InvalidSecretRefError,
    );
  });
});
