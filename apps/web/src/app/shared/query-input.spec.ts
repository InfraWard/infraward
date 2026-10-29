import { currentTokenStart, querySuggestions } from './query-input';

describe('querySuggestions', () => {
  const values = {
    tag: [{ value: 'prueba' }, { value: 'prod' }, { value: 'web prod' }],
    type: [
      { value: 'server', label: 'Servidor' },
      { value: 'image', label: 'Imagen' },
    ],
  };

  it('sugiere claves al escribir (alias en español primero) con la consulta completa', () => {
    const s = querySuggestions('tag:prod no', 'inventory', values);
    expect(s.map((x) => x.value)).toEqual(['tag:prod nombre:']);
    expect(
      querySuggestions('', 'inventory', values).map((x) => x.label),
    ).toContain('ip:');
    // `cve:` solo en vulnerabilidades.
    expect(querySuggestions('cv', 'inventory', values)).toEqual([]);
    expect(
      querySuggestions('cv', 'vulnerabilities', values).map((x) => x.label),
    ).toEqual(['cve:']);
    expect(
      querySuggestions('-ta', 'inventory', values).map((x) => x.value),
    ).toEqual(['-tag:']);
  });

  it('tras clave:, sus valores (por valor o etiqueta), con comillas si hacen falta', () => {
    expect(
      querySuggestions('tag:pr', 'inventory', values).map((x) => x.value),
    ).toEqual(['tag:prueba ', 'tag:prod ', 'tag:"web prod" ']);
    expect(querySuggestions('x tipo:serv', 'inventory', values)).toEqual([
      {
        value: 'x tipo:server ',
        label: 'tipo:server',
        description: 'Servidor',
      },
    ]);
    expect(querySuggestions('foo:', 'inventory', values)).toEqual([]);
    expect(querySuggestions('sitio:', 'inventory', values)).toEqual([]);
  });

  it('el token actual no se parte dentro de comillas', () => {
    expect(currentTokenStart('nombre:"web pr')).toBe(0);
    expect(currentTokenStart('a b')).toBe(2);
  });
});
