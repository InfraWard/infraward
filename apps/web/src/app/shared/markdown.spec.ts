import { renderMarkdown } from './markdown';

describe('renderMarkdown', () => {
  it('pinta el Markdown habitual (GFM, saltos de línea)', () => {
    const html = renderMarkdown('# Título\n\n- **uno**\n- `dos`\nlínea\notra');
    expect(html).toContain('<h1>Título</h1>');
    expect(html).toContain('<strong>uno</strong>');
    expect(html).toContain('<code>dos</code>');
    expect(html).toContain('línea<br>otra');
  });

  it('el HTML en bruto sale como texto', () => {
    const html = renderMarkdown('<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<script');
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;script&gt;');
  });

  it('solo enlaces http(s) y mailto, en otra pestaña y sin opener', () => {
    expect(renderMarkdown('[web](https://ejemplo.org)')).toContain(
      '<a href="https://ejemplo.org" target="_blank" rel="noopener noreferrer">web</a>',
    );
    const js = renderMarkdown('[mal](javascript:alert(1))');
    expect(js).not.toContain('<a');
    expect(js).toContain('mal');
    expect(renderMarkdown('![logo](https://ejemplo.org/x.png)')).not.toContain('<img');
  });

  it('vacío: nada', () => {
    expect(renderMarkdown('  ')).toBe('');
    expect(renderMarkdown(null)).toBe('');
  });
});
