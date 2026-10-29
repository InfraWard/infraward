import { Marked, type Tokens } from 'marked';

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

/** Solo enlaces http(s) y mailto; el resto se queda como texto. */
const SAFE_LINK = /^(https?:|mailto:)/i;

/**
 * Markdown de las notas (GFM con saltos de línea). El HTML en bruto se muestra como texto, los
 * enlaces solo pueden ser http(s) o mailto (y abren en otra pestaña sin `opener`) y las imágenes
 * se quedan en un enlace (la CSP no deja cargar imágenes de fuera). El resultado pasa además por
 * el saneador de Angular al pintarlo con `[innerHTML]`.
 */
const markdown = new Marked({
  gfm: true,
  breaks: true,
  async: false,
  renderer: {
    html({ text }: Tokens.HTML | Tokens.Tag): string {
      return escapeHtml(text);
    },
    link({ href, title, tokens }: Tokens.Link): string {
      const text = this.parser.parseInline(tokens);
      if (!SAFE_LINK.test(href)) return text;
      const t = title ? ` title="${escapeHtml(title)}"` : '';
      return `<a href="${escapeHtml(href)}"${t} target="_blank" rel="noopener noreferrer">${text}</a>`;
    },
    image({ href, text }: Tokens.Image): string {
      if (!SAFE_LINK.test(href)) return escapeHtml(text);
      return `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text || href)}</a>`;
    },
  },
});

export function renderMarkdown(text: string | null | undefined): string {
  if (!text?.trim()) return '';
  return markdown.parse(text) as string;
}
