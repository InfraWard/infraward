import { describe, expect, it } from 'vitest';
import { parseTerminalClientMessage, terminalSocketUrl } from './terminal.js';

const TICKET = 'A'.repeat(43);

describe('parseTerminalClientMessage', () => {
  it('auth y resize válidos', () => {
    expect(
      parseTerminalClientMessage(JSON.stringify({ type: 'auth', ticket: TICKET, cols: 80, rows: 24 })),
    ).toEqual({ type: 'auth', ticket: TICKET, cols: 80, rows: 24 });
    expect(parseTerminalClientMessage('{"type":"resize","cols":132,"rows":40}')).toEqual({
      type: 'resize',
      cols: 132,
      rows: 40,
    });
  });

  it('rechaza lo que no cuadra: JSON roto, tamaños fuera de rango, tickets raros, otros tipos', () => {
    for (const text of [
      'no es json',
      'null',
      '{"type":"resize","cols":0,"rows":24}',
      '{"type":"resize","cols":80,"rows":501}',
      '{"type":"resize","cols":1.5,"rows":24}',
      '{"type":"resize","cols":"80","rows":24}',
      `{"type":"auth","ticket":"con espacios ${'x'.repeat(30)}","cols":80,"rows":24}`,
      '{"type":"auth","ticket":"corto","cols":80,"rows":24}',
      `{"type":"exec","ticket":"${TICKET}","cols":80,"rows":24}`,
    ])
      expect(parseTerminalClientMessage(text), text).toBeNull();
  });
});

describe('terminalSocketUrl', () => {
  it('completa una ruta relativa con el origen de la página', () => {
    expect(terminalSocketUrl('/gateway/terminal', 'https://infraward.example')).toBe(
      'wss://infraward.example/gateway/terminal',
    );
    expect(terminalSocketUrl('/gateway/terminal', 'http://localhost:4200')).toBe(
      'ws://localhost:4200/gateway/terminal',
    );
    expect(terminalSocketUrl('wss://gw.example/terminal', 'https://x.example')).toBe(
      'wss://gw.example/terminal',
    );
  });
});
