import type { TerminalServerMessage } from '@infraward/shared-types';
import WebSocket from 'ws';

/** Cliente de pruebas del WebSocket del gateway: guarda la salida y los mensajes de control. */
export class TestTerminal {
  output = '';
  readonly messages: TerminalServerMessage[] = [];
  readonly closed: Promise<{ code: number; reason: string }>;

  private constructor(readonly ws: WebSocket) {
    ws.on('message', (data, isBinary) => {
      if (isBinary) this.output += (data as Buffer).toString('utf8');
      else this.messages.push(JSON.parse(String(data)) as TerminalServerMessage);
    });
    this.closed = new Promise((done) =>
      ws.on('close', (code, reason) => done({ code, reason: reason.toString() })),
    );
  }

  /** Conecta y manda el ticket (primer mensaje). */
  static async open(
    url: string,
    ticket: string,
    size = { cols: 80, rows: 24 },
    headers: Record<string, string> = {},
  ): Promise<TestTerminal> {
    const ws = new WebSocket(url, { headers });
    const terminal = new TestTerminal(ws);
    await new Promise<void>((done, fail) => {
      ws.once('open', () => done());
      ws.once('error', fail);
      ws.once('unexpected-response', (_req, res) => fail(new Error(`HTTP ${res.statusCode}`)));
    });
    ws.send(JSON.stringify({ type: 'auth', ticket, ...size }));
    return terminal;
  }

  type(text: string): void {
    this.ws.send(Buffer.from(text), { binary: true });
  }

  resize(cols: number, rows: number): void {
    this.ws.send(JSON.stringify({ type: 'resize', cols, rows }));
  }

  message<T extends TerminalServerMessage['type']>(
    type: T,
  ): Extract<TerminalServerMessage, { type: T }> | undefined {
    return this.messages.find((m) => m.type === type) as
      | Extract<TerminalServerMessage, { type: T }>
      | undefined;
  }

  /** Espera a que la salida (o un mensaje de control) cumpla la condición. */
  async until(
    condition: (t: TestTerminal) => boolean,
    what: string,
    timeoutMs = 20_000,
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!condition(this)) {
      if (Date.now() > deadline)
        throw new Error(
          `Timeout esperando ${what}. Salida:\n${this.output}\nMensajes: ${JSON.stringify(this.messages)}`,
        );
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  async waitOutput(text: string | RegExp, timeoutMs?: number): Promise<void> {
    await this.until(
      (t) => (typeof text === 'string' ? t.output.includes(text) : text.test(t.output)),
      String(text),
      timeoutMs,
    );
  }

  async waitExit(timeoutMs?: number): Promise<Extract<TerminalServerMessage, { type: 'exit' }>> {
    await this.until((t) => !!t.message('exit'), 'el mensaje exit', timeoutMs);
    return this.message('exit')!;
  }
}
