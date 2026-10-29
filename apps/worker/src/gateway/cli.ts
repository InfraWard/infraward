// Cliente de pruebas de la terminal (sesión 21): sin la web, desde línea de órdenes.
//
//   node dist/gateway/cli.js --api http://localhost:3000 --asset <uuid> [--gateway ws://…]
//
// Entra en la API como una persona (email y contraseña y, con TOTP, el código: la sesión queda
// recién reautenticada), pide la terminal (POST /terminal/sessions) y se conecta al gateway con el
// ticket. Las credenciales se leen de INFRAWARD_EMAIL, INFRAWARD_PASSWORD e INFRAWARD_TOTP o se
// preguntan por la terminal: nunca como argumentos (quedarían en el historial y en `ps`).
import {
  parseTerminalClientMessage,
  terminalSocketUrl,
  type CreateTerminalSessionResponse,
  type TerminalServerMessage,
} from '@infraward/shared-types';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import WebSocket from 'ws';

const { values } = parseArgs({
  options: {
    api: { type: 'string' },
    asset: { type: 'string' },
    gateway: { type: 'string' },
  },
});
if (!values.api || !values.asset) {
  process.stderr.write('Uso: cli.js --api <url de la API> --asset <id> [--gateway <ws://…>]\n');
  process.exit(2);
}
const api = values.api.replace(/\/+$/, '');

async function ask(question: string, hidden = false): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  if (hidden) {
    // Sin eco: se sustituye la escritura de readline mientras se teclea.
    const output = rl as unknown as { _writeToOutput: (s: string) => void };
    output._writeToOutput = (s: string) => {
      if (s.includes(question)) process.stderr.write(s);
    };
  }
  const answer = await rl.question(question);
  rl.close();
  if (hidden) process.stderr.write('\n');
  return answer.trim();
}

let cookie = '';
let csrf = '';

async function call(path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${api}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(cookie && { cookie }),
      ...(csrf && { 'x-csrf-token': csrf }),
    },
    body: JSON.stringify(body),
  });
  const setCookie = res.headers.getSetCookie().find((c) => /iw_session=/.test(c));
  if (setCookie) cookie = setCookie.split(';')[0]!;
  const text = await res.text();
  return { status: res.status, json: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const email = process.env.INFRAWARD_EMAIL || (await ask('Email: '));
const password = process.env.INFRAWARD_PASSWORD || (await ask('Contraseña: ', true));
let res = await call('/auth/login', { email, password });
if (res.status !== 200) fail(`Login: HTTP ${res.status} ${String(res.json.message ?? '')}`);
csrf = String(res.json.csrfToken);
if (res.json.mfaPending) {
  const code = process.env.INFRAWARD_TOTP || (await ask('Código de verificación: '));
  res = await call('/auth/mfa/verify', { code });
  if (res.status !== 200) fail(`Código: HTTP ${res.status} ${String(res.json.message ?? '')}`);
  csrf = String(res.json.csrfToken);
}

res = await call('/terminal/sessions', { assetId: values.asset });
if (res.status !== 201)
  fail(`Terminal rechazada: HTTP ${res.status} ${String(res.json.code ?? '')} ${String(res.json.message ?? '')}`);
const ticket = res.json as unknown as CreateTerminalSessionResponse;
// Con una ruta relativa (`/gateway/terminal`, la web hace de proxy) hace falta --gateway o el
// origen de la API.
const url = values.gateway
  ? `${values.gateway.replace(/\/+$/, '')}/terminal`
  : terminalSocketUrl(ticket.gatewayUrl, new URL(api).origin);

const size = () => ({ cols: process.stdout.columns || 80, rows: process.stdout.rows || 24 });
// La cookie de la sesión que pidió el ticket: el gateway manda su hash a la API al canjearlo.
const ws = new WebSocket(url, { headers: { cookie } });
let code = 1;
const restore = () => {
  if (process.stdin.isTTY) process.stdin.setRawMode(false);
  process.stdin.pause();
};

ws.on('open', () => {
  const auth = { type: 'auth' as const, ticket: ticket.ticket, ...size() };
  if (!parseTerminalClientMessage(JSON.stringify(auth))) fail('Ticket con un formato inesperado');
  ws.send(JSON.stringify(auth));
});
ws.on('message', (data, isBinary) => {
  if (isBinary) {
    process.stdout.write(data as Buffer);
    return;
  }
  const message = JSON.parse(String(data)) as TerminalServerMessage;
  if (message.type === 'ready') {
    process.stderr.write(`[conectado a ${message.asset} como ${message.account}]\r\n`);
    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', (chunk) => ws.send(chunk, { binary: true }));
    process.stdout.on('resize', () => ws.send(JSON.stringify({ type: 'resize', ...size() })));
  } else if (message.type === 'notice') {
    process.stderr.write(`\r\n[aviso] ${message.message}\r\n`);
  } else if (message.type === 'exit') {
    code = message.code ?? (message.reason === 'exit' ? 0 : 1);
    restore();
    process.stderr.write(
      `\r\n[sesión cerrada: ${message.reason}${message.code !== null ? `, código ${message.code}` : ''}${message.message ? ` · ${message.message}` : ''}]\r\n`,
    );
  }
});
ws.on('close', () => {
  restore();
  process.exit(code);
});
ws.on('error', (error) => {
  restore();
  fail(`Gateway: ${error.message}`);
});
