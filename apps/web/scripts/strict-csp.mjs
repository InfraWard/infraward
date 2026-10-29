#!/usr/bin/env node
// Paso posterior a la build de producción: quita 'unsafe-inline' de script-src en la CSP de
// src/index.html. El autoCsp de Angular (angular.json, security.autoCsp) añade otra CSP <meta> con
// el sha256 de sus scripts de carga inline; el navegador aplica las dos, así que la primera
// necesita esos hashes en lugar de 'unsafe-inline' para que el cargador corra. Si alguna de las
// dos no está donde se espera, la build falla: la CSP nunca vuelve a inline sin avisar.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const file = resolve(process.argv[2] ?? 'dist/web/browser/index.html');
const html = readFileSync(file, 'utf8');

const metas = [...html.matchAll(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/g)];
const auto = metas.find((m) => m[1].includes("'strict-dynamic'"));
if (!auto) throw new Error(`${file}: no autoCsp policy found (security.autoCsp in angular.json?)`);
const hashes = auto[1].match(/'sha256-[A-Za-z0-9+/=]+'/g) ?? [];
if (hashes.length === 0) throw new Error(`${file}: the autoCsp policy has no script hashes`);

const LOOSE = "script-src 'self' 'unsafe-inline'";
const own = metas.find((m) => m !== auto && m[1].includes(LOOSE));
if (!own) {
  if (metas.some((m) => m !== auto && /script-src 'self' 'sha256-/.test(m[1]))) {
    console.log(`strict-csp: ${file} already processed`);
    process.exit(0);
  }
  throw new Error(`${file}: no CSP with "${LOOSE}" to tighten`);
}
const strict = own[0].replace(LOOSE, `script-src 'self' ${hashes.join(' ')}`);
writeFileSync(file, html.replace(own[0], strict));
console.log(`strict-csp: script-src without 'unsafe-inline' (${hashes.length} hashes) in ${file}`);
