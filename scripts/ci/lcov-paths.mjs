// Los lcov de Vitest y de `ng test` llevan las rutas relativas a su paquete (`SF:src/…`), y
// SonarQube las resuelve desde la raíz del repo: les antepone el directorio del paquete.
// Uso: node scripts/ci/lcov-paths.mjs (busca apps/*/coverage/**/lcov.info y packages/*/…)
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, posix } from 'node:path';

function lcovFiles(dir) {
  let found = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) found = found.concat(lcovFiles(path));
    else if (entry === 'lcov.info') found.push(path);
  }
  return found;
}

let total = 0;
for (const root of ['apps', 'packages']) {
  for (const pkg of readdirSync(root)) {
    const coverage = join(root, pkg, 'coverage');
    let files = [];
    try {
      files = lcovFiles(coverage);
    } catch {
      continue; // sin cobertura (no se testeó en este pipeline)
    }
    for (const file of files) {
      const prefix = posix.join(root, pkg);
      const text = readFileSync(file, 'utf8').replace(/^SF:(.+)$/gm, (line, path) =>
        isAbsolute(path) || path.startsWith(`${prefix}/`) ? line : `SF:${posix.join(prefix, path)}`,
      );
      writeFileSync(file, text);
      total++;
      console.log(`${file}: rutas desde la raíz (${prefix}/…)`);
    }
  }
}
if (total === 0) console.log('Ningún lcov.info que reescribir');
