// Espera a que respondan uno o más puertos TCP (host:puerto). En CI, los services de GitLab
// pueden seguir arrancando cuando empieza el script (p. ej. initdb de PostgreSQL en un disco
// lento supera los 30 s del health check del runner).
// Uso: node scripts/ci/wait-for-tcp.mjs postgres:5432 redis:6379 [--timeout=120]
import net from 'node:net';

const args = process.argv.slice(2);
const timeoutArg = args.find((a) => a.startsWith('--timeout='));
const deadline = Date.now() + Number(timeoutArg?.split('=')[1] ?? 120) * 1000;
const targets = args.filter((a) => !a.startsWith('--'));

function reachable(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port, timeout: 2000 }, () => {
      socket.end();
      resolve(true);
    });
    socket.on('error', () => resolve(false));
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });
}

for (const target of targets) {
  const [host, port] = target.split(':');
  while (!(await reachable(host, Number(port)))) {
    if (Date.now() > deadline) {
      console.error(`${target} no responde`);
      process.exit(1);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  console.log(`${target} listo`);
}
