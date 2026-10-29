import { NestFactory } from '@nestjs/core';

/**
 * Dos modos con el mismo código e imagen (DESIGN §3): el worker de jobs (por defecto) y el
 * gateway de las terminales (`node dist/main.js gateway`), cada uno en su proceso.
 */
async function bootstrap() {
  if (process.argv[2] === 'gateway') {
    const { GatewayModule } = await import('./gateway/gateway.module.js');
    // Servidor propio (http + ws): el proceso vive mientras escucha; al recibir SIGTERM/SIGINT
    // avisa a las terminales abiertas y las cierra limpiamente.
    const app = await NestFactory.createApplicationContext(GatewayModule);
    app.enableShutdownHooks();
    return;
  }
  const { WorkerModule } = await import('./worker.module.js');
  // Contexto standalone sin HTTP: los Worker de BullMQ mantienen vivo el proceso y
  // se cierran (terminando el job en curso) al recibir SIGTERM/SIGINT.
  const app = await NestFactory.createApplicationContext(WorkerModule);
  app.enableShutdownHooks();
}
await bootstrap();
