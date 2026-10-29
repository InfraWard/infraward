import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { EnvironmentVariables } from './config/env.validation.js';
import { createApp } from './setup-app.js';

async function bootstrap() {
  const app = await createApp();
  const port = app
    .get(ConfigService<EnvironmentVariables, true>)
    .get('PORT', { infer: true });
  await app.listen(port, '0.0.0.0');
  Logger.log(
    `API escuchando en http://localhost:${port} (docs en /docs)`,
    'Bootstrap',
  );
}
await bootstrap();
