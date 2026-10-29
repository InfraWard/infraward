import fastifyCookie from '@fastify/cookie';
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import {
  DocumentBuilder,
  SwaggerModule,
  type OpenAPIObject,
} from '@nestjs/swagger';
import { apiReference } from '@scalar/nestjs-api-reference';
import { AppModule } from './app.module.js';
import { sessionCookieName } from './auth/session-cookie.js';
import { docsPublic, trustProxySetting } from './config/env.validation.js';

/** Crea y configura la aplicación (compartido por main.ts y los tests e2e). */
export async function createApp(): Promise<NestFastifyApplication> {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    // Antes de validar la config con Nest: TRUST_PROXY se lee del entorno ya cargado
    // (ConfigModule carga los .env al importar AppModule).
    new FastifyAdapter({
      trustProxy: trustProxySetting(process.env.TRUST_PROXY ?? 'false'),
    }),
    {
      bufferLogs: false,
    },
  );
  await app.register(fastifyCookie);
  app.enableShutdownHooks();
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  securityHeaders(app);
  // Referencia pública de la API solo donde se permite (DOCS_PUBLIC; apagada en producción).
  if (docsPublic(process.env)) setupDocs(app);
  return app;
}

/**
 * Cabeceras de seguridad de las respuestas de la API. Las de la web (CSP con scripts) las pone
 * su servidor; aquí, JSON: nada que ejecutar ni enmarcar. /docs (Scalar) necesita sus scripts.
 */
function securityHeaders(app: NestFastifyApplication): void {
  const fastify = app.getHttpAdapter().getInstance();
  fastify.addHook('onSend', (request, reply, payload, done) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
    if (!request.url.startsWith('/docs')) {
      reply.header(
        'Content-Security-Policy',
        "default-src 'none'; frame-ancestors 'none'",
      );
      reply.header('X-Frame-Options', 'DENY');
    }
    done(null, payload);
  });
}

/**
 * Donde vale la cookie vale también un token de API (salvo los endpoints @SessionOnly, que lo
 * rechazan con 403 y lo dicen en su descripción): se añade como alternativa.
 */
function addBearerAlternative(document: OpenAPIObject): void {
  for (const item of Object.values(document.paths)) {
    for (const op of Object.values(item) as Array<{ security?: object[] }>) {
      if (!op || typeof op !== 'object' || !Array.isArray(op.security)) continue;
      const hasCookie = op.security.some((r) => 'cookie' in r);
      const hasBearer = op.security.some((r) => 'bearer' in r);
      if (hasCookie && !hasBearer) op.security.push({ bearer: [] });
    }
  }
}

/** OpenAPI en /openapi.json y referencia interactiva de Scalar en /docs. */
function setupDocs(app: NestFastifyApplication): void {
  const secure = process.env.SESSION_COOKIE_SECURE?.toLowerCase() !== 'false';
  const config = new DocumentBuilder()
    .setTitle('InfraWard API')
    .setDescription(
      'Inventario inteligente de infraestructura. Sesión con cookie httpOnly (POST /auth/login) y cabecera X-CSRF-Token en las peticiones que modifican datos, o un token de API personal (Ajustes › Tokens de API) en `Authorization: Bearer iwt_…`: los de solo lectura solo valen para GET.',
    )
    .setVersion(process.env.npm_package_version ?? '0.0.0')
    .addCookieAuth(sessionCookieName(secure))
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', description: 'Token de API (iwt_…)' },
      'bearer',
    )
    .build();
  const document = SwaggerModule.createDocument(app, config);
  addBearerAlternative(document);

  const fastify = app.getHttpAdapter().getInstance();
  fastify.get('/openapi.json', (_req, reply) => reply.send(document));
  app.use('/docs', apiReference({ withFastify: true, content: document }));
}
