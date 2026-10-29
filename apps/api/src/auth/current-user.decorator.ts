import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import type { AuthenticatedUser, RequestSession } from './authenticated-user.js';

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AuthenticatedUser | undefined =>
    context.switchToHttp().getRequest<FastifyRequest>().user,
);

export const CurrentSession = createParamDecorator(
  (_data: unknown, context: ExecutionContext): RequestSession | undefined =>
    context.switchToHttp().getRequest<FastifyRequest>().authSession,
);
