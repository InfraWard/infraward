import { NotFoundException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { GatewayAuthGuard, gatewaySecretHash } from './gateway-auth.guard.js';

const SECRET = 'secreto-del-gateway-de-32-caracteres-o-mas';

function context(authorization?: string): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers: { authorization } }) }),
  } as unknown as ExecutionContext;
}

describe('GatewayAuthGuard', () => {
  const guard = new GatewayAuthGuard(gatewaySecretHash(`${SECRET}\n`));

  it('solo con `Gateway <secreto>`', () => {
    expect(guard.canActivate(context(`Gateway ${SECRET}`))).toBe(true);
    for (const header of [
      undefined,
      SECRET,
      `Bearer ${SECRET}`,
      `Gateway ${SECRET}x`,
      `Gateway ${SECRET.slice(1)}`,
      `gateway ${SECRET}`,
      `Gateway ${'x'.repeat(600)}`,
    ])
      expect(() => guard.canActivate(context(header)), String(header)).toThrow(
        UnauthorizedException,
      );
  });

  it('sin secreto configurado, las rutas no existen', () => {
    expect(() => new GatewayAuthGuard(null).canActivate(context(`Gateway ${SECRET}`))).toThrow(
      NotFoundException,
    );
  });

  it('secretos cortos no valen', () => {
    expect(() => gatewaySecretHash('corto')).toThrow(/al menos 32/);
  });
});
