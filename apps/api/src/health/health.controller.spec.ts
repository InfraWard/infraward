import { Test, TestingModule } from '@nestjs/testing';
import { HealthController } from './health.controller.js';

describe('HealthController', () => {
  let controller: HealthController;

  beforeEach(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
    }).compile();

    controller = moduleRef.get(HealthController);
  });

  it('devuelve el estado de la API', () => {
    const health = controller.check();
    expect(health.service).toBe('api');
    expect(health.status).toBe('ok');
    expect(() => new Date(health.timestamp).toISOString()).not.toThrow();
  });
});
