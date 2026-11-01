import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Acciones de solo lectura de la terminal (DESIGN §11): una sesión puede ejecutar un comando fijo
 * en lugar de la shell (p. ej. habilitar Podman rootless) y lo que lleva queda registrado.
 */
export class TerminalAction1793313780000 implements MigrationInterface {
  name = 'TerminalAction1793313780000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "terminal_sessions" ADD "action" jsonb`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "terminal_sessions" DROP COLUMN "action"`);
  }
}
