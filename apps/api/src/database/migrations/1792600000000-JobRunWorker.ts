import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Varias réplicas del worker (sesión W-0, DESIGN §20): qué réplica ejecuta cada job (Actividad) y
 * cuántas veces se ha empezado, que es el fencing token de sus escrituras finales.
 */
export class JobRunWorker1792600000000 implements MigrationInterface {
  name = 'JobRunWorker1792600000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "job_runs" ADD "worker" character varying(64)
        `);
    await queryRunner.query(`
            ALTER TABLE "job_runs" ADD "attempt" integer NOT NULL DEFAULT '0'
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "job_runs" DROP COLUMN "attempt"
        `);
    await queryRunner.query(`
            ALTER TABLE "job_runs" DROP COLUMN "worker"
        `);
  }
}
