import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Qué lanzó cada ejecución que no cuelga de otra (DESIGN §20, «Origen»): la API, la comprobación
 * periódica o el alta. Las anteriores se quedan sin saberlo (null).
 */
export class JobRunTrigger1793487024000 implements MigrationInterface {
  name = 'JobRunTrigger1793487024000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "job_runs"
            ADD "trigger" character varying(16)
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "job_runs" DROP COLUMN "trigger"
        `);
  }
}
