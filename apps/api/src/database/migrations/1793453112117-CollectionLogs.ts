import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Log de cada ejecución (DESIGN §20, «Log de cada ejecución»): uno por intento de cada job, con
 * sus pasos, comandos, stderr de lo que falla y el resultado. Se va con su fila de `job_runs` y
 * el líder del worker lo poda pasados `COLLECTION_LOG_RETENTION_DAYS`.
 */
export class CollectionLogs1793453112117 implements MigrationInterface {
  name = 'CollectionLogs1793453112117';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "job_run_logs" (
                "job_run_id" uuid NOT NULL,
                "attempt" integer NOT NULL,
                "asset_id" uuid,
                "worker" character varying(64),
                "entries" jsonb NOT NULL DEFAULT '[]',
                "truncated" boolean NOT NULL DEFAULT false,
                "dropped" integer NOT NULL DEFAULT '0',
                "bytes" integer NOT NULL DEFAULT '0',
                "started_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                CONSTRAINT "PK_eff1850440c1f53e5993d0dcc26" PRIMARY KEY ("job_run_id", "attempt")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_job_run_logs_asset" ON "job_run_logs" ("asset_id")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_job_run_logs_updated" ON "job_run_logs" ("updated_at")
        `);
    await queryRunner.query(`
            ALTER TABLE "job_run_logs"
            ADD CONSTRAINT "FK_2651d904a7b6a5b73dbced31b4a" FOREIGN KEY ("job_run_id") REFERENCES "job_runs"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "job_run_logs"
            ADD CONSTRAINT "FK_386101f16f77054861433e2d0f7" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "job_run_logs" DROP CONSTRAINT "FK_386101f16f77054861433e2d0f7"
        `);
    await queryRunner.query(`
            ALTER TABLE "job_run_logs" DROP CONSTRAINT "FK_2651d904a7b6a5b73dbced31b4a"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_job_run_logs_updated"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_job_run_logs_asset"
        `);
    await queryRunner.query(`
            DROP TABLE "job_run_logs"
        `);
  }
}
