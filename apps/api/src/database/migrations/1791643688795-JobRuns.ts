import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Historial de ejecuciones de jobs (Actividad): BullMQ borra los jobs terminados. */
export class JobRuns1791643688795 implements MigrationInterface {
  name = 'JobRuns1791643688795';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."job_run_state" AS ENUM('queued', 'active', 'completed', 'failed')
        `);
    await queryRunner.query(`
            CREATE TABLE "job_runs" (
                "id" uuid NOT NULL,
                "name" character varying(64) NOT NULL,
                "queue" character varying(32) NOT NULL,
                "asset_id" uuid,
                "asset_name" character varying(255),
                "state" "public"."job_run_state" NOT NULL DEFAULT 'queued',
                "progress" smallint NOT NULL DEFAULT '0',
                "message" character varying(500),
                "error" character varying(1000),
                "parent_job_id" uuid,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "started_at" TIMESTAMP WITH TIME ZONE,
                "finished_at" TIMESTAMP WITH TIME ZONE,
                CONSTRAINT "PK_4d0012c04fcfc287550b76be7e9" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            ALTER TABLE "job_runs"
            ADD CONSTRAINT "FK_b9f76b87aee8fc266d62247e45a" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    // A mano: TypeORM no sabe declarar índices DESC ni parciales con IN.
    await queryRunner.query(`
            CREATE INDEX "IDX_job_runs_created" ON "job_runs" ("created_at" DESC)
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_job_runs_asset_created" ON "job_runs" ("asset_id", "created_at" DESC)
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_job_runs_running" ON "job_runs" ("created_at")
            WHERE "state" IN ('queued', 'active')
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "public"."IDX_job_runs_running"`);
    await queryRunner.query(`DROP INDEX "public"."IDX_job_runs_asset_created"`);
    await queryRunner.query(`DROP INDEX "public"."IDX_job_runs_created"`);
    await queryRunner.query(`
            ALTER TABLE "job_runs" DROP CONSTRAINT "FK_b9f76b87aee8fc266d62247e45a"
        `);
    await queryRunner.query(`
            DROP TABLE "job_runs"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."job_run_state"
        `);
  }
}
