import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Paneles personalizables (QoL-8): el panel guardado de cada usuario y de cada proyecto, y las
 * muestras diarias de los gráficos de evolución (una por día, ámbito y métrica, también la global:
 * índice único NULLS NOT DISTINCT, que TypeORM no sabe declarar).
 */
export class Dashboards1792524409442 implements MigrationInterface {
  name = 'Dashboards1792524409442';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "metric_samples" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "day" date NOT NULL,
                "project_id" uuid,
                "metric" character varying(48) NOT NULL,
                "values" jsonb NOT NULL,
                "granularity" character varying(8) NOT NULL DEFAULT 'day',
                CONSTRAINT "CHK_metric_samples_granularity" CHECK ("granularity" IN ('day', 'week')),
                CONSTRAINT "PK_21aecc6180afbd6e0f6fcd82b62" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_metric_samples_project_id" ON "metric_samples" ("project_id")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_metric_samples_day_project_metric"
            ON "metric_samples" ("day", "project_id", "metric") NULLS NOT DISTINCT
        `);
    await queryRunner.query(`
            CREATE TABLE "dashboards" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "owner_user_id" uuid,
                "project_id" uuid,
                "layout" jsonb NOT NULL,
                "version" integer NOT NULL DEFAULT '1',
                "updated_by_id" uuid,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "CHK_dashboards_owner" CHECK (num_nonnulls("owner_user_id", "project_id") = 1),
                CONSTRAINT "PK_1b4b4bc346118e0d335f16c5344" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_dashboards_owner_user_id" ON "dashboards" ("owner_user_id")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_dashboards_project_id" ON "dashboards" ("project_id")
        `);
    await queryRunner.query(`
            ALTER TABLE "metric_samples"
            ADD CONSTRAINT "FK_a33ceffa591810fffd597e16c98" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "dashboards"
            ADD CONSTRAINT "FK_c00f64cb08dfcfb3ff2e32d1926" FOREIGN KEY ("owner_user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "dashboards"
            ADD CONSTRAINT "FK_39076243471d2b31ff35c20a409" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "dashboards"
            ADD CONSTRAINT "FK_7615244e35fc71faf48dec197bc" FOREIGN KEY ("updated_by_id") REFERENCES "users"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "dashboards" DROP CONSTRAINT "FK_7615244e35fc71faf48dec197bc"
        `);
    await queryRunner.query(`
            ALTER TABLE "dashboards" DROP CONSTRAINT "FK_39076243471d2b31ff35c20a409"
        `);
    await queryRunner.query(`
            ALTER TABLE "dashboards" DROP CONSTRAINT "FK_c00f64cb08dfcfb3ff2e32d1926"
        `);
    await queryRunner.query(`
            ALTER TABLE "metric_samples" DROP CONSTRAINT "FK_a33ceffa591810fffd597e16c98"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_dashboards_project_id"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_dashboards_owner_user_id"
        `);
    await queryRunner.query(`
            DROP TABLE "dashboards"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_metric_samples_day_project_metric"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_metric_samples_project_id"
        `);
    await queryRunner.query(`
            DROP TABLE "metric_samples"
        `);
  }
}
