import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Priorización (sesión 19): KEV y EPSS por CVE con el estado de cada fuente, y en `findings` el
 * CVSS, la prioridad con sus motivos, el ruido y la alerta de KEV.
 */
export class Prioritization1792350000000 implements MigrationInterface {
  name = 'Prioritization1792350000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "vulnerability_intel" (
                "vulnerability_id" character varying(128) NOT NULL,
                "in_kev" boolean NOT NULL DEFAULT false,
                "kev_added" date,
                "kev_due" date,
                "kev_ransomware" boolean NOT NULL DEFAULT false,
                "kev_name" character varying(500),
                "epss" real,
                "epss_percentile" real,
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_6d9b09439153aa68ef70341673a" PRIMARY KEY ("vulnerability_id")
            )
        `);
    await queryRunner.query(`
            CREATE TABLE "intel_feeds" (
                "source" character varying(16) NOT NULL,
                "enabled" boolean NOT NULL DEFAULT true,
                "fetched_at" TIMESTAMP WITH TIME ZONE,
                "checked_at" TIMESTAMP WITH TIME ZONE,
                "etag" character varying(512),
                "last_modified" character varying(64),
                "version" character varying(64),
                "record_count" integer,
                "last_error" character varying(500),
                "last_error_at" TIMESTAMP WITH TIME ZONE,
                CONSTRAINT "PK_056d8e476254cb6de5ca4e172eb" PRIMARY KEY ("source")
            )
        `);
    await queryRunner.query(`
            ALTER TABLE "findings"
            ADD "cvss_score" real,
            ADD "priority" smallint,
            ADD "priority_reasons" jsonb,
            ADD "noise_reason" character varying(32),
            ADD "kev_alerted_at" TIMESTAMP WITH TIME ZONE
        `);
    // Lista por prioridad (TypeORM no declara DESC: la entidad lo marca con synchronize: false).
    await queryRunner.query(`
            CREATE INDEX "IDX_findings_status_priority" ON "findings" ("status", "priority" DESC NULLS LAST)
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "IDX_findings_status_priority"`);
    await queryRunner.query(`
            ALTER TABLE "findings"
            DROP COLUMN "kev_alerted_at",
            DROP COLUMN "noise_reason",
            DROP COLUMN "priority_reasons",
            DROP COLUMN "priority",
            DROP COLUMN "cvss_score"
        `);
    await queryRunner.query(`DROP TABLE "intel_feeds"`);
    await queryRunner.query(`DROP TABLE "vulnerability_intel"`);
  }
}
