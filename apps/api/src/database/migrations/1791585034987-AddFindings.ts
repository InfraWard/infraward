import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Imágenes de contenedor escaneadas con Trivy y findings por asset (DESIGN §9). */
export class AddFindings1791585034987 implements MigrationInterface {
  name = 'AddFindings1791585034987';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."image_scan_status" AS ENUM('pending', 'scanned', 'skipped', 'failed')
        `);
    await queryRunner.query(`
            CREATE TABLE "container_images" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "image_id" character varying(71) NOT NULL,
                "repo_digests" text array NOT NULL DEFAULT '{}',
                "repo_tags" text array NOT NULL DEFAULT '{}',
                "platform" character varying(64),
                "scan_status" "public"."image_scan_status" NOT NULL DEFAULT 'pending',
                "scan_reason" character varying(500),
                "scanned_at" TIMESTAMP WITH TIME ZONE,
                "scan_source" character varying(32),
                "source_asset_id" uuid,
                "config_digest" character varying(71),
                "trivy_version" character varying(32),
                "db_updated_at" TIMESTAMP WITH TIME ZONE,
                "vulnerabilities" jsonb,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_f6bb31b1cf4f627561a1364387e" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_container_images_image_id" ON "container_images" ("image_id")
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."finding_severity" AS ENUM('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."finding_status" AS ENUM('open', 'fixed', 'accepted')
        `);
    await queryRunner.query(`
            CREATE TABLE "findings" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "asset_id" uuid NOT NULL,
                "image_id" character varying(71),
                "fingerprint" character varying(64) NOT NULL,
                "vulnerability_id" character varying(128) NOT NULL,
                "package_name" character varying(255) NOT NULL,
                "installed_version" character varying(255) NOT NULL,
                "fixed_version" character varying(512),
                "severity" "public"."finding_severity" NOT NULL,
                "title" character varying(500),
                "fix_status" character varying(32),
                "pkg_path" character varying(1024),
                "primary_url" character varying(1024),
                "status" "public"."finding_status" NOT NULL DEFAULT 'open',
                "first_seen_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "last_seen_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "fixed_at" TIMESTAMP WITH TIME ZONE,
                CONSTRAINT "PK_ae9807d6293c23c13ff8804d09c" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_findings_vulnerability_id" ON "findings" ("vulnerability_id")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_findings_asset_status" ON "findings" ("asset_id", "status")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_findings_asset_fingerprint" ON "findings" ("asset_id", "fingerprint")
        `);
    await queryRunner.query(`
            ALTER TABLE "findings"
            ADD CONSTRAINT "FK_7d894b4934a315f8259c5515384" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "findings" DROP CONSTRAINT "FK_7d894b4934a315f8259c5515384"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_findings_asset_fingerprint"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_findings_asset_status"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_findings_vulnerability_id"
        `);
    await queryRunner.query(`
            DROP TABLE "findings"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."finding_status"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."finding_severity"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_container_images_image_id"
        `);
    await queryRunner.query(`
            DROP TABLE "container_images"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."image_scan_status"
        `);
  }
}
