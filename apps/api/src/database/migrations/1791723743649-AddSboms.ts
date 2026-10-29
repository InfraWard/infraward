import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * SBOMs y paquetes (sesión 15, DESIGN §5, §9): `sboms` guarda el CycloneDX (gzip) de cada asset
 * —servidor, CT o imagen— para re-evaluarlo con `trivy sbom` sin conectarse; `packages`, sus
 * paquetes normalizados. `container_images.sbom_backfill_failed_at` marca las imágenes escaneadas
 * antes de los SBOMs cuyo escaneo de relleno falló (no se reintenta solo).
 */
export class AddSboms1791723743649 implements MigrationInterface {
  name = 'AddSboms1791723743649';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."sbom_source" AS ENUM('docker_save', 'rootfs')
        `);
    await queryRunner.query(`
            CREATE TABLE "sboms" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "asset_id" uuid NOT NULL,
                "source" "public"."sbom_source" NOT NULL,
                "spec_version" character varying(16) NOT NULL,
                "content" bytea NOT NULL,
                "content_sha256" character varying(64) NOT NULL,
                "packages_sha256" character varying(64) NOT NULL,
                "size_bytes" integer NOT NULL,
                "package_count" integer NOT NULL,
                "os_family" character varying(64),
                "os_name" character varying(64),
                "trivy_version" character varying(32),
                "generated_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                "evaluated_at" TIMESTAMP WITH TIME ZONE,
                "db_updated_at" TIMESTAMP WITH TIME ZONE,
                "vulnerability_count" integer,
                "evaluation_error" character varying(500),
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_42b87656690869c61cd010db44a" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_sboms_asset_id" ON "sboms" ("asset_id")
        `);
    await queryRunner.query(`
            CREATE TABLE "packages" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "asset_id" uuid NOT NULL,
                "sbom_id" uuid NOT NULL,
                "name" character varying(255) NOT NULL,
                "version" character varying(255) NOT NULL,
                "ecosystem" character varying(32) NOT NULL,
                "purl" character varying(1024),
                "pkg_path" character varying(1024),
                CONSTRAINT "PK_020801f620e21f943ead9311c98" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_packages_sbom_id" ON "packages" ("sbom_id")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_packages_name" ON "packages" ("name")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_packages_purl" ON "packages" ("purl")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_packages_asset_name" ON "packages" ("asset_id", "name")
        `);
    await queryRunner.query(`
            ALTER TABLE "container_images"
            ADD "sbom_backfill_failed_at" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            ALTER TABLE "sboms"
            ADD CONSTRAINT "FK_4b181b3fd55f8cc7c2302fffad4" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "packages"
            ADD CONSTRAINT "FK_c5def985ca6d9447279c3b3f4ca" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "packages"
            ADD CONSTRAINT "FK_fbd07a57f7456f5d1c3f352effe" FOREIGN KEY ("sbom_id") REFERENCES "sboms"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "packages" DROP CONSTRAINT "FK_fbd07a57f7456f5d1c3f352effe"
        `);
    await queryRunner.query(`
            ALTER TABLE "packages" DROP CONSTRAINT "FK_c5def985ca6d9447279c3b3f4ca"
        `);
    await queryRunner.query(`
            ALTER TABLE "sboms" DROP CONSTRAINT "FK_4b181b3fd55f8cc7c2302fffad4"
        `);
    await queryRunner.query(`
            ALTER TABLE "container_images" DROP COLUMN "sbom_backfill_failed_at"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_packages_asset_name"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_packages_purl"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_packages_name"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_packages_sbom_id"
        `);
    await queryRunner.query(`
            DROP TABLE "packages"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_sboms_asset_id"
        `);
    await queryRunner.query(`
            DROP TABLE "sboms"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."sbom_source"
        `);
  }
}
