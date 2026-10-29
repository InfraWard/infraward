import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Inventario de dominios (QoL-5, DESIGN §13): tipo de asset `dns_provider` (cuenta de un conector
 * de dominios), comprobaciones de registros DNS (colgantes y «esperado»), avisos de caducidad ya
 * enviados y ajustes globales con los umbrales de caducidad (30 y 7 días). Al revertir, los
 * conectores (`dns_provider`) se borran (sus dominios y registros quedan como raíces).
 */
export class DomainInventory1792005868313 implements MigrationInterface {
  name = 'DomainInventory1792005868313';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "app_settings" (
                "key" character varying(64) NOT NULL,
                "value" jsonb NOT NULL,
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_975c2db59c65c05fd9c6b63a2ab" PRIMARY KEY ("key")
            )
        `);
    await queryRunner.query(`
            CREATE TABLE "dns_record_checks" (
                "asset_id" uuid NOT NULL,
                "level" character varying(8),
                "reason" character varying(32) NOT NULL,
                "target" character varying(255) NOT NULL,
                "ambiguous" boolean NOT NULL DEFAULT false,
                "takeover_service" character varying(64),
                "value_hash" character varying(64) NOT NULL,
                "accepted_value_hash" character varying(64),
                "accepted_by" character varying(320),
                "accepted_at" TIMESTAMP WITH TIME ZONE,
                "notified_value_hash" character varying(64),
                "checked_at" TIMESTAMP WITH TIME ZONE NOT NULL,
                CONSTRAINT "CHK_dns_record_checks_level" CHECK (
                    "level" IS NULL
                    OR "level" IN ('high', 'info')
                ),
                CONSTRAINT "PK_3b8b0edd379043b9409cdb87ca2" PRIMARY KEY ("asset_id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_dns_record_checks_level" ON "dns_record_checks" ("level")
        `);
    await queryRunner.query(`
            CREATE TABLE "expiry_alerts" (
                "asset_id" uuid NOT NULL,
                "not_after" TIMESTAMP WITH TIME ZONE NOT NULL,
                "threshold_days" integer NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_299923ccc4d38bfec6fd49d3f5d" PRIMARY KEY ("asset_id", "not_after", "threshold_days")
            )
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_assets_type_natural_key"
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."asset_type"
            ADD VALUE 'dns_provider'
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_assets_type_natural_key" ON "assets" ("type", "natural_key")
            WHERE "natural_key" IS NOT NULL
        `);
    await queryRunner.query(`
            ALTER TABLE "dns_record_checks"
            ADD CONSTRAINT "FK_3b8b0edd379043b9409cdb87ca2" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "expiry_alerts"
            ADD CONSTRAINT "FK_64114d90911285a8348a37da740" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            INSERT INTO "app_settings" ("key", "value") VALUES ('expiry_warning_days', '[30, 7]')
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "expiry_alerts" DROP CONSTRAINT "FK_64114d90911285a8348a37da740"
        `);
    await queryRunner.query(`
            ALTER TABLE "dns_record_checks" DROP CONSTRAINT "FK_3b8b0edd379043b9409cdb87ca2"
        `);
    await queryRunner.query(`
            DELETE FROM "assets" WHERE "type" = 'dns_provider'
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_assets_type_natural_key"
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."asset_type_old" AS ENUM(
                'server',
                'vm',
                'lxc',
                'container',
                'domain',
                'dns_record',
                'database',
                'image',
                'volume',
                'network',
                'subscription',
                'certificate'
            )
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ALTER COLUMN "type" TYPE "public"."asset_type_old" USING "type"::"text"::"public"."asset_type_old"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."asset_type"
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."asset_type_old"
            RENAME TO "asset_type"
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_assets_type_natural_key" ON "assets" USING btree ("natural_key", "type")
            WHERE (natural_key IS NOT NULL)
        `);
    await queryRunner.query(`
            DROP TABLE "expiry_alerts"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_dns_record_checks_level"
        `);
    await queryRunner.query(`
            DROP TABLE "dns_record_checks"
        `);
    await queryRunner.query(`
            DROP TABLE "app_settings"
        `);
  }
}
