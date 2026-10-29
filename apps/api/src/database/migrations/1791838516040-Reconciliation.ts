import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Reconciliación (sesión 17, DESIGN §5, §10): política de inventario (`inventory_policies`, con la
 * global sembrada: 6 h, escaneo activado y periódico) y la efectiva de cada asset
 * (`effective_policy`, la calcula la API al arrancar), contador de ausencias (`missing_runs`,
 * `missing_since`, `missing_scope_id`) y retirada automática (`retired_auto`), última
 * reconciliación (`reconciled_at`, al principio la última recolección), snapshots con su diff
 * (`source`, `previous_id`, `diff`), `notifications` y `users.notifications_seen_at`.
 * Los `missing` que ya había cuentan su primera ejecución, con su padre como ámbito.
 */
export class Reconciliation1791838516040 implements MigrationInterface {
  name = 'Reconciliation1791838516040';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "inventory_policies" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "scope" character varying(16) NOT NULL,
                "asset_id" uuid,
                "tag" character varying(255),
                "reconcile_interval_minutes" integer,
                "scan_enabled" boolean,
                "scan_periodic" boolean,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "CHK_inventory_policies_interval" CHECK (
                    "reconcile_interval_minutes" IS NULL
                    OR "reconcile_interval_minutes" = 0
                    OR "reconcile_interval_minutes" BETWEEN 5 AND 43200
                ),
                CONSTRAINT "CHK_inventory_policies_target" CHECK (
                    (
                        "scope" = 'global'
                        AND "asset_id" IS NULL
                        AND "tag" IS NULL
                        AND "reconcile_interval_minutes" IS NOT NULL
                        AND "scan_enabled" IS NOT NULL
                        AND "scan_periodic" IS NOT NULL
                    )
                    OR (
                        "scope" = 'asset'
                        AND "asset_id" IS NOT NULL
                        AND "tag" IS NULL
                    )
                    OR (
                        "scope" = 'tag'
                        AND "asset_id" IS NULL
                        AND "tag" IS NOT NULL
                    )
                ),
                CONSTRAINT "PK_b1cbf617c7f01c46837b65e5fdc" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_inventory_policies_asset" ON "inventory_policies" ("asset_id")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_inventory_policies_tag" ON "inventory_policies" ("tag")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_inventory_policies_global" ON "inventory_policies" ("scope")
            WHERE "scope" = 'global'
        `);
    await queryRunner.query(`
            CREATE TABLE "notifications" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "kind" character varying(32) NOT NULL,
                "asset_id" uuid,
                "asset_name" character varying(255),
                "message" text NOT NULL,
                "items" jsonb NOT NULL DEFAULT '[]',
                "total" integer NOT NULL DEFAULT '0',
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_6a72c3c0f683f6462415e653c3a" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_notifications_created" ON "notifications" ("created_at")
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "effective_policy" jsonb NOT NULL DEFAULT '{}'
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "missing_runs" integer NOT NULL DEFAULT '0'
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "missing_since" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "missing_scope_id" uuid
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "retired_auto" boolean NOT NULL DEFAULT false
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "reconciled_at" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots"
            ADD "source" character varying(16) NOT NULL DEFAULT 'collect'
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots"
            ADD "previous_id" uuid
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots"
            ADD "diff" jsonb
        `);
    await queryRunner.query(`
            ALTER TABLE "users"
            ADD "notifications_seen_at" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD CONSTRAINT "FK_e36ee107b70142be587d07ea72c" FOREIGN KEY ("missing_scope_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "inventory_policies"
            ADD CONSTRAINT "FK_cfad17db66171150e466c6c07ac" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "notifications"
            ADD CONSTRAINT "FK_4bddd455aad7f9c6e33196ae5ae" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots"
            ADD CONSTRAINT "FK_764ab876b8e9d503cd60853b6ba" FOREIGN KEY ("previous_id") REFERENCES "snapshots"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            INSERT INTO "inventory_policies" ("scope", "reconcile_interval_minutes", "scan_enabled", "scan_periodic")
            VALUES ('global', 360, true, true)
        `);
    await queryRunner.query(`
            UPDATE "assets" a SET "missing_runs" = 1, "missing_since" = a."updated_at",
                   "missing_scope_id" = (SELECT r."parent_id" FROM "asset_relations" r
                                          WHERE r."child_id" = a."id" AND r."type" = 'contains')
             WHERE a."status" = 'missing'
        `);
    await queryRunner.query(`
            UPDATE "assets" a SET "reconciled_at" = (SELECT max(s."collected_at") FROM "snapshots" s
                                                      WHERE s."asset_id" = a."id")
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "snapshots" DROP CONSTRAINT "FK_764ab876b8e9d503cd60853b6ba"
        `);
    await queryRunner.query(`
            ALTER TABLE "notifications" DROP CONSTRAINT "FK_4bddd455aad7f9c6e33196ae5ae"
        `);
    await queryRunner.query(`
            ALTER TABLE "inventory_policies" DROP CONSTRAINT "FK_cfad17db66171150e466c6c07ac"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP CONSTRAINT "FK_e36ee107b70142be587d07ea72c"
        `);
    await queryRunner.query(`
            ALTER TABLE "users" DROP COLUMN "notifications_seen_at"
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots" DROP COLUMN "diff"
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots" DROP COLUMN "previous_id"
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots" DROP COLUMN "source"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "reconciled_at"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "retired_auto"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "missing_scope_id"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "missing_since"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "missing_runs"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "effective_policy"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_notifications_created"
        `);
    await queryRunner.query(`
            DROP TABLE "notifications"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_inventory_policies_global"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_inventory_policies_tag"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_inventory_policies_asset"
        `);
    await queryRunner.query(`
            DROP TABLE "inventory_policies"
        `);
  }
}
