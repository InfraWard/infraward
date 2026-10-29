import type { MigrationInterface, QueryRunner } from 'typeorm';

const TARGET_CHECK_BEFORE = `("scope" = 'global' AND "asset_id" IS NULL AND "tag" IS NULL AND "reconcile_interval_minutes" IS NOT NULL AND "scan_enabled" IS NOT NULL AND "scan_periodic" IS NOT NULL)
   OR ("scope" = 'asset' AND "asset_id" IS NOT NULL AND "tag" IS NULL)
   OR ("scope" = 'tag' AND "asset_id" IS NULL AND "tag" IS NOT NULL)`;

const TARGET_CHECK = `("scope" = 'global' AND "asset_id" IS NULL AND "tag" IS NULL AND "project_id" IS NULL AND "reconcile_interval_minutes" IS NOT NULL AND "scan_enabled" IS NOT NULL AND "scan_periodic" IS NOT NULL)
   OR ("scope" = 'asset' AND "asset_id" IS NOT NULL AND "tag" IS NULL AND "project_id" IS NULL)
   OR ("scope" = 'tag' AND "asset_id" IS NULL AND "tag" IS NOT NULL AND "project_id" IS NULL)
   OR ("scope" = 'project' AND "asset_id" IS NULL AND "tag" IS NULL AND "project_id" IS NOT NULL)`;

const NAME_EXPRESSION = 'COALESCE("display_name", "discovered_name")';

/**
 * Organización del inventario (QoL-3, DESIGN §5 y §10): nombre descubierto aparte del visible
 * (`name` pasa a ser una columna generada), notas, colores de tags, proyectos con pertenencia
 * heredada (`project_memberships` y la efectiva en `assets.effective_projects`) y reglas de
 * política por proyecto.
 */
export class InventoryOrganization1791930000000 implements MigrationInterface {
  name = 'InventoryOrganization1791930000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // El nombre que había es el descubierto (o el del alta a mano): nadie renombraba aún.
    await queryRunner.query(`
            ALTER TABLE "assets" RENAME COLUMN "name" TO "discovered_name"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "display_name" character varying(255),
            ADD "notes" text,
            ADD "effective_projects" uuid array NOT NULL DEFAULT '{}',
            ADD CONSTRAINT "CHK_assets_notes_length" CHECK (char_length("notes") <= 20000)
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "name" character varying(255) GENERATED ALWAYS AS (${NAME_EXPRESSION}) STORED NOT NULL
        `);
    // TypeORM compara las columnas generadas con esta tabla (migration:check).
    await queryRunner.query(
      `INSERT INTO "typeorm_metadata" ("database", "schema", "table", "type", "name", "value")
       VALUES (current_database(), current_schema(), 'assets', 'GENERATED_COLUMN', 'name', $1)`,
      [NAME_EXPRESSION],
    );
    await queryRunner.query(`
            CREATE INDEX "IDX_assets_effective_projects" ON "assets" USING GIN ("effective_projects")
        `);

    await queryRunner.query(`
            CREATE TABLE "projects" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "name" character varying(100) NOT NULL,
                "description" text,
                "color" character varying(7),
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "CHK_projects_color" CHECK (
                    "color" IS NULL
                    OR "color" ~ '^#[0-9a-fA-F]{6}$'
                ),
                CONSTRAINT "PK_6271df0a7aed1d6c0691ce6ac50" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_projects_name" ON "projects" (lower("name"))
        `);
    await queryRunner.query(`
            CREATE TABLE "project_memberships" (
                "project_id" uuid NOT NULL,
                "asset_id" uuid NOT NULL,
                "mode" character varying(8) NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "CHK_project_memberships_mode" CHECK ("mode" IN ('include', 'exclude')),
                CONSTRAINT "PK_a98bb14893308d5d708e83b334d" PRIMARY KEY ("project_id", "asset_id"),
                CONSTRAINT "FK_38a73cbcc58fbed8e62a66d79b8" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE NO ACTION,
                CONSTRAINT "FK_6b88b31e21f7e3591c10221183a" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_project_memberships_asset" ON "project_memberships" ("asset_id")
        `);
    await queryRunner.query(`
            CREATE TABLE "tag_styles" (
                "tag" character varying(255) NOT NULL,
                "color" character varying(7) NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "CHK_tag_styles_color" CHECK ("color" ~ '^#[0-9a-fA-F]{6}$'),
                CONSTRAINT "PK_299ac358925ed71e5c804a55fba" PRIMARY KEY ("tag")
            )
        `);

    await queryRunner.query(`
            ALTER TABLE "inventory_policies"
            ADD "project_id" uuid,
            ADD CONSTRAINT "FK_5936fb671af4e7a402817415d16" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_inventory_policies_project" ON "inventory_policies" ("project_id")
        `);
    await queryRunner.query(`
            ALTER TABLE "inventory_policies" DROP CONSTRAINT "CHK_inventory_policies_target"
        `);
    await queryRunner.query(`
            ALTER TABLE "inventory_policies"
            ADD CONSTRAINT "CHK_inventory_policies_target" CHECK (${TARGET_CHECK})
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            DELETE FROM "inventory_policies" WHERE "scope" = 'project'
        `);
    await queryRunner.query(`
            ALTER TABLE "inventory_policies" DROP CONSTRAINT "CHK_inventory_policies_target"
        `);
    await queryRunner.query(`
            ALTER TABLE "inventory_policies"
            ADD CONSTRAINT "CHK_inventory_policies_target" CHECK (${TARGET_CHECK_BEFORE})
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_inventory_policies_project"
        `);
    await queryRunner.query(`
            ALTER TABLE "inventory_policies" DROP COLUMN "project_id"
        `);
    await queryRunner.query(`
            DROP TABLE "tag_styles"
        `);
    await queryRunner.query(`
            DROP TABLE "project_memberships"
        `);
    await queryRunner.query(`
            DROP TABLE "projects"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_assets_effective_projects"
        `);
    await queryRunner.query(
      `DELETE FROM "typeorm_metadata"
        WHERE "type" = 'GENERATED_COLUMN' AND "table" = 'assets' AND "name" = 'name'
          AND "database" = current_database() AND "schema" = current_schema()`,
    );
    // Se conserva el nombre visible: lo renombrado a mano pasa a ser el nombre a secas.
    await queryRunner.query(`
            ALTER TABLE "assets" ADD "visible_name" character varying(255)
        `);
    await queryRunner.query(`
            UPDATE "assets" SET "visible_name" = "name"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            DROP COLUMN "name",
            DROP CONSTRAINT "CHK_assets_notes_length",
            DROP COLUMN "notes",
            DROP COLUMN "effective_projects",
            DROP COLUMN "display_name",
            DROP COLUMN "discovered_name"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" RENAME COLUMN "visible_name" TO "name"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" ALTER COLUMN "name" SET NOT NULL
        `);
  }
}
