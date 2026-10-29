import type { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateInventory1791484229115 implements MigrationInterface {
  name = 'CreateInventory1791484229115';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."asset_type" AS ENUM(
                'server',
                'vm',
                'lxc',
                'container',
                'domain',
                'dns_record',
                'database'
            )
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."asset_status" AS ENUM(
                'pending_enrollment',
                'active',
                'missing',
                'retired'
            )
        `);
    await queryRunner.query(`
            CREATE TABLE "assets" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "type" "public"."asset_type" NOT NULL,
                "name" character varying(255) NOT NULL,
                "status" "public"."asset_status" NOT NULL DEFAULT 'pending_enrollment',
                "natural_key" character varying(512),
                "roles" text array NOT NULL DEFAULT '{}',
                "tags" text array NOT NULL DEFAULT '{}',
                "facts" jsonb NOT NULL DEFAULT '{}',
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_da96729a8b113377cfb6a62439c" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_assets_status" ON "assets" ("status")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_assets_type_natural_key" ON "assets" ("type", "natural_key")
            WHERE "natural_key" IS NOT NULL
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."asset_relation_type" AS ENUM('contains', 'resolves_to', 'depends_on')
        `);
    await queryRunner.query(`
            CREATE TABLE "asset_relations" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "parent_id" uuid NOT NULL,
                "child_id" uuid NOT NULL,
                "type" "public"."asset_relation_type" NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "CHK_asset_relations_not_self" CHECK ("parent_id" <> "child_id"),
                CONSTRAINT "PK_5b3447842fd9665412ecec8128e" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_asset_relations_child" ON "asset_relations" ("child_id")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_contains_child" ON "asset_relations" ("child_id")
            WHERE "type" = 'contains'
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_parent_child_type" ON "asset_relations" ("parent_id", "child_id", "type")
        `);
    await queryRunner.query(`
            CREATE TABLE "snapshots" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "asset_id" uuid NOT NULL,
                "collected_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "facts" jsonb NOT NULL DEFAULT '{}',
                "roles" text array NOT NULL DEFAULT '{}',
                "job_id" character varying(64),
                CONSTRAINT "PK_f5661b5fd4224d23e26a631986b" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            ALTER TABLE "asset_relations"
            ADD CONSTRAINT "FK_f6a7b26b46c30a756b5e543984e" FOREIGN KEY ("parent_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "asset_relations"
            ADD CONSTRAINT "FK_0de2d4651c7fee349b3817cd3e3" FOREIGN KEY ("child_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots"
            ADD CONSTRAINT "FK_fb015ea5fd5e24f46e31d951816" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    // Índices que TypeORM no sabe declarar (en las entidades con synchronize: false).
    await queryRunner.query(`
            CREATE INDEX "IDX_assets_facts" ON "assets" USING GIN ("facts" jsonb_path_ops)
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_assets_tags" ON "assets" USING GIN ("tags")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_assets_roles" ON "assets" USING GIN ("roles")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_snapshots_asset_collected" ON "snapshots" ("asset_id", "collected_at" DESC)
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            DROP INDEX "public"."IDX_snapshots_asset_collected"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_assets_roles"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_assets_tags"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_assets_facts"
        `);
    await queryRunner.query(`
            ALTER TABLE "snapshots" DROP CONSTRAINT "FK_fb015ea5fd5e24f46e31d951816"
        `);
    await queryRunner.query(`
            ALTER TABLE "asset_relations" DROP CONSTRAINT "FK_0de2d4651c7fee349b3817cd3e3"
        `);
    await queryRunner.query(`
            ALTER TABLE "asset_relations" DROP CONSTRAINT "FK_f6a7b26b46c30a756b5e543984e"
        `);
    await queryRunner.query(`
            DROP TABLE "snapshots"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_parent_child_type"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_contains_child"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_asset_relations_child"
        `);
    await queryRunner.query(`
            DROP TABLE "asset_relations"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."asset_relation_type"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_assets_type_natural_key"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_assets_status"
        `);
    await queryRunner.query(`
            DROP TABLE "assets"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."asset_status"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."asset_type"
        `);
  }
}
