import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Qué servicio sirve cada dominio (QoL-5b, DESIGN §13): caminos de los registros DNS hasta el
 * asset que los sirve (`dns_service_paths`, con el destino fijado a mano), reenvíos NAT declarados
 * en Ajustes (`nat_forwards`) y las relaciones automáticas `served_by` (registro → asset final) y
 * `routes_to` (eslabón → siguiente). Al revertir se borran esas relaciones.
 */
export class ServicePaths1792090478667 implements MigrationInterface {
  name = 'ServicePaths1792090478667';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "dns_service_paths" (
                "record_id" uuid NOT NULL,
                "status" character varying(16) NOT NULL,
                "final_asset_id" uuid,
                "hops" jsonb NOT NULL DEFAULT '[]',
                "confidence" character varying(16),
                "cut_reason" character varying(32),
                "public" boolean NOT NULL DEFAULT false,
                "via_asset_ids" uuid array NOT NULL DEFAULT '{}',
                "pinned_asset_id" uuid,
                "pinned_by" character varying(320),
                "pinned_at" TIMESTAMP WITH TIME ZONE,
                "computed_at" TIMESTAMP WITH TIME ZONE,
                CONSTRAINT "CHK_dns_service_paths_status" CHECK (
                    "status" IN ('complete', 'partial', 'manual', 'none')
                ),
                CONSTRAINT "PK_8cd1a007dd444d1bf390f8ad2a9" PRIMARY KEY ("record_id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_dns_service_paths_final" ON "dns_service_paths" ("final_asset_id")
        `);
    // «Por aquí pasan»: caminos que atraviesan un asset (GIN; TypeORM no sabe declararlo).
    await queryRunner.query(`
            CREATE INDEX "IDX_dns_service_paths_via" ON "dns_service_paths" USING GIN ("via_asset_ids")
        `);
    await queryRunner.query(`
            CREATE TABLE "nat_forwards" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "public_ip" inet NOT NULL,
                "public_port" integer NOT NULL,
                "proto" character varying(3) NOT NULL DEFAULT 'tcp',
                "target_asset_id" uuid NOT NULL,
                "target_port" integer NOT NULL,
                "description" character varying(255),
                "created_by" character varying(320),
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "UQ_nat_forwards_public" UNIQUE ("public_ip", "public_port", "proto"),
                CONSTRAINT "CHK_nat_forwards_ports" CHECK (
                    "public_port" BETWEEN 1 AND 65535
                    AND "target_port" BETWEEN 1 AND 65535
                ),
                CONSTRAINT "CHK_nat_forwards_proto" CHECK ("proto" IN ('tcp', 'udp')),
                CONSTRAINT "PK_0fb19e935fcc0e76d0e7a9bf981" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_parent_child_type"
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."asset_relation_type"
            ADD VALUE 'served_by'
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."asset_relation_type"
            ADD VALUE 'routes_to'
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_parent_child_type" ON "asset_relations" ("parent_id", "child_id", "type")
        `);
    await queryRunner.query(`
            ALTER TABLE "dns_service_paths"
            ADD CONSTRAINT "FK_8cd1a007dd444d1bf390f8ad2a9" FOREIGN KEY ("record_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "dns_service_paths"
            ADD CONSTRAINT "FK_100f6537fd2b2d4a48470deff5f" FOREIGN KEY ("final_asset_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "dns_service_paths"
            ADD CONSTRAINT "FK_a21c2454552813f5bfba25a7f97" FOREIGN KEY ("pinned_asset_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "nat_forwards"
            ADD CONSTRAINT "FK_59e060753834352b52d0b4f7ab1" FOREIGN KEY ("target_asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            DELETE FROM "asset_relations" WHERE "type" IN ('served_by', 'routes_to')
        `);
    await queryRunner.query(`
            ALTER TABLE "nat_forwards" DROP CONSTRAINT "FK_59e060753834352b52d0b4f7ab1"
        `);
    await queryRunner.query(`
            ALTER TABLE "dns_service_paths" DROP CONSTRAINT "FK_a21c2454552813f5bfba25a7f97"
        `);
    await queryRunner.query(`
            ALTER TABLE "dns_service_paths" DROP CONSTRAINT "FK_100f6537fd2b2d4a48470deff5f"
        `);
    await queryRunner.query(`
            ALTER TABLE "dns_service_paths" DROP CONSTRAINT "FK_8cd1a007dd444d1bf390f8ad2a9"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_parent_child_type"
        `);
    // Los índices parciales comparan con el enum: se rehacen con el tipo de antes.
    await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_contains_child"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_instance_of_parent"
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."asset_relation_type_old" AS ENUM(
                'contains',
                'resolves_to',
                'depends_on',
                'instance_of',
                'mounts',
                'attached_to',
                'stores',
                'secured_by'
            )
        `);
    await queryRunner.query(`
            ALTER TABLE "asset_relations"
            ALTER COLUMN "type" TYPE "public"."asset_relation_type_old" USING "type"::"text"::"public"."asset_relation_type_old"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."asset_relation_type"
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."asset_relation_type_old"
            RENAME TO "asset_relation_type"
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_parent_child_type" ON "asset_relations" USING btree ("child_id", "parent_id", "type")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_contains_child" ON "asset_relations" ("child_id")
            WHERE "type" = 'contains'
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_instance_of_parent" ON "asset_relations" ("parent_id")
            WHERE "type" = 'instance_of'
        `);
    await queryRunner.query(`
            DROP TABLE "nat_forwards"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_dns_service_paths_via"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_dns_service_paths_final"
        `);
    await queryRunner.query(`
            DROP TABLE "dns_service_paths"
        `);
  }
}
