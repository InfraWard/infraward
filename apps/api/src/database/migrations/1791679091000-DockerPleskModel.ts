import type { MigrationInterface, QueryRunner } from 'typeorm';

const ASSET_TYPES_BEFORE = `'server', 'vm', 'lxc', 'container', 'domain', 'dns_record', 'database', 'image'`;
const ASSET_TYPES_AFTER = `${ASSET_TYPES_BEFORE}, 'volume', 'network', 'subscription', 'certificate'`;
const RELATION_TYPES_BEFORE = `'contains', 'resolves_to', 'depends_on', 'instance_of'`;
const RELATION_TYPES_AFTER = `${RELATION_TYPES_BEFORE}, 'mounts', 'attached_to', 'stores', 'secured_by'`;

/**
 * Docker completo y Plesk (sesión 14, DESIGN §5, §8):
 * - assets `volume` y `network` (hijos del host Docker) con `mounts` / `attached_to` desde los
 *   contenedores;
 * - `stores` host Docker → imagen (qué hosts tienen la imagen aunque nadie la use), creada aquí a
 *   partir de los `instance_of` existentes (contenedor → su host);
 * - assets `subscription` y `certificate` de Plesk, y `secured_by` dominio → certificado.
 *
 * Los enums se recrean (como en `ImagesAsAssets`) para poder usar los valores nuevos en esta
 * misma transacción; los índices parciales que comparan con ellos se rehacen.
 */
export class DockerPleskModel1791679091000 implements MigrationInterface {
  name = 'DockerPleskModel1791679091000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await recreateAssetEnums(
      queryRunner,
      ASSET_TYPES_AFTER,
      RELATION_TYPES_AFTER,
    );
    await queryRunner.query(`
            INSERT INTO "asset_relations" ("parent_id", "child_id", "type")
            SELECT DISTINCT h."parent_id", i."child_id", 'stores'::"public"."asset_relation_type"
              FROM "asset_relations" i
              JOIN "asset_relations" h ON h."child_id" = i."parent_id" AND h."type" = 'contains'
             WHERE i."type" = 'instance_of'
            ON CONFLICT DO NOTHING
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Borra también sus relaciones (ON DELETE CASCADE).
    await queryRunner.query(`
            DELETE FROM "assets" WHERE "type" IN ('volume', 'network', 'subscription', 'certificate')
        `);
    await queryRunner.query(`
            DELETE FROM "asset_relations" WHERE "type" IN ('mounts', 'attached_to', 'stores', 'secured_by')
        `);
    await recreateAssetEnums(
      queryRunner,
      ASSET_TYPES_BEFORE,
      RELATION_TYPES_BEFORE,
    );
  }
}

/** Sustituye los enums `asset_type` y `asset_relation_type` por otros con estos valores. */
async function recreateAssetEnums(
  queryRunner: QueryRunner,
  assetTypes: string,
  relationTypes: string,
): Promise<void> {
  await queryRunner.query(`
            ALTER TYPE "public"."asset_type" RENAME TO "asset_type_old"
        `);
  await queryRunner.query(`
            CREATE TYPE "public"."asset_type" AS ENUM(${assetTypes})
        `);
  await queryRunner.query(`
            ALTER TABLE "assets"
            ALTER COLUMN "type" TYPE "public"."asset_type" USING "type"::"text"::"public"."asset_type"
        `);
  await queryRunner.query(`
            DROP TYPE "public"."asset_type_old"
        `);
  // Los índices parciales comparan con el enum: se rehacen con el tipo nuevo.
  await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_contains_child"
        `);
  await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_instance_of_parent"
        `);
  await queryRunner.query(`
            ALTER TYPE "public"."asset_relation_type" RENAME TO "asset_relation_type_old"
        `);
  await queryRunner.query(`
            CREATE TYPE "public"."asset_relation_type" AS ENUM(${relationTypes})
        `);
  await queryRunner.query(`
            ALTER TABLE "asset_relations"
            ALTER COLUMN "type" TYPE "public"."asset_relation_type" USING "type"::"text"::"public"."asset_relation_type"
        `);
  await queryRunner.query(`
            DROP TYPE "public"."asset_relation_type_old"
        `);
  await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_contains_child" ON "asset_relations" ("child_id")
            WHERE "type" = 'contains'
        `);
  await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_instance_of_parent" ON "asset_relations" ("parent_id")
            WHERE "type" = 'instance_of'
        `);
}
