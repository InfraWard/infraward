import type { MigrationInterface, QueryRunner } from 'typeorm';

const ASSET_TYPES_BEFORE = `'server', 'vm', 'lxc', 'container', 'domain', 'dns_record', 'database'`;
const RELATION_TYPES_BEFORE = `'contains', 'resolves_to', 'depends_on'`;

/**
 * Imágenes de contenedor como assets (DESIGN §5, §9): asset `image` (clave natural = image ID)
 * con su ficha de escaneo en `container_images`, relación `instance_of` contenedor → imagen
 * (`parent_id` = contenedor, origen; `child_id` = imagen) y findings una sola vez por imagen en lugar
 * de copiados en cada contenedor.
 *
 * Los enums se recrean (en lugar de `ALTER TYPE … ADD VALUE`) para poder usar los valores
 * nuevos en esta misma transacción.
 */
export class ImagesAsAssets1791586561533 implements MigrationInterface {
  name = 'ImagesAsAssets1791586561533';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await recreateAssetEnums(
      queryRunner,
      `${ASSET_TYPES_BEFORE}, 'image'`,
      `${RELATION_TYPES_BEFORE}, 'instance_of'`,
    );
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_asset_relations_instance_of_parent" ON "asset_relations" ("parent_id")
            WHERE "type" = 'instance_of'
        `);

    // Un asset `image` por imagen registrada.
    await queryRunner.query(`
            ALTER TABLE "container_images"
            ADD "asset_id" uuid,
            ADD "vulnerability_count" integer
        `);
    await queryRunner.query(`
            UPDATE "container_images" SET "vulnerability_count" = jsonb_array_length("vulnerabilities")
             WHERE jsonb_typeof("vulnerabilities") = 'array'
        `);
    await queryRunner.query(`
            WITH created AS (
              INSERT INTO "assets" ("type", "name", "status", "natural_key", "facts")
              SELECT 'image', COALESCE(ci."repo_tags"[1], left(ci."image_id", 19)), 'active',
                     ci."image_id",
                     jsonb_build_object('image', jsonb_build_object(
                       'imageId', ci."image_id",
                       'repoTags', to_jsonb(ci."repo_tags"),
                       'repoDigests', to_jsonb(ci."repo_digests"),
                       'platform', ci."platform"))
                FROM "container_images" ci
              RETURNING "id", "natural_key"
            )
            UPDATE "container_images" ci SET "asset_id" = created."id"
              FROM created WHERE created."natural_key" = ci."image_id"
        `);
    await queryRunner.query(`
            ALTER TABLE "container_images" ALTER COLUMN "asset_id" SET NOT NULL
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_container_images_asset_id" ON "container_images" ("asset_id")
        `);
    await queryRunner.query(`
            ALTER TABLE "container_images"
            ADD CONSTRAINT "FK_d236b72617a767dcdb54415f960" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);

    // Contenedor → imagen que ejecuta.
    await queryRunner.query(`
            INSERT INTO "asset_relations" ("parent_id", "child_id", "type")
            SELECT a."id", ci."asset_id", 'instance_of'
              FROM "assets" a
              JOIN "container_images" ci ON ci."image_id" = a."facts"->'docker'->>'imageId'
             WHERE a."type" = 'container'
        `);

    // Findings: uno por (imagen, fingerprint). Fechas extremas; estado: accepted > open > fixed;
    // el resto de campos, de la fila vista más recientemente.
    await queryRunner.query(`
            INSERT INTO "findings" ("asset_id", "fingerprint", "vulnerability_id", "package_name",
                                    "installed_version", "fixed_version", "severity", "title",
                                    "fix_status", "pkg_path", "primary_url", "status",
                                    "first_seen_at", "last_seen_at", "fixed_at")
            SELECT ci."asset_id", d."fingerprint", d."vulnerability_id", d."package_name",
                   d."installed_version", d."fixed_version", d."severity", d."title",
                   d."fix_status", d."pkg_path", d."primary_url", g."status",
                   g."first_seen_at", g."last_seen_at",
                   CASE WHEN g."status" = 'fixed' THEN g."fixed_at" END
              FROM (SELECT DISTINCT ON (f."image_id", f."fingerprint") f.*
                      FROM "findings" f JOIN "assets" a ON a."id" = f."asset_id"
                     WHERE a."type" = 'container'
                     ORDER BY f."image_id", f."fingerprint", f."last_seen_at" DESC, f."id") d
              JOIN (SELECT f."image_id", f."fingerprint",
                           min(f."first_seen_at") AS "first_seen_at",
                           max(f."last_seen_at") AS "last_seen_at",
                           max(f."fixed_at") AS "fixed_at",
                           (CASE WHEN bool_or(f."status" = 'accepted') THEN 'accepted'
                                 WHEN bool_or(f."status" = 'open') THEN 'open'
                                 ELSE 'fixed' END)::"finding_status" AS "status"
                      FROM "findings" f JOIN "assets" a ON a."id" = f."asset_id"
                     WHERE a."type" = 'container'
                     GROUP BY f."image_id", f."fingerprint") g
                ON g."image_id" = d."image_id" AND g."fingerprint" = d."fingerprint"
              JOIN "container_images" ci ON ci."image_id" = d."image_id"
        `);
    await queryRunner.query(`
            DELETE FROM "findings" f USING "assets" a
             WHERE a."id" = f."asset_id" AND a."type" = 'container'
        `);
    await queryRunner.query(`
            ALTER TABLE "findings" DROP COLUMN "image_id"
        `);
    await queryRunner.query(`
            ALTER TABLE "container_images" DROP COLUMN "vulnerabilities"
        `);
  }

  /**
   * Aproximado: vuelve a copiar los findings de cada imagen a sus contenedores, pero las
   * vulnerabilidades de `container_images` quedan a null (el código anterior re-analizaría las
   * imágenes) y se pierden las imágenes sin contenedores.
   */
  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "findings" ADD "image_id" character varying(71)
        `);
    await queryRunner.query(`
            ALTER TABLE "container_images" ADD "vulnerabilities" jsonb
        `);
    await queryRunner.query(`
            INSERT INTO "findings" ("asset_id", "image_id", "fingerprint", "vulnerability_id",
                                    "package_name", "installed_version", "fixed_version",
                                    "severity", "title", "fix_status", "pkg_path",
                                    "primary_url", "status", "first_seen_at", "last_seen_at",
                                    "fixed_at")
            SELECT r."parent_id", ci."image_id", f."fingerprint", f."vulnerability_id",
                   f."package_name", f."installed_version", f."fixed_version", f."severity",
                   f."title", f."fix_status", f."pkg_path", f."primary_url", f."status",
                   f."first_seen_at", f."last_seen_at", f."fixed_at"
              FROM "findings" f
              JOIN "container_images" ci ON ci."asset_id" = f."asset_id"
              JOIN "asset_relations" r ON r."child_id" = f."asset_id" AND r."type" = 'instance_of'
        `);
    await queryRunner.query(`
            ALTER TABLE "container_images" DROP CONSTRAINT "FK_d236b72617a767dcdb54415f960"
        `);
    // Borra también sus findings y relaciones (ON DELETE CASCADE).
    await queryRunner.query(`
            DELETE FROM "assets" WHERE "type" = 'image'
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_container_images_asset_id"
        `);
    await queryRunner.query(`
            ALTER TABLE "container_images" DROP COLUMN "vulnerability_count", DROP COLUMN "asset_id"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_instance_of_parent"
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
  // El índice parcial compara con el enum: se rehace con el tipo nuevo.
  await queryRunner.query(`
            DROP INDEX "public"."UQ_asset_relations_contains_child"
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
}
