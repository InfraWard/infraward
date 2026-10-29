import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * CA SSH (sesión 13): modo de acceso de cada asset (`static_key` | `ca_certificate`), el que
 * instala cada enrolamiento, enrolamientos sin clave pública (modo CA) y el propósito
 * `ca_migration` (pasar un servidor de clave estática a certificados).
 */
export class SshCaAuth1791662400000 implements MigrationInterface {
  name = 'SshCaAuth1791662400000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."ssh_auth_mode" AS ENUM('static_key', 'ca_certificate')
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "ssh_auth" "public"."ssh_auth_mode" NOT NULL DEFAULT 'static_key'
        `);
    await queryRunner.query(`
            ALTER TABLE "enrollments"
            ADD "auth_mode" "public"."ssh_auth_mode" NOT NULL DEFAULT 'static_key'
        `);
    await queryRunner.query(`
            ALTER TABLE "enrollments" ALTER COLUMN "public_key" DROP NOT NULL
        `);
    // ADD VALUE dentro de la transacción es válido mientras el valor no se use en ella.
    await queryRunner.query(`
            ALTER TYPE "public"."enrollment_purpose" ADD VALUE 'ca_migration'
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Sin `ca_migration` ni enrolamientos sin clave: lo más parecido en el esquema anterior.
    await queryRunner.query(`
            UPDATE "enrollments" SET "purpose" = 'sudoers_update' WHERE "purpose" = 'ca_migration'
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."enrollment_purpose" RENAME TO "enrollment_purpose_old"
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."enrollment_purpose" AS ENUM('initial', 'sudoers_update')
        `);
    await queryRunner.query(`
            ALTER TABLE "enrollments" ALTER COLUMN "purpose" TYPE "public"."enrollment_purpose"
            USING "purpose"::text::"public"."enrollment_purpose"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."enrollment_purpose_old"
        `);
    await queryRunner.query(`
            UPDATE "enrollments" SET "public_key" = '' WHERE "public_key" IS NULL
        `);
    await queryRunner.query(`
            ALTER TABLE "enrollments" ALTER COLUMN "public_key" SET NOT NULL
        `);
    await queryRunner.query(`
            ALTER TABLE "enrollments" DROP COLUMN "auth_mode"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "ssh_auth"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."ssh_auth_mode"
        `);
  }
}
