import type { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUserRole1791484229000 implements MigrationInterface {
  name = 'AddUserRole1791484229000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."user_role" AS ENUM('admin', 'viewer')
        `);
    await queryRunner.query(`
            ALTER TABLE "users"
            ADD "role" "public"."user_role" NOT NULL DEFAULT 'viewer'
        `);
    // Hasta ahora todos los usuarios eran administradores de facto.
    await queryRunner.query(`
            UPDATE "users" SET "role" = 'admin'
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "users" DROP COLUMN "role"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."user_role"
        `);
  }
}
