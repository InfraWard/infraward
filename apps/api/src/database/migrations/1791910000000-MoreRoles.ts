import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Roles editor, operator y auditor (DESIGN §14): se añaden al enum `user_role` entre admin y
 * viewer (de más a menos permisos). Al revertir, quien tenga uno de ellos pasa a viewer.
 */
export class MoreRoles1791910000000 implements MigrationInterface {
  name = 'MoreRoles1791910000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    for (const role of ['editor', 'operator', 'auditor'])
      await queryRunner.query(
        `ALTER TYPE "public"."user_role" ADD VALUE IF NOT EXISTS '${role}' BEFORE 'viewer'`,
      );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            UPDATE "users" SET "role" = 'viewer' WHERE "role" IN ('editor', 'operator', 'auditor')
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."user_role" RENAME TO "user_role_old"
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."user_role" AS ENUM('admin', 'viewer')
        `);
    await queryRunner.query(`
            ALTER TABLE "users" ALTER COLUMN "role" DROP DEFAULT
        `);
    await queryRunner.query(`
            ALTER TABLE "users"
            ALTER COLUMN "role" TYPE "public"."user_role" USING "role"::"text"::"public"."user_role"
        `);
    await queryRunner.query(`
            ALTER TABLE "users" ALTER COLUMN "role" SET DEFAULT 'viewer'
        `);
    await queryRunner.query(`
            DROP TYPE "public"."user_role_old"
        `);
  }
}
