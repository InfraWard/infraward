import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Buscador de CVEs (sesión 16, DESIGN §5, §9, §15): `findings.opened_at` (cuándo se abrió por
 * última vez: al aparecer o al reabrirse; los existentes, su `first_seen_at`) y
 * `users.vulnerabilities_seen_at` («Marcar como vistos» del panel de CVEs nuevos).
 */
export class AddCveSearch1791736537161 implements MigrationInterface {
  name = 'AddCveSearch1791736537161';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "findings"
            ADD "opened_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
        `);
    await queryRunner.query(`
            UPDATE "findings" SET "opened_at" = "first_seen_at"
        `);
    await queryRunner.query(`
            ALTER TABLE "users"
            ADD "vulnerabilities_seen_at" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_findings_status_opened_at" ON "findings" ("status", "opened_at")
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            DROP INDEX "public"."IDX_findings_status_opened_at"
        `);
    await queryRunner.query(`
            ALTER TABLE "users" DROP COLUMN "vulnerabilities_seen_at"
        `);
    await queryRunner.query(`
            ALTER TABLE "findings" DROP COLUMN "opened_at"
        `);
  }
}
