import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Login con OIDC (QoL-2, DESIGN §5 y §14): origen de la cuenta (`local` u `oidc`) e identidad
 * del proveedor enlazada (issuer + sub, única entre las enlazadas) en `users`; ID token de la
 * sesión (pista para cerrar también la del proveedor) en `user_sessions`.
 */
export class OidcLogin1791920000000 implements MigrationInterface {
  name = 'OidcLogin1791920000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."user_origin" AS ENUM('local', 'oidc')
        `);
    await queryRunner.query(`
            ALTER TABLE "users"
            ADD "origin" "public"."user_origin" NOT NULL DEFAULT 'local',
            ADD "oidc_issuer" character varying(512),
            ADD "oidc_subject" character varying(255)
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_users_oidc_identity" ON "users" ("oidc_issuer", "oidc_subject")
            WHERE "oidc_subject" IS NOT NULL
        `);
    await queryRunner.query(`
            ALTER TABLE "user_sessions"
            ADD "oidc_id_token" text
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "user_sessions" DROP COLUMN "oidc_id_token"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_users_oidc_identity"
        `);
    await queryRunner.query(`
            ALTER TABLE "users"
            DROP COLUMN "oidc_subject",
            DROP COLUMN "oidc_issuer",
            DROP COLUMN "origin"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."user_origin"
        `);
  }
}
