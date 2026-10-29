import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * MFA y reautenticación reciente (DESIGN §5 y §14): referencia al secreto TOTP (cifrado en el
 * proveedor de secretos) y último paso aceptado en `users`; códigos de recuperación (solo
 * sha256); en `user_sessions`, cómo se abrió, cuándo se confirmó la identidad por última vez,
 * los fallos del segundo paso y el propósito `mfa` (sesión intermedia del login).
 */
export class MfaStepUp1792440000000 implements MigrationInterface {
  name = 'MfaStepUp1792440000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "users"
            ADD "totp_secret_ref" character varying(512),
            ADD "totp_pending_ref" character varying(512),
            ADD "totp_enabled_at" TIMESTAMP WITH TIME ZONE,
            ADD "totp_last_step" bigint
        `);
    await queryRunner.query(`
            CREATE TABLE "user_recovery_codes" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "user_id" uuid NOT NULL,
                "code_hash" bytea NOT NULL,
                "used_at" TIMESTAMP WITH TIME ZONE,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_user_recovery_codes" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_user_recovery_codes_user_id" ON "user_recovery_codes" ("user_id")
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_user_recovery_codes_code_hash" ON "user_recovery_codes" ("code_hash")
        `);
    await queryRunner.query(`
            ALTER TABLE "user_recovery_codes"
            ADD CONSTRAINT "FK_f659216e26d0ef1238379cbf40c" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."user_session_auth_method" AS ENUM('password', 'oidc')
        `);
    await queryRunner.query(`
            ALTER TABLE "user_sessions"
            ADD "auth_method" "public"."user_session_auth_method" NOT NULL DEFAULT 'password',
            ADD "reauthenticated_at" TIMESTAMP WITH TIME ZONE,
            ADD "mfa_failures" smallint NOT NULL DEFAULT '0'
        `);
    // Las sesiones abiertas por OIDC son las que guardan el ID token.
    await queryRunner.query(`
            UPDATE "user_sessions" SET "auth_method" = 'oidc' WHERE "oidc_id_token" IS NOT NULL
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."user_session_purpose" ADD VALUE 'mfa'
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Postgres no quita valores de un enum: se rehace el tipo sin `mfa` (y esas sesiones se van).
    await queryRunner.query(`DELETE FROM "user_sessions" WHERE "purpose" = 'mfa'`);
    await queryRunner.query(`
            ALTER TYPE "public"."user_session_purpose" RENAME TO "user_session_purpose_old"
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."user_session_purpose" AS ENUM('full', 'password_change')
        `);
    await queryRunner.query(`
            ALTER TABLE "user_sessions" ALTER COLUMN "purpose" DROP DEFAULT
        `);
    await queryRunner.query(`
            ALTER TABLE "user_sessions"
            ALTER COLUMN "purpose" TYPE "public"."user_session_purpose" USING "purpose"::text::"public"."user_session_purpose"
        `);
    await queryRunner.query(`
            ALTER TABLE "user_sessions" ALTER COLUMN "purpose" SET DEFAULT 'full'
        `);
    await queryRunner.query(`DROP TYPE "public"."user_session_purpose_old"`);
    await queryRunner.query(`
            ALTER TABLE "user_sessions"
            DROP COLUMN "mfa_failures",
            DROP COLUMN "reauthenticated_at",
            DROP COLUMN "auth_method"
        `);
    await queryRunner.query(`DROP TYPE "public"."user_session_auth_method"`);
    await queryRunner.query(`
            ALTER TABLE "user_recovery_codes" DROP CONSTRAINT "FK_f659216e26d0ef1238379cbf40c"
        `);
    await queryRunner.query(`DROP TABLE "user_recovery_codes"`);
    await queryRunner.query(`
            ALTER TABLE "users"
            DROP COLUMN "totp_last_step",
            DROP COLUMN "totp_enabled_at",
            DROP COLUMN "totp_pending_ref",
            DROP COLUMN "totp_secret_ref"
        `);
  }
}
