import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Terminal web y acceso (sesión 22, DESIGN §5 y §11): políticas de acceso interactivo
 * (`access_policies`), latido de las sesiones (`terminal_sessions.heartbeat_at`) y los motivos de
 * cierre `revoked` y `gateway_lost`.
 */
export class TerminalAccess1792696046490 implements MigrationInterface {
  name = 'TerminalAccess1792696046490';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "access_policies" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "permission" character varying(32) NOT NULL,
                "subject_type" character varying(8) NOT NULL,
                "user_id" uuid,
                "role" "public"."user_role",
                "scope" character varying(8) NOT NULL,
                "asset_id" uuid,
                "tag" character varying(255),
                "project_id" uuid,
                "created_by" uuid,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "CHK_access_policies_permission" CHECK ("permission" IN ('terminal.open')),
                CONSTRAINT "CHK_access_policies_target" CHECK (
                    (
                        "scope" = 'asset'
                        AND "asset_id" IS NOT NULL
                        AND "tag" IS NULL
                        AND "project_id" IS NULL
                    )
                    OR (
                        "scope" = 'tag'
                        AND "asset_id" IS NULL
                        AND "tag" IS NOT NULL
                        AND "project_id" IS NULL
                    )
                    OR (
                        "scope" = 'project'
                        AND "asset_id" IS NULL
                        AND "tag" IS NULL
                        AND "project_id" IS NOT NULL
                    )
                ),
                CONSTRAINT "CHK_access_policies_subject" CHECK (
                    (
                        "subject_type" = 'user'
                        AND "user_id" IS NOT NULL
                        AND "role" IS NULL
                    )
                    OR (
                        "subject_type" = 'role'
                        AND "user_id" IS NULL
                        AND "role" IS NOT NULL
                    )
                ),
                CONSTRAINT "PK_93705ea815f89343d7bf80cd60e" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_access_policies_user_id" ON "access_policies" ("user_id")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_access_policies_asset_id" ON "access_policies" ("asset_id")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_access_policies_project_id" ON "access_policies" ("project_id")
        `);
    // Una regla igual (permiso, sujeto y objetivo) no se repite: un índice por tipo de sujeto
    // (el cast del enum de roles a texto no es inmutable).
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_access_policies_user_rule" ON "access_policies" (
                "permission",
                "user_id",
                "scope",
                COALESCE("asset_id"::text, "project_id"::text, "tag")
            )
            WHERE "subject_type" = 'user'
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_access_policies_role_rule" ON "access_policies" (
                "permission",
                "role",
                "scope",
                COALESCE("asset_id"::text, "project_id"::text, "tag")
            )
            WHERE "subject_type" = 'role'
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions"
            ADD "heartbeat_at" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions"
            ADD "revoke_requested_at" TIMESTAMP WITH TIME ZONE
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."terminal_close_reason"
            ADD VALUE 'revoked'
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."terminal_close_reason"
            ADD VALUE 'gateway_lost'
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_terminal_sessions_auth_session_id" ON "terminal_sessions" ("auth_session_id")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_terminal_sessions_live" ON "terminal_sessions" ("state")
            WHERE "state" IN ('starting', 'active')
        `);
    await queryRunner.query(`
            ALTER TABLE "access_policies"
            ADD CONSTRAINT "FK_6c8d1a855ad905a20a882888384" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "access_policies"
            ADD CONSTRAINT "FK_4ecec9b10535296c4ad70d232bb" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "access_policies"
            ADD CONSTRAINT "FK_3a81fe28f4a4315a8a2f5cbbc3a" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "access_policies"
            ADD CONSTRAINT "FK_7599f09386c741f2850978b0de9" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "access_policies" DROP CONSTRAINT "FK_7599f09386c741f2850978b0de9"
        `);
    await queryRunner.query(`
            ALTER TABLE "access_policies" DROP CONSTRAINT "FK_3a81fe28f4a4315a8a2f5cbbc3a"
        `);
    await queryRunner.query(`
            ALTER TABLE "access_policies" DROP CONSTRAINT "FK_4ecec9b10535296c4ad70d232bb"
        `);
    await queryRunner.query(`
            ALTER TABLE "access_policies" DROP CONSTRAINT "FK_6c8d1a855ad905a20a882888384"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_terminal_sessions_live"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_terminal_sessions_auth_session_id"
        `);
    // Los motivos nuevos no existen en el tipo anterior.
    await queryRunner.query(`
            UPDATE "terminal_sessions" SET "close_reason" = 'denied' WHERE "close_reason" IN ('revoked', 'gateway_lost')
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."terminal_close_reason_old" AS ENUM(
                'exit',
                'client',
                'idle',
                'max_duration',
                'gateway_shutdown',
                'limit',
                'connect_failed',
                'expired',
                'denied'
            )
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions"
            ALTER COLUMN "close_reason" TYPE "public"."terminal_close_reason_old" USING "close_reason"::"text"::"public"."terminal_close_reason_old"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."terminal_close_reason"
        `);
    await queryRunner.query(`
            ALTER TYPE "public"."terminal_close_reason_old"
            RENAME TO "terminal_close_reason"
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions" DROP COLUMN "revoke_requested_at"
        `);
    await queryRunner.query(`
            ALTER TABLE "terminal_sessions" DROP COLUMN "heartbeat_at"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_access_policies_role_rule"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_access_policies_user_rule"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_access_policies_project_id"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_access_policies_asset_id"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_access_policies_user_id"
        `);
    await queryRunner.query(`
            DROP TABLE "access_policies"
        `);
  }
}
