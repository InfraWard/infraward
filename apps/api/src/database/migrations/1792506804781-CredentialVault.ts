import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Caja fuerte de credenciales (QoL-7): entradas y su historial de versiones (sin valores), el
 * texto cifrado del almacén local de la caja fuerte (con su propia clave) y el público de las
 * notificaciones (un revelado solo lo ven los demás admins).
 */
export class CredentialVault1792506804781 implements MigrationInterface {
  name = 'CredentialVault1792506804781';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "vault_local_secrets" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "path" text NOT NULL,
                "version" integer NOT NULL,
                "key_id" character varying(16) NOT NULL,
                "iv" bytea NOT NULL,
                "ciphertext" bytea NOT NULL,
                "auth_tag" bytea NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "UQ_vault_local_secrets_path_version" UNIQUE ("path", "version"),
                CONSTRAINT "PK_dc870d89d84eb7dfd39cbe12d21" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."vault_entry_kind" AS ENUM('console', 'web', 'ipmi', 'other')
        `);
    await queryRunner.query(`
            CREATE TABLE "vault_entries" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "asset_id" uuid,
                "kind" "public"."vault_entry_kind" NOT NULL,
                "name" character varying(120) NOT NULL,
                "username" character varying(200),
                "url" character varying(2000),
                "notes" text,
                "secret_ref" text,
                "current_version" integer,
                "last_rotated_at" TIMESTAMP WITH TIME ZONE,
                "rotation_days" integer,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "created_by_id" uuid,
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_by_id" uuid,
                "deleted_at" TIMESTAMP WITH TIME ZONE,
                "deleted_by_id" uuid,
                CONSTRAINT "PK_7d61f2905530eb80cab310f978b" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_vault_entries_asset_id" ON "vault_entries" ("asset_id")
        `);
    await queryRunner.query(`
            CREATE INDEX "IDX_vault_entries_deleted_at" ON "vault_entries" ("deleted_at")
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."vault_version_origin" AS ENUM('created', 'replaced', 'restored')
        `);
    await queryRunner.query(`
            CREATE TABLE "vault_entry_versions" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "entry_id" uuid NOT NULL,
                "version" integer NOT NULL,
                "origin" "public"."vault_version_origin" NOT NULL,
                "restored_from" integer,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "created_by_id" uuid,
                CONSTRAINT "UQ_vault_entry_versions_entry_version" UNIQUE ("entry_id", "version"),
                CONSTRAINT "PK_825f91d6d109c932f363d58c0cb" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            ALTER TABLE "notifications"
            ADD "audience_roles" character varying(16) array
        `);
    await queryRunner.query(`
            ALTER TABLE "notifications"
            ADD "exclude_user_id" uuid
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entries"
            ADD CONSTRAINT "FK_3108465c739c5840825361eb53a" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entries"
            ADD CONSTRAINT "FK_6de149611cfa6d54cd17834d8d0" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entries"
            ADD CONSTRAINT "FK_d95e001ae9299193071e886b996" FOREIGN KEY ("updated_by_id") REFERENCES "users"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entries"
            ADD CONSTRAINT "FK_2872de1d5c0b00c22ed996b6c09" FOREIGN KEY ("deleted_by_id") REFERENCES "users"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entry_versions"
            ADD CONSTRAINT "FK_dda238ca4fca4488c581866e0c4" FOREIGN KEY ("entry_id") REFERENCES "vault_entries"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entry_versions"
            ADD CONSTRAINT "FK_e08b817ecada2bc0745c73f27f5" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE
            SET NULL ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "vault_entry_versions" DROP CONSTRAINT "FK_e08b817ecada2bc0745c73f27f5"
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entry_versions" DROP CONSTRAINT "FK_dda238ca4fca4488c581866e0c4"
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entries" DROP CONSTRAINT "FK_2872de1d5c0b00c22ed996b6c09"
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entries" DROP CONSTRAINT "FK_d95e001ae9299193071e886b996"
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entries" DROP CONSTRAINT "FK_6de149611cfa6d54cd17834d8d0"
        `);
    await queryRunner.query(`
            ALTER TABLE "vault_entries" DROP CONSTRAINT "FK_3108465c739c5840825361eb53a"
        `);
    await queryRunner.query(`
            ALTER TABLE "notifications" DROP COLUMN "exclude_user_id"
        `);
    await queryRunner.query(`
            ALTER TABLE "notifications" DROP COLUMN "audience_roles"
        `);
    await queryRunner.query(`
            DROP TABLE "vault_entry_versions"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."vault_version_origin"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_vault_entries_deleted_at"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_vault_entries_asset_id"
        `);
    await queryRunner.query(`
            DROP TABLE "vault_entries"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."vault_entry_kind"
        `);
    await queryRunner.query(`
            DROP TABLE "vault_local_secrets"
        `);
  }
}
