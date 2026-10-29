import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Datos de conexión y credenciales (referencias) del asset y proceso de alta (DESIGN §7). */
export class AddEnrollment1791498852177 implements MigrationInterface {
  name = 'AddEnrollment1791498852177';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TYPE "public"."enrollment_method" AS ENUM('script', 'manual')
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."enrollment_purpose" AS ENUM('initial', 'sudoers_update')
        `);
    await queryRunner.query(`
            CREATE TYPE "public"."enrollment_status" AS ENUM(
                'pending',
                'confirmed',
                'verified',
                'failed',
                'cancelled'
            )
        `);
    await queryRunner.query(`
            CREATE TABLE "enrollments" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "asset_id" uuid NOT NULL,
                "method" "public"."enrollment_method" NOT NULL,
                "purpose" "public"."enrollment_purpose" NOT NULL,
                "status" "public"."enrollment_status" NOT NULL DEFAULT 'pending',
                "token_hash" character(64),
                "expires_at" TIMESTAMP WITH TIME ZONE,
                "public_key" text NOT NULL,
                "ssh_user" character varying(32) NOT NULL,
                "reported_host_keys" jsonb NOT NULL DEFAULT '[]',
                "sudoers_version" integer,
                "error" text,
                "job_id" character varying(64),
                "confirmed_at" TIMESTAMP WITH TIME ZONE,
                "verified_at" TIMESTAMP WITH TIME ZONE,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "PK_7c0f752f9fb68bf6ed7367ab00f" PRIMARY KEY ("id")
            )
        `);
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_enrollments_token_hash" ON "enrollments" ("token_hash")
        `);
    // A mano: TypeORM no sabe declarar índices DESC ni parciales con IN.
    await queryRunner.query(`
            CREATE INDEX "IDX_enrollments_asset_created" ON "enrollments" ("asset_id", "created_at" DESC)
        `);
    // Como mucho un enrolamiento abierto (esperando al script o verificándose) por asset.
    await queryRunner.query(`
            CREATE UNIQUE INDEX "UQ_enrollments_asset_open" ON "enrollments" ("asset_id")
            WHERE "status" IN ('pending', 'confirmed')
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "connection" jsonb
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "credentials" jsonb NOT NULL DEFAULT '{}'
        `);
    await queryRunner.query(`
            ALTER TABLE "assets"
            ADD "host_key_fingerprint" character varying(128)
        `);
    await queryRunner.query(`
            ALTER TABLE "enrollments"
            ADD CONSTRAINT "FK_6bcd59302c591c529296cabcd80" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE NO ACTION
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TABLE "enrollments" DROP CONSTRAINT "FK_6bcd59302c591c529296cabcd80"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "host_key_fingerprint"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "credentials"
        `);
    await queryRunner.query(`
            ALTER TABLE "assets" DROP COLUMN "connection"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_enrollments_asset_open"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."IDX_enrollments_asset_created"
        `);
    await queryRunner.query(`
            DROP INDEX "public"."UQ_enrollments_token_hash"
        `);
    await queryRunner.query(`
            DROP TABLE "enrollments"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."enrollment_status"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."enrollment_purpose"
        `);
    await queryRunner.query(`
            DROP TYPE "public"."enrollment_method"
        `);
  }
}
