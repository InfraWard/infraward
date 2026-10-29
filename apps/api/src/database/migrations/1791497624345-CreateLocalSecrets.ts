import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Texto cifrado del proveedor de secretos local (AES-256-GCM; la clave maestra vive fuera de la BD). */
export class CreateLocalSecrets1791497624345 implements MigrationInterface {
  name = 'CreateLocalSecrets1791497624345';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "local_secrets" (
                "id" uuid NOT NULL DEFAULT gen_random_uuid(),
                "path" text NOT NULL,
                "key_id" character varying(16) NOT NULL,
                "iv" bytea NOT NULL,
                "ciphertext" bytea NOT NULL,
                "auth_tag" bytea NOT NULL,
                "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                CONSTRAINT "UQ_7723b88496a31f2533e8de43bae" UNIQUE ("path"),
                CONSTRAINT "PK_70b7f29c25d9936f3ea8aa1ccb0" PRIMARY KEY ("id")
            )
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            DROP TABLE "local_secrets"
        `);
  }
}
