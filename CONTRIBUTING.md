# Contributing to InfraWard

Thanks for your interest in InfraWard! Bug reports, ideas, documentation fixes and code are all welcome. This guide explains how to get a development environment running and what we expect from a pull request.

## Before you start

- **Security vulnerabilities**: never open a public issue. Report them privately as described in [SECURITY.md](SECURITY.md).
- **Bugs**: open an issue with the InfraWard version (image tag or commit), how it is deployed (compose, Podman, replicas…), the steps to reproduce, what you expected and what happened. Logs help, but remove hostnames, IPs, tokens and anything else private first.
- **Features and larger changes**: open an issue to discuss the idea before writing code, so we can agree on the approach (and check it fits the design in [docs/DESIGN.md](docs/DESIGN.md)).
- **Small fixes** (typos, docs, obvious bugs): a pull request on its own is fine.

The code comments and most of the documentation are currently in Spanish. Issues and pull requests in English or Spanish are both welcome.

## Contributor License Agreement (CLA)

Before your first pull request can be merged, you must sign the [InfraWard Individual Contributor License Agreement](CLA.md). It only takes a minute and you sign it once for all your future contributions:

1. Open your pull request.
2. The **CLA Assistant** bot comments on it with a link.
3. Sign in with GitHub and accept the agreement. The `license/cla` check turns green.

The CLA lets the project owner distribute your contribution under the project's license (AGPL-3.0) and, if needed in the future, under other licenses, while committing to keep every released version available under an OSI-approved open source license. You keep the copyright of your work. A Spanish translation for information is in [CLA.es.md](CLA.es.md); the English version is the binding one.

If your contribution is owned by your employer, make sure you are allowed to contribute it (see section 4 of the CLA).

## Development setup

Requirements:

- **Node.js 24** (see `.nvmrc`) and **pnpm**, enabled through Corepack.
- **Docker or Podman** with Compose, for PostgreSQL and Redis (and for the integration tests).
- To collect and scan real servers from your machine, the worker also needs `ansible-playbook` and `trivy` in the `PATH`. They are not needed for the unit tests.

```bash
corepack enable
pnpm install
cp deploy/.env.example deploy/.env
cp apps/api/.env.example apps/api/.env
cp apps/worker/.env.example apps/worker/.env
(umask 177; mkdir -p deploy/secrets && openssl rand -base64 32 > deploy/secrets/master.key)
pnpm infra:up                 # PostgreSQL + Redis (deploy/docker-compose.yml)
pnpm dev                      # packages, API (:3000), worker, gateway and web (:4200) in watch mode
```

`pnpm infra:down` stops PostgreSQL and Redis. Optional services for local testing:

- `pnpm openbao:bootstrap`: a development OpenBao (KV, SSH CA and the app's AppRoles), needed for the web terminal and the SSH CA mode.
- `pnpm keycloak:bootstrap`: a test Keycloak for OIDC login.

The full list of environment variables is documented in `apps/api/.env.example` and `apps/worker/.env.example`.

### Repository layout

```
apps/web               Angular + OptimusNG
apps/api               NestJS API (migrations in src/database/migrations)
apps/worker            NestJS standalone worker (also runs the terminal gateway)
packages/shared-types  Shared DTOs (the only package the web may import)
packages/domain        TypeORM inventory entities
packages/secrets       SecretsService and providers (local, OpenBao)
packages/connectors    Discoverers and domain connectors
ansible/               Enrollment script and collection playbook
deploy/                Development compose, OpenBao, Keycloak and the example deployment
```

## Tests and checks

Run these before opening a pull request:

```bash
pnpm -r build                 # respects the dependency graph (shared-types first)
pnpm -r lint
pnpm -r test                  # unit tests (Vitest; the web uses ng test)
```

Depending on what you changed:

| Command | When |
|---|---|
| `pnpm --filter @infraward/api test:e2e` | API or worker behaviour. Uses PostgreSQL and Redis from `DATABASE_URL`/`REDIS_URL`, or Testcontainers. |
| `pnpm --filter @infraward/api test:integration` | Enrollment script, root helper, SSH and OpenBao, against real sshd and OpenBao containers (needs Docker). |
| `pnpm --filter @infraward/secrets test:integration` | Secret providers against a real OpenBao. |
| `pnpm --filter @infraward/api migration:check` | Any change to a TypeORM entity: fails if a migration is missing. |


## Code guidelines

- **TypeScript** everywhere, formatted with **Prettier** (`.prettierrc`: single quotes, trailing commas) and checked with **ESLint**. Follow `.editorconfig` (UTF-8, 2 spaces, final newline).
- Internal dependencies use `workspace:*`; each package builds to `dist/`. Do not add TypeScript `paths` pointing at another package's sources.
- **The web may only import `@infraward/shared-types`**; `domain`, `secrets` and `connectors` are backend-only (enforced by ESLint).
- **Database changes go through TypeORM migrations** (`pnpm --filter @infraward/api migration:generate`), never `synchronize`. A migration must apply, revert and apply again.
- **Secrets are references, never values**: do not log, store or return secret values, and keep the inventory user read-only. Changes that touch enrollment, sudoers, SSH or secrets need tests (integration tests when possible).
- Add or update tests for every behaviour change, and update `docs/DESIGN.md` and the README when you change how something works.

## Commits and pull requests

- Commits follow [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`, for example `fix(web): …` or `feat: …`. Types used in the project: `feat`, `fix`, `docs`, `test`, `perf`, `ci`, `chore`, `style`.
- Keep commits focused, with a summary that says what changes and, in the body, why.
- One topic per pull request. Describe what it does, how you tested it and any migration or configuration change it needs; link the related issue.
- Pull requests target `main`. Accepted pull requests are integrated by the maintainers into the development tree, keeping you as the author, and ship in the next release.

## License

InfraWard is licensed under the [GNU Affero General Public License v3.0](LICENSE). By contributing, you agree that your contributions are licensed as described in the [CLA](CLA.md).
