# Changelog

All notable changes to InfraWard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-11-01

### Added

- Accept the risk of a finding: from the CVE page, the vulnerability list (in bulk) or by CVE across a project, with a mandatory reason and an optional expiry date (up to one year). Accepted findings stop counting as open but still show as affected in the CVE search; when the expiry date passes they reopen automatically with a notification, and a scan that no longer sees them marks them fixed. Accepting and reopening are audited and need the new `findings.accept` permission (admin and editor).
- Outbound alerts: the notifications of the in-app bell can also go out by webhook (JSON POST, optionally signed with HMAC-SHA256) or email (the worker's SMTP), configured by admins in Settings › Alertas with a per-channel filter and a test button. The webhook URL and signing secret are kept in the secrets manager, and the worker protects against SSRF (HTTPS only by default, no loopback, link-local or private targets unless allowed, no redirects, connects to the validated address). Deliveries run on their own `alerts` queue (`ALERTS_CONCURRENCY`) with retries, and a notification is only marked as sent once its deliveries are queued.
- Log of every collection, discovery and scan, viewable from the asset page ("Recolecciones" tab): the steps, every command the worker ran (ssh, ansible-playbook, trivy…) with its duration and exit code, the Ansible tasks, the end of the stderr of whatever failed and the result. Secrets, keys and tokens are redacted before saving, each run's log is capped (`COLLECTION_LOG_MAX_KB`, 256 KiB) and logs are deleted after `COLLECTION_LOG_RETENTION_DAYS` (30 days). Failed runs are highlighted and a running job refreshes until it finishes. New endpoints `GET /assets/{id}/runs` and `GET /assets/{id}/runs/{runId}/log`; reading a log requires the `assets.operate` permission (admin, editor, operator), since it carries error output from the servers.
- Redesigned Activity page. Each run now says where it came from: a bulk operation, another task (a collection that triggered a discovery, a reconciliation that queued collections…), the periodic inventory check, a manual request or an enrollment, with a link to the task or bulk operation that launched it, and the list can be filtered by origin. Clicking a run opens its own page (`/activity/{id}`) with its timing, the tasks it launched and its log, also for runs without an asset. The asset's "Recolecciones" tab, the "Actividad reciente" widget and the bulk-operation result link to it. New endpoints `GET /jobs/runs/{id}` and `GET /jobs/runs/{id}/log` (the log requires `assets.operate`) and the `origin` filter on `GET /jobs`. Runs recorded before this version show no origin.
- Podman support (part of #10): hosts with Podman get the new `podman-host` role and their containers, images, volumes and networks are inventoried with the native `podman` CLI, without `podman-docker` or a root socket. Pods (the pod's infra container is skipped) and quadlet/systemd containers (`PODMAN_SYSTEMD_UNIT`) are shown on the container. Rootless Podman users are detected automatically with read-only signals (running containers, an active user socket, or container storage in their home) and listed in the new «Usuarios de Podman» card of the server; their containers are inventoried, through each user's own Podman socket and marked with their user, once the user is enabled. «Habilitar» shows a command to copy and run with sudo (it turns on linger and the user's `podman.socket` and adds the user to `/etc/infraward/podman-users`, which remains the server-side consent) or, if the server has the admin access and you can open a terminal, runs it as `infraward-admin` in a new read-only terminal where you see the command and its output without being able to type. The enrollment option `--podman-users=<user,…>` is kept as an optional override. Detected users that are not enabled, and enabled users without an active socket, raise a warning on the server. Images are scanned with `podman save --format docker-archive`, the web terminal opens in rootful Podman containers, and Docker and Podman can coexist on the same host. A read-only terminal action never runs when the page loads: it waits for you to press «Ejecutar». Queries to a rootless user's socket run as that user (`runuser`), never as root, and an image taken from a rootless user's store is only scanned if its config and every layer match the image ID. Requires sudoers v8: re-run the enrollment script on Podman hosts.

### Removed

- The Contributor License Agreement (`CLA.md`, `CLA.es.md`) and the CLA Assistant check on pull requests. Contributions are now accepted under the project's license (AGPL-3.0) without signing anything.

### Fixed

- A failed run's error was shown twice at the end of its log ("Fallo: …" and "Fallido: …").
- The web terminal never opened in production builds ("No se pudo cargar la terminal"): xterm.js is a CommonJS package and the production bundle only exposes it as a default export, so the terminal class was not found. "Reconectar" now also retries loading the terminal, and leaving the page to confirm your identity no longer triggers the browser's "leave site?" prompt while no session is open.
- Confirming your identity with an OIDC provider (step-up before opening a terminal and other sensitive actions) failed with authentik from the second time in the same provider session: authentik ignores `max_age=0` and does not ask for credentials again on later `prompt=login` requests, so the returned `auth_time` was stale. The request now uses `max_age=30`, which authentik enforces.
- A fully patched RHEL-family server (e.g. Rocky Linux 10) showed hundreds of open HIGH vulnerabilities with a patch available: dnf keeps the previous kernels installed (`installonly_limit`) and Trivy reports, for each package of each older kernel, every CVE fixed since then. Findings on kernels that are not running (and on kernel headers and tools) no longer count in the asset, inventory tree, project and dashboard summaries; the asset overview shows them apart, and the asset's Vulnerabilities tab now hides them by default like the main list, saying how many were left out, with an "Incluir lo oculto" toggle.

## [0.5.2] - 2026-10-31

### Added

- `CHANGELOG.md` with the changes of every version since 0.1.0. GitHub releases now take their notes from it.

### Fixed

- Collecting from a host failed with "Failed to create temporary directory" when the worker runs with a read-only root filesystem (as in the example compose file): Ansible's local temporary directory now lives in the job's tmpfs. The error shown for a failed collection is no longer cut off mid-word and recognises this case.

## [0.5.1] - 2026-10-29

### Fixed

- Publishing the web, API and worker images to `ghcr.io/infraward`: the registry login in the release pipeline failed (CI components updated to v1.1.1).

## [0.5.0] - 2026-10-29

First public release of the source code on GitHub.

### Added

- `REDIS_PASSWORD_FILE` for the API, worker and gateway, as an alternative to `REDIS_PASSWORD`. The example compose file now passes the Redis password as a secret (created by `init.sh`), so it no longer appears in any container's environment.
- `OIDC_ALLOW_UNVERIFIED_SIGNUP` for providers that verify email addresses but do not send the `email_verified` claim (such as Entra ID). It only allows sign-up, never linking to an existing local account.
- OCI labels (title, description, license, source and creation date) on the web, API and worker images.
- `SECURITY.md` with the vulnerability reporting policy, and `docs/SECURITY-NOTES.md` with the authorization model and a deployment checklist.
- `CONTRIBUTING.md` and an individual Contributor License Agreement (based on the Apache ICLA v2.2).

### Changed

- The project name is written as InfraWard in every text: web, API, worker, enrollment script and documentation. This includes the TOTP issuer; authenticators that are already set up keep their label. Lowercase identifiers (`infraward`, paths and keys) are unchanged.
- The API docs (`/docs` and `/openapi.json`) are off by default in production; set `DOCS_PUBLIC=true` to enable them.
- `PUBLIC_URL` must use HTTPS in production, except for loopback addresses.

### Fixed

- The web terminal no longer loses the output of commands that finish immediately.

### Security

- Patched vulnerable dependencies (including fastify, zod, fast-uri, body-parser, multer, undici and vite) and hardened the pnpm supply chain (minimum release age, no trust downgrades, no exotic sub-dependencies).
- Login is also rate-limited per account, not only per IP (`LOGIN_ACCOUNT_THROTTLE_*`, with counters in Redis via `THROTTLE_STORAGE`). Only failures count, a successful login resets the counter, and networks the account has recently signed in from are not blocked, so a single IP cannot lock out another account.
- Resetting or changing a password now also revokes the user's API tokens.
- Automatic OIDC sign-up requires a verified email address, so nobody can create an account with someone else's email.
- The enrollment script refuses a symlinked (or foreign-owned) `~/.ssh` or `authorized_keys` in the inventory user's home and writes them as that user, so it can no longer be tricked into overwriting root's keys.
- The OpenBao client never follows HTTP redirects, so AppRole credentials and tokens cannot be forwarded to another host.
- Scan exclusion patterns are matched without regular expressions, which removes a ReDoS on patterns with many `*`.
- The web terminal does not accept input until the API has recorded the session opening.
- The enrollment token is no longer written to the nginx access log.
- nginx sends X-Frame-Options, CSP `frame-ancestors`, HSTS, `nosniff` and Referrer-Policy on every location, and the production build no longer needs `script-src 'unsafe-inline'`.
- Container images: updated base images (nginx 1.31 on Alpine 3.24), npm and corepack removed from the API image, Trivy 0.76.1, and every image is scanned for fixable critical vulnerabilities before it is pushed. The worker runs on Ubuntu 26.04 for the OpenSSH client fix (CVE-2026-60002).
- Example compose file: Redis password, an internal network for PostgreSQL, Redis and OpenBao, `cap_drop: ALL`, `no-new-privileges`, read-only root filesystems and non-root users.

## 0.4.0 - 2026-10-23

### Added

- Multi-factor authentication with TOTP, and recent re-authentication (step-up) for sensitive actions.
- Credentials vault, and a warning when a server's sshd configuration needs attention.
- Customizable dashboards with widgets; the project summary is now a widget dashboard.
- Interactive web terminal through the worker's gateway mode, with access policies and immediate session cut-off.
- Worker parallelism and support for running several worker replicas.
- "Search for new vulnerabilities" in Vulnerabilities, using the Trivy database, and a "Data sources" panel.

### Changed

- Redesigned Profile, "Add server" and Projects (grid or list view).
- The vulnerability list is faster: it only aggregates the CVEs on the current page.

### Fixed

- Saving a dashboard after using its menu no longer fails with an overlap error.
- Vulnerability search finds tags with accented characters.
- The worker waits for the API to finish database migrations before taking jobs.
- A forced Trivy database download is no longer skipped.
- The last row of the web terminal is no longer cut off.

## 0.3.0 - 2026-10-21

### Added

- Search with filter syntax, bulk actions on vulnerabilities and inventory policy exclusions.
- Vulnerability prioritization using KEV, EPSS, noise and asset context.

## 0.2.0 - 2026-10-18

### Added

- Which service serves each domain.
- Bulk operations, export and API tokens.
- Users can change their own email address (local accounts, from a web session and with an attempt limit), and admins can change any user's email.
- The example deployment uses bind mounts under `./data`, and `init.sh` checks their permissions.

### Fixed

- An unrelated `Authorization` header no longer invalidates the cookie session.

## 0.1.0 - 2026-10-15

Initial release.

### Added

- Web app, API and worker connected through a job queue, with container images and an example compose deployment (OpenBao included and enabled by default).
- Asset inventory with relations, snapshots and a tree view; asset pages, a dashboard, an activity log of jobs, and global search across vulnerabilities and inventory.
- Server enrollment with one-time tokens, SSH host key pinning and an enrollment script with live progress (`--install-sudo` optional), using a single root helper in sudoers that also works with sudo-rs.
- Collection with Ansible and role detection, plus discoverers for Proxmox (containers via `pct exec`), Docker and Plesk.
- Duplicate server detection by machine-id that never overwrites data; clones that share a machine-id are tracked separately.
- Secrets with a local AES-256-GCM provider or OpenBao (AppRole, KV v2), and short-lived SSH certificates from the OpenBao SSH CA (the default for enrollment).
- Vulnerability scanning with Trivy, container images as assets with findings stored once per image, CycloneDX SBOMs and package lists, and periodic re-evaluation without connecting to the servers.
- CVE search with the tree of affected assets, Trivy details and newly found CVEs.
- Periodic reconciliation, inventory policy, snapshot diffs and notifications.
- User management, roles (viewer, editor, operator, auditor and admin), audit log, httpOnly cookie sessions, login rate limiting and OIDC login.
- Inventory organization: display names, colored tags, notes and projects.
- Relationship views: asset map, hierarchy and layered topology.
- Domain inventory with Cloudflare, RDAP, certificates and dangling DNS records.
- Light and dark theme.

[Unreleased]: https://github.com/InfraWard/infraward/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/InfraWard/infraward/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/InfraWard/infraward/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/InfraWard/infraward/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/InfraWard/infraward/releases/tag/v0.5.0
