# Changelog

All notable changes to InfraWard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/InfraWard/infraward/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/InfraWard/infraward/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/InfraWard/infraward/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/InfraWard/infraward/releases/tag/v0.5.0
