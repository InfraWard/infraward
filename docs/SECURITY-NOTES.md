# Security notes

Design decisions and deployment settings that matter for security. How to report a
vulnerability is in [SECURITY.md](../SECURITY.md).

## Authorization model (single tenant)

InfraWard is a single-tenant tool: every authenticated user belongs to the same organization.

- Endpoints without a `@Can(...)` permission only require authentication. Any signed-in user,
  including the `viewer` role, can read **all** assets, findings, SBOMs and domains of every
  project. Writes and sensitive actions always need an explicit permission.
- An `AccessPolicy` only **adds** permissions on an asset; it never restricts reads.
- This is by design and is not an IDOR while the deployment has a single tenant. Do not use one
  instance for organizations that must not see each other's inventory. A multi-tenant setup would
  need reads filtered by project.

## Run logs

Every collection, discovery and scan keeps a log in `job_run_logs` (DESIGN §20): the commands the
worker ran, their duration and exit code, Ansible failures (`msg`, `rc`, the end of `stderr`) and
the last 40 lines of the stderr of whatever failed. That stderr comes from the servers, so it can
carry anything they print: paths, user names, versions, configuration fragments.

- It never stores stdout (the server data) or the job's temporary paths, and every line goes
  through `redactSecrets` before it is saved (PEM/OpenSSH private keys, credentials in URLs,
  `Authorization` and Bearer tokens, `key=value` pairs with secret-like names, InfraWard,
  OpenBao/Vault, JWT, GitHub/GitLab, AWS and Slack tokens). Redaction is pattern based and
  best-effort: a secret in an unknown format printed by a server would be kept.
- Reading a log needs `assets.operate` (admin, editor, operator), both from the asset
  (`GET /assets/:id/runs/:runId/log`) and from the Activity page (`GET /jobs/runs/:id/log`, which
  also covers runs without an asset); `viewer` and `auditor` only see the runs themselves.
- A bulk operation's summary (`message` of its `assets.bulk` run) includes the email of whoever
  launched it and is shown to every user who can see the Activity, as before; it is now also
  repeated as the `parent` of each task the operation launched.
- Logs are capped per run (`COLLECTION_LOG_MAX_KB`) and deleted after
  `COLLECTION_LOG_RETENTION_DAYS` (30), never later than the run history
  (`JOB_RUNS_RETENTION_DAYS`). Database backups keep them for as long as the backups live.

## `pct-exec` on Proxmox nodes

The enrollment script installs a query helper (`infraward-query`) whose sudoers entry is
read-only, with one exception: `pct-exec` runs an arbitrary command as root inside a container of
that node (Ansible collection inside LXC containers). The helper validates the container id, not
the command.

Consequence: whoever holds the worker's SSH key or certificate is root in every container of
every enrolled Proxmox node. Protect the worker accordingly: keep its image up to date (OpenSSH
client), give it only the network egress it needs and do not expose its host.

## Outbound alerts (webhook and email)

Alert channels (Settings › Alerts, admins only, recent re-authentication to change them) send the
same content as the in-app bell: message, asset name, affected item names and a link. Never facts,
connection data or credentials.

- Only the worker sends. The API stores the channel and queues the test message.
- The full webhook URL (it often carries a token) and its HMAC signing secret are stored in the
  secrets manager. The database and the web only see the host. Audit events record the host or
  the number of recipients, never the URL.
- SSRF: the worker resolves the host before connecting and rejects the target if any address is
  loopback, unspecified, link-local (cloud metadata such as `169.254.169.254`), multicast or
  reserved, and, in IPv6, any range that embeds or translates an IPv4 address (IPv4-compatible
  and mapped, NAT64, 6to4, Teredo), so `[::127.0.0.1]` cannot reach loopback. Private ranges (RFC 1918, CGNAT, ULA) are rejected unless
  `ALERTS_WEBHOOK_ALLOW_PRIVATE=true`, and `http:` unless `ALERTS_WEBHOOK_ALLOW_HTTP=true`. It then
  connects to the validated address (no second lookup, so no DNS rebinding) and does not follow
  redirects. Enable private targets only if the worker's network should be reachable that way.
- A slow or hostile receiver cannot hold the worker: `ALERTS_TIMEOUT_MS` is a total deadline up to
  the response headers, the response body is never read, and deliveries run on their own `alerts`
  queue.
- Receivers should verify `X-InfraWard-Signature` (`sha256=` HMAC-SHA256 of
  `<X-InfraWard-Timestamp>.<raw body>`) and reject old timestamps to stop replays.
- SMTP: TLS is required (`SMTP_SECURE=true`, or STARTTLS enforced by `SMTP_REQUIRE_TLS`, the
  default). The password is a `secret://` reference (`SMTP_PASSWORD_REF`), resolved on each send.

## Docker and rootful Podman hosts

On a Docker host the read-only queries still expose the containers' configuration to root-level
tooling (the helper's templates never print environment variables or non-whitelisted labels, but
`docker` access is root-equivalent). The same applies to rootful Podman (`podman` as root, sudoers
v8). Rootless Podman users are *detected* read-only during collection (running `conmon`
processes, the presence of their socket, container storage in their home), but only *queried* if
they are listed in `/etc/infraward/podman-users`, the server-side consent. That list is written by
the «Habilitar» action (a command the admin runs with sudo, or the same fixed script run as
`infraward-admin` in a read-only web terminal) or, optionally, by the enrollment script option
`--podman-users=<user,…>`. Queries only go through that user's own API socket
(`/run/user/<uid>/podman/podman.sock`), and the Podman client for those queries runs **as that
user** (`runuser`), never as root: the user owns the socket and everything it answers, and could
swap it for a symlink after any check, so a root client would be talking to a hostile server. The
helper also refuses the socket if it, or its directory, is a symlink (an early, best-effort check).
The helper never opens a user's storage as root.

## Read-only terminal actions

A terminal session may run a fixed command instead of a shell (today only enabling rootless Podman
for detected users). It needs the same permission, recent re-authentication and admin access as
the terminal. The API only accepts user names detected on that asset, the gateway builds the argv
itself (no free text reaches a shell) and drops all client input except resizes. It is still a
root action on the server (`sudo`), audited like any terminal session, with the action in the
audit details. The web page never runs it on load: it waits, explaining what will run as root,
until the person presses «Ejecutar», so a crafted link alone cannot trigger it.

Images saved from a rootless user's store come from a service that user controls, and Trivy only
checks the image config. Before scanning such an archive the worker checks that the config has the
requested image ID and that every layer matches its `rootfs.diff_ids` (no duplicate entries, no
OCI `index.json`); otherwise the copy is discarded.

## Deployment checklist

- **`PUBLIC_URL` over https.** Servers fetch the enrollment script with
  `curl <PUBLIC_URL>/enroll/<token> | sudo bash`. With `NODE_ENV=production` the API refuses to
  start if `PUBLIC_URL` is not `https://` (loopback addresses are allowed for local tests).
- **`TRUST_PROXY` set to the exact proxy address.** It decides which `X-Forwarded-For` hops are
  trusted for the client IP (audit log and per-IP rate limits). A broad value such as `true` or
  `uniquelocal` lets any client in that range forge its IP. Use the address or CIDR of the reverse
  proxy that sits in front of the API.
- **Login rate limits.** Per IP (`LOGIN_THROTTLE_LIMIT` / `LOGIN_THROTTLE_TTL`, 5 per 60 s, every
  attempt) and per account (`LOGIN_ACCOUNT_THROTTLE_LIMIT` / `LOGIN_ACCOUNT_THROTTLE_TTL`, 10
  *failed* attempts per 300 s, from any IP). The per-account block does not apply to networks the
  account signed in from successfully in the last 30 days (the IP, or its /64 for IPv6), so
  flooding an account with bad passwords does not lock its owner out of their usual network; the
  per-IP limit still applies there. A successful login resets the account's counter. Counters live
  in Redis (`THROTTLE_STORAGE=redis`, the default), so they are shared by every API replica.
- **API reference.** `/docs` and `/openapi.json` are not served in production unless
  `DOCS_PUBLIC=true`. Outside production they are on by default.
- **Enrollment tokens in logs.** The token travels in the URL path (`/api/enroll/<token>`). The web
  image's nginx does not write those requests to its access log. Its error log still shows the
  request line when the API cannot be reached (the token was not used and expires with
  `ENROLLMENT_TOKEN_TTL`). If you put another reverse proxy in front, disable its access log for
  `/api/enroll/` too, or mask the path.
