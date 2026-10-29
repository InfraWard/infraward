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

## `pct-exec` on Proxmox nodes

The enrollment script installs a query helper (`infraward-query`) whose sudoers entry is
read-only, with one exception: `pct-exec` runs an arbitrary command as root inside a container of
that node (Ansible collection inside LXC containers). The helper validates the container id, not
the command.

Consequence: whoever holds the worker's SSH key or certificate is root in every container of
every enrolled Proxmox node. Protect the worker accordingly: keep its image up to date (OpenSSH
client), give it only the network egress it needs and do not expose its host.

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
