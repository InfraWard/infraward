# Security Policy

## Supported versions

Only the latest released version of InfraWard receives security fixes. Please upgrade to the latest release before reporting an issue.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for security vulnerabilities.**

Report them privately through one of these channels:

- GitHub private vulnerability reporting: go to the repository's **Security** tab and click **Report a vulnerability**.
- Email: **natanael@h4ckdata.es**

Please include as much of the following as you can:

- Affected version (release tag or commit).
- Component affected (API, web, worker, gateway, Ansible roles...).
- Steps to reproduce the issue.
- Impact: what an attacker could achieve.
- A proof of concept, if available.

## What to expect

These are targets, not guarantees, as InfraWard is maintained by a small team:

- **Acknowledgement** within 72 hours.
- **Initial assessment** (severity and whether it is accepted) within 7 days.
- **Fix and coordinated disclosure** within 90 days of the report. We will agree on the disclosure date with you and keep you informed of progress.

Please do not disclose the vulnerability publicly until a fix has been released or the 90-day period has ended, whichever comes first.

## Hardening your deployment

[docs/SECURITY-NOTES.md](docs/SECURITY-NOTES.md) describes the authorization model, the security
trade-offs of the design and a deployment checklist (`PUBLIC_URL` over https, `TRUST_PROXY`, login
rate limits, the API reference and enrollment tokens in logs).

## Out of scope

- Issues in self-hosted deployments caused by insecure configuration (for example, exposing services without TLS or using default/weak secrets).
- Attacks that require administrator access to InfraWard or root access to the host.
- Denial of service through volumetric traffic.
- Social engineering, phishing or physical attacks.
- Vulnerabilities in third-party dependencies that are already publicly known and have no InfraWard-specific impact (please report them upstream).

## Credit

With your permission, we will credit you in the release notes and the security advisory for the fix.
