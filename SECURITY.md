# Security Policy 🛡️

We take the security of `quietscope` very seriously. If you believe you have found a security vulnerability in this project, please report it to us responsibly using the instructions below.

## Supported Versions ✅

We actively support and provide security patches for the following versions of `quietscope`:

| Version | Supported |
| :--- | :--- |
| v0.5.x | Yes (Active) |
| v0.4.x | Maintenance |
| < v0.4.0 | No |

---

## Reporting a Vulnerability 🔒

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a vulnerability, please report it via one of the following methods:
1. **GitHub Private Vulnerability Reporting**: Go to the "Security" tab of the repository on GitHub and click "Report a vulnerability" (once the repository is public).
2. **Email**: Send an email to `hempestdevelopment@gmail.com` with the subject `[SECURITY VULNERABILITY] quietscope`.

### What to include:
- A detailed description of the vulnerability.
- Step-by-step instructions to reproduce the issue (PoC).
- Potential impact (e.g., local privilege escalation, unexpected path traversal in cleanup).
- Any proposed remediation steps or code diffs.

---

## Our Commitment 🤝

When you report a vulnerability, we promise to:
- Acknowledge receipt of your report within 48 hours.
- Work closely with you to validate and understand the issue.
- Provide a timeline for fixing the vulnerability.
- Publicly credit you for the discovery (unless you prefer to remain anonymous) once the fix is released.

---

## Safe Harbor & Out of Scope 🚫

As `quietscope` is a local-only auditing tool:
- Vulnerabilities that require full root system access already present on the host to exploit quietscope are considered low severity.
- Modifying standard system settings or deleting files via `--clean-confirm` when explicitly authorized by the user is the intended behavior and is out of scope unless it deletes directories outside the strictly defined allowlist.

## AI Control Center Boundaries

- AI Control Center mutations are local-only and require preview/diff plus a backup before write, delete, disable, cleanup, or restore.
- Secret-bearing paths are not readable or manageable: `.env` files, SSH/private keys, Keychain data, cloud credential directories, and known browser/mail/message stores remain blocked.
- MCP configs are parsed structurally for JSON, TOML, and YAML. Quietscope never executes discovered MCP commands, scripts, hooks, or package launchers.
- Environment maps are treated as key-name metadata. UI/API responses redact sensitive-looking values and expose env key names only.
- Local model directories are inventory/manual-review items. They are not auto-cleaned by default and destructive model deletion should be performed outside Quietscope after separate review.
