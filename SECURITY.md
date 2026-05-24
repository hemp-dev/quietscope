# Security Policy

## Reporting a vulnerability

Please report security issues privately to the project maintainers. Until a dedicated security email is published, use a private GitHub security advisory if available.

Do not include real secrets, tokens, cookies, private keys, Keychain data, browser password data, or full private audit reports in public issues.

## What counts as a security issue

- Secret values printed in output.
- Reading sensitive file contents that should be metadata-only.
- Executing discovered MCP commands, project scripts, shell startup snippets, or suspicious commands.
- Cleanup deleting paths outside the allowlist.
- HTML report injection or unsafe rendering of untrusted strings.
- Network requests, telemetry, analytics, or remote report upload.
- Command construction that uses shell strings instead of strict argument arrays.

## What does not count as a security issue

- Best-effort checks reporting `INFO` when macOS blocks access.
- False positives in risk classification.
- Missing coverage for a new AI tool or MCP schema.
- Manual verification requirements for TCC, MDM, or software updates.

## Privacy expectations

Audit reports contain local paths, host metadata, and security posture information. Treat reports as sensitive local files. The tool masks sensitive environment values and does not read secret file contents, but local paths can still reveal private project or username information.

## Responsible disclosure process

1. Send a private report with reproduction steps and expected impact.
2. Maintainers acknowledge and triage.
3. A fix is prepared with regression tests where practical.
4. Release notes credit the reporter if requested.
5. Public disclosure happens after a fixed release is available or by mutual agreement.
