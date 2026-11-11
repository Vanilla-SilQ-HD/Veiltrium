# Security policy

## Supported versions

Security fixes are applied to `main` and published in the newest installer and panel releases. Use `veiltrium check-update` and update to the latest release before reporting a vulnerability.

## Report a vulnerability

Use a [private GitHub security advisory](https://github.com/Vanilla-SilQ-HD/Veiltrium/security/advisories/new). Do not open a public issue for an exploitable vulnerability.

Include the affected version, configuration, impact and a minimal reproduction. Use synthetic credentials and documentation-only IP addresses. Never attach real private keys, passwords, panel cookies, client links, export archives, `/root/veiltrium` files or logs containing secrets.

Useful reports cover, for example, command execution, privilege escalation, firewall or sandbox bypass, secret disclosure, signature/verification bypass, rollback leaving a node inconsistent, and CSRF or authentication bypass in the panel.

The maintainer will triage the report privately, coordinate a fix and disclose details only after users have had a reasonable opportunity to update.
