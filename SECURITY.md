# Security policy

SecureShare handles private files and authentication data. Report suspected vulnerabilities privately to the project owner before making details public.

Include the affected endpoint or component, reproduction steps, impact, and a safe proof of concept. Do not upload real private files or expose credentials while testing.

Security design details are maintained in [`docs/security/`](docs/security/), including the threat model, OWASP checklist, and implemented controls.

## Do not commit

- `.env` files or secrets.
- JWT or encryption keys.
- AWS access keys.
- Database credentials.
- Uploaded files or private logs.
