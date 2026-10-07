# Threat model

## Scope and assets

The system protects user credentials, file contents, file metadata, S3 objects, share capabilities,
and audit history. The main trust boundaries are the browser-to-API connection, the API-to-MongoDB
connection, and the API-to-S3 connection. The upload directory is temporary and must remain private.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| An attacker guesses or steals a file ID | JWT authentication and owner checks on file operations | A stolen authenticated token still grants that account's access until it expires or is invalidated |
| A share token is brute-forced | 32 random bytes, only a SHA-256 digest is stored, expiry/revocation, optional password and download cap | Anyone who obtains the URL can use it within its configured limits |
| Malicious upload disguised by extension | Filename/MIME checks and magic-byte validation | Supported parsers and content can still contain novel threats |
| Malware upload | ClamAV scan before encryption plus header heuristics | Heuristics and antivirus are not a sandbox or a guarantee of safety |
| Storage tampering or corruption | Encrypted S3 objects and SHA-256 verification after decryption | Key compromise or a database hash compromise needs separate key and database controls |
| Path traversal through filenames | Reject traversal markers and separators; generate server-side storage names | Keep temporary directories outside any static web root |
| Abuse and resource exhaustion | File-size, file-count, quota, and endpoint rate limits | Distributed abuse still requires infrastructure-level controls |
| Credential attacks | bcrypt password hashes, failed-login controls, blocked accounts | MFA and broader identity protections are not currently implemented |
| Sensitive data in logs | Audit sanitization and token redaction | Review third-party and infrastructure logs as part of operations |
| Untrusted link import | `assertTrustedShareLink` accepts only configured SecureShare hosts or local development hosts | Misconfigured `APP_URL` or deployment trust lists can weaken this boundary |

## Security assumptions

TLS terminates correctly in production, environment secrets are protected, MongoDB and S3 credentials
are least-privilege, and the deployment host is trusted. The API does not claim to make a file safe to
open; it helps identify and control risk while preserving confidentiality and integrity.

## Incident response priorities

If credentials or the encryption key are exposed, immediately restrict the affected cloud identity,
rotate secrets, preserve audit records, and assess whether files require re-encryption. If a share URL
is exposed, revoke that share and create a replacement with a password and download limit. If malware
is detected, preserve the audit event, remove the object, identify related downloads, and investigate
the scanner and deployment logs.
