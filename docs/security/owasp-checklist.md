# OWASP-oriented security checklist

This checklist maps the main OWASP risks to the controls currently present in SecureShare. It is a
development checklist, not a penetration-test report.

| Area | Current control | Follow-up |
| --- | --- | --- |
| Broken access control | Bearer authentication, owner checks for files and shares, admin middleware | Add automated authorization tests for every new resource route |
| Cryptographic failures | bcrypt passwords, AES-256-CBC before S3, SHA-256 integrity checks, secret-based configuration | Prefer authenticated encryption and managed key rotation |
| Injection | Mongoose queries, Zod/request validation, generated S3 keys, restricted filenames | Keep validating all new query and command inputs |
| Insecure design | Expiring/revocable links, optional share passwords, download limits, storage quotas | Threat-model new sharing and import features before release |
| Security misconfiguration | Helmet, restricted CORS, environment-based configuration, no public file directory | Set production secrets, HTTPS, least-privilege AWS permissions, and secure cookie policy where applicable |
| Vulnerable components | npm lockfiles and CI checks | Run dependency audits and patch regularly |
| Identification/authentication | bcrypt, JWT verification, blocked-account checks, rate limits | Consider refresh-token rotation, MFA, and token revocation for higher assurance |
| Software/data integrity | File extension and magic-byte checks, ClamAV, cleanup on failed uploads, hash verification | Add signed build/dependency provenance and malware-scan monitoring |
| Logging/monitoring | Sanitized audit records, request IDs, success/failure events | Alert on repeated failures, malware detections, and unusual downloads |
| SSRF | Trusted-host validation for imported SecureShare links | Keep outbound fetches restricted; never fetch arbitrary URLs |

## Release checks

- Confirm `ENCRYPTION_KEY`, JWT configuration, database, S3, CORS, and `APP_URL` are set from a secret
  store rather than committed files.
- Confirm S3 objects are private and the AWS identity can access only the required bucket/prefix.
- Keep ClamAV required in production when the deployment depends on malware rejection.
- Run server tests, client lint/build, and dependency vulnerability checks in CI.
- Verify error responses and logs do not contain passwords, bearer tokens, share tokens, or raw file
  contents.
