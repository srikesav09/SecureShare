# Database design

SecureShare uses MongoDB through Mongoose. File bytes live in Amazon S3; MongoDB stores identity,
ownership, encrypted-file metadata, share capabilities, and audit events.

## Collections

### `users`

Stores `name`, unique lower-case `email`, bcrypt `password`, `role` (`USER` or `ADMIN`),
`isBlocked`, `storageUsed`, and `storageLimit`. Storage values are bytes. Timestamps are enabled.

### `files`

Stores the original display name, generated stored name, validated MIME type, size, owner reference,
unique S3 key, encryption flag, AES IV, SHA-256 hash, and timestamps. `securityAnalysis` contains the
status (`CLEAN`, `REVIEW`, or `BLOCKED`), risk score, findings, analysis engine, and ClamAV result.
Every file has an owner reference and file access is scoped to that owner in service queries.

### `shares`

Stores references to the file and owner, a unique SHA-256 digest of the URL token, optional bcrypt
password hash, expiry time, revocation state, download count, optional maximum downloads, and
timestamps. Plain share tokens are returned only when a link is created; they are not stored in the
database or audit details.

### `auditlogs`

Stores the action, status, resource type and ID, optional user reference, timestamp, request ID, IP
address, user-agent, and sanitized details. Authenticated users can query their own events; owners
can also see anonymous events for their share links.

## Relationships and invariants

```text
User 1 -------- * File
User 1 -------- * Share -------- 1 File
User 1 -------- * AuditLog
```

- A file cannot be downloaded or deleted by a non-owner.
- A share can be revoked by its owner and is bounded by expiry and, optionally, download count.
- Download services verify the decrypted SHA-256 hash before returning bytes.
- Deleting a file decrements the owner's usage and attempts S3 cleanup.
- Audit details are sanitized to prevent passwords, tokens, cookies, authorization headers, and
  secrets from being persisted or returned.

Indexes and uniqueness constraints should be reviewed as data volume grows. In particular, email,
stored file names, S3 keys, and share token digests are unique fields in the current schemas.
