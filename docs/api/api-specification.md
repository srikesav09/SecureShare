## Audit activity

`GET /api/audit-logs` returns the authenticated user’s recent activity. It also includes anonymous
open/download events for share links owned by that user.

Query parameters:

- `page` — positive page number, default `1`.
- `limit` — `1` to `100`, default `30`.
- `action` — an action from `server/src/utils/constants.js`.
- `status` — `SUCCESS` or `FAILED`.

The response includes sanitized event details, status, timestamp, IP address, and user-agent data.
Passwords, tokens, cookies, authorization headers, and secrets are never returned.
