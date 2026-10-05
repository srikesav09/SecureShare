## Audit trail

SecureShare records authentication, upload, preview, download, deletion, share creation, share
opening, shared-file downloads, password failures, and invalid-link events. Authenticated users can
see their own activity at `/api/audit-logs`; owners also see anonymous access events for their share
links. Audit details are sanitized before returning them to a client.

## File-risk analysis

Before a file is encrypted and stored, SecureShare checks its extension and magic signature, then
runs a lightweight heuristic analysis over the file header and metadata. It detects executable
signatures, suspicious double extensions, active-content patterns, and risky PDF actions such as
JavaScript, automatic actions, and embedded launchable content.

This is an advisory defense-in-depth control. It is not a full malware scanner, sandbox, or threat
intelligence service. Production environments should still add an antivirus or malware-scanning
pipeline for high-assurance threat detection.
