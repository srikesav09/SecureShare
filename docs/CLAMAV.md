# ClamAV malware scanning

SecureShare scans uploaded files before encryption and storage. Infected files are rejected, removed from the upload directory, and recorded in the audit log.

## Install on Ubuntu/EC2

```bash
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon
sudo systemctl enable --now clamav-freshclam
sudo systemctl enable --now clamav-daemon
sudo freshclam
```

Verify the scanner before restarting SecureShare:

```bash
clamdscan --no-summary /path/to/a-test-file
```

Set these server environment variables:

```env
CLAMAV_REQUIRED=true
CLAMAV_DAEMON_COMMAND=clamdscan
CLAMAV_SCAN_TIMEOUT_MS=30000
CLAMAV_DATABASE_DIR=/var/lib/clamav
```

When `CLAMAV_REQUIRED=true`, uploads fail closed if ClamAV is unavailable. Never expose the upload directory through Nginx or a static file server. After changing environment variables, restart the API process with PM2 and verify `/api/health`.

For local development, keep `CLAMAV_REQUIRED=false` if ClamAV is not installed; the existing header heuristics still run, and the response identifies the malware scan as skipped.
