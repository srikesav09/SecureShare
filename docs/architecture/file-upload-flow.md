# File upload flow

Uploads are accepted at `POST /api/files/upload` as a single multipart field named `file`. The
endpoint requires authentication and an upload rate-limit check.

## Validation pipeline

1. Multer writes the temporary upload beneath the server's `uploads` directory.
2. The filename is checked for null bytes, path separators, traversal markers, empty names, and
   excessive length.
3. The extension and client MIME type must be one of the supported pairs: PDF, PNG, JPEG, or plain
   text. The request is limited to one file and 10 MiB.
4. The file signature is checked against the extension. For example, PDFs must begin with `%PDF-`,
   PNGs must contain the PNG signature, JPEGs must contain the JPEG marker, and text must decode as
   UTF-8. The server replaces the client MIME value with the validated type.
5. ClamAV scans the temporary file. If `CLAMAV_REQUIRED=true`, an unavailable scanner fails closed;
   infected files are rejected.
6. Header and metadata heuristics calculate a risk score and findings. High-severity findings mark a
   file `REVIEW`; this analysis is advisory and does not replace antivirus or sandboxing.
7. The original bytes are hashed, encrypted, uploaded to S3, and recorded in MongoDB with the IV,
   hash, ownership, size, and security analysis.
8. The owner's `storageUsed` value is incremented and a successful upload is written to the audit
   log.

If any stage fails, the service removes the temporary plaintext, encrypted temporary file, and S3
object when applicable. Storage quota is checked before processing; the default account limit is 100
MiB. The server should never expose the local upload directory as static content.

## Supported file types

| Extension | MIME type |
| --- | --- |
| `.pdf` | `application/pdf` |
| `.png` | `image/png` |
| `.jpg`, `.jpeg` | `image/jpeg` |
| `.txt` | `text/plain` |

Files are not renamed based on user input when stored locally: the server generates a safe temporary
name. The original display name is retained only as metadata.
