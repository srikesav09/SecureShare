# File encryption and integrity flow

SecureShare encrypts files before sending them to Amazon S3. The API keeps file metadata in MongoDB,
but the object stored in S3 is the encrypted payload.

## Upload

```text
multipart upload
      |
      v
filename/MIME checks -> magic-signature checks -> ClamAV + heuristic analysis
      |
      v
SHA-256(original bytes) -> AES-256-CBC encryption -> S3 object
      |                                      |
      +-------------- MongoDB metadata -------+
```

The server reads `ENCRYPTION_KEY` as a 64-character hexadecimal value (32 bytes). Each upload gets a
fresh 16-byte initialization vector (IV). The original file is hashed before encryption; the hash and
IV are stored with the file record. The encrypted object is written under an owner-scoped key such as
`files/<user-id>/<generated-name>.enc`.

## Download and preview

1. The request is authenticated and the file ownership is checked.
2. The encrypted object is fetched from S3.
3. AES-256-CBC decrypts it using the stored IV.
4. SHA-256 is calculated over the decrypted bytes and compared with the stored hash.
5. Only after a successful integrity check are the bytes returned, either for download or browser
   preview. Both operations are audited.

Deletion removes the database record and attempts to remove the corresponding S3 object. Upload error
handling also cleans up local temporary files and an object that was uploaded before a later step
failed.

## Key management and limitations

The encryption key is supplied through server configuration and must not be committed to the
repository. Deployments should keep it in a secret manager and rotate it through a planned
re-encryption process. AES-CBC provides confidentiality and the stored hash provides an integrity
check, but this design is not authenticated encryption; a future migration should consider an AEAD
mode such as AES-GCM with versioned ciphertext metadata.
