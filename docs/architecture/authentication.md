# Authentication and authorization

SecureShare uses stateless JSON Web Tokens (JWTs) for API authentication. A user registers with a
name, email, and password, then signs in to receive a token. Passwords are stored as bcrypt hashes;
the plaintext password is never persisted or returned by the API.

## Request flow

1. `POST /api/auth/register` validates the account fields, rejects a duplicate email, hashes the
   password, and creates a `USER` account.
2. `POST /api/auth/login` verifies the email and bcrypt hash, rejects blocked accounts, and signs a
   JWT containing the user identity and role.
3. Protected requests send `Authorization: Bearer <token>`.
4. The authentication middleware verifies the signature and loads the user from MongoDB. It removes
   the password from the lookup and rejects missing or blocked users.
5. Controllers use the authenticated user ID as the ownership boundary for files, shares, and audit
   activity. Administrative routes additionally require the `ADMIN` role.

The token secret and lifetime are configured through the server environment. Tokens are not stored in
the database, so logout is normally implemented by removing the token from the client. To invalidate
already-issued tokens, rotate the JWT secret or add a server-side token revocation strategy.

## Security boundaries

- File downloads require both a valid token and ownership of the requested file.
- Share links are separate capabilities. They use a random token in the URL, while only its SHA-256
  digest is stored in MongoDB.
- Optional share passwords are bcrypt-hashed and are supplied through `X-Share-Password`.
- CORS allows configured frontend origins only; security headers are applied by Helmet.
- Login, upload, and share-creation endpoints are rate limited.

Authentication proves who is making a request; it does not make uploaded files trustworthy. Upload
signature checks, malware scanning, encryption, integrity verification, and audit logging are separate
controls described in the other architecture and security documents.
