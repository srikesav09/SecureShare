# SecureShare

SecureShare is a private file-sharing platform. Authenticated users can upload files, view their stored files, download or delete them, and create controlled share links.

## Features

- User registration, login, and protected profiles.
- File upload with type/signature validation.
- File listing, in-app preview for browser-supported files, download, and deletion.
- Per-file header and metadata risk analysis with user-facing findings.
- Account-scoped audit activity for uploads, previews, downloads, shares, sign-ins, and failures.
- On-demand analysis for older files that were uploaded before security analysis was enabled.
- Expiring or revocable share links.
- MongoDB persistence and AWS S3 file storage.
- Encryption, rate limiting, security headers, request IDs, CORS restrictions, and centralized errors.
- Responsive React UI with Overview, My files, Shared links, and Settings views.

## Technology

| Area       | Technology                                            |
| ---------- | ----------------------------------------------------- |
| Client     | React, React Router, Vite, Tailwind CSS               |
| API        | Node.js, Express                                      |
| Database   | MongoDB with Mongoose                                 |
| Storage    | Amazon S3                                             |
| Security   | Zod, Helmet, CORS, rate limiting, Multer              |
| Testing    | Node.js test runner, Supertest, MongoDB Memory Server |
| Deployment | GitHub Actions, Vercel, AWS EC2                       |

## Project structure

```text
SecureShare/
├── client/                 # React/Vite web application
│   ├── public/              # Static assets and application icons
│   └── src/                 # Components, pages, routes, and API services
├── server/                 # Express API
│   ├── src/                 # Controllers, middleware, models, routes, and services
│   └── test/                # API and security tests
├── docs/                   # Architecture, API, deployment, and security documentation
├── postman/                # Postman collections and environments
└── .github/workflows/      # CI/CD workflows
```

## Requirements

- Node.js 22 or newer.
- npm.
- MongoDB connection string.
- AWS S3 bucket and credentials for the server.

## Local setup

```powershell
git clone <your-repository-url>
cd SecureShare

cd server
npm ci

cd ..\client
npm ci
```

Create `server/.env` from [`server/.env.example`](server/.env.example) and set the required values. Never commit `.env` files, secrets, AWS credentials, or uploaded files.

Start the API:

```powershell
cd server
npm run dev
```

The API runs on `http://localhost:5000` by default. In a second terminal, start the client:

```powershell
cd client
npm run dev
```

Vite normally serves the client at `http://localhost:5173`. If that port is busy, use the alternate URL printed in the terminal.

To override the API URL, create `client/.env`:

```env
VITE_API_URL=http://localhost:5000
```

The client removes a trailing `/api` automatically, so either `http://localhost:5000` or `http://localhost:5000/api` works.

## API overview

The local API base is `http://localhost:5000/api`. Production uses `https://api.srikesav.site/api`.
The production web app is served by Vercel at `https://secure-share-lime.vercel.app`.

| Method | Endpoint                  | Purpose                       | Access        |
| ------ | ------------------------- | ----------------------------- | ------------- |
| GET    | `/api/health`             | Check API availability        | Public        |
| POST   | `/api/auth/register`      | Create an account             | Public        |
| POST   | `/api/auth/login`         | Sign in and receive a token   | Public        |
| GET    | `/api/auth/profile`       | Read the current profile      | Authenticated |
| POST   | `/api/files/upload`       | Upload one file               | Authenticated |
| GET    | `/api/files`              | List the current user’s files | Authenticated |
| GET    | `/api/files/:id/download` | Download a file               | Authenticated |
| GET    | `/api/audit-logs`         | Read account and share activity | Authenticated |
| POST   | `/api/files/:id/security-analysis` | Analyze an existing file | Authenticated |
| DELETE | `/api/files/:id`          | Delete a file                 | Authenticated |
| POST   | `/api/share/:fileId`      | Create a share link           | Authenticated |
| DELETE | `/api/share/:shareId`     | Revoke a share link           | Authenticated |
| GET    | `/share/:token`           | Access a shared file          | Share token   |

Protected requests use `Authorization: Bearer <jwt-token>`.

More detail is available in [`docs/`](docs/), especially [`docs/api/api-specification.md`](docs/api/api-specification.md).

## Security analysis and audit activity

Every upload is checked before encryption using extension validation, file signatures, and advisory
header heuristics. The analysis looks for executable headers, suspicious double extensions, active
content patterns, and risky PDF actions. A warning does not prove that a file is malicious, and a
clean result is not a guarantee that a file is safe; users should still use endpoint antivirus and
avoid opening untrusted files.

The Audit activity view is limited to the signed-in user’s own events plus anonymous access events
for links they own. It records the action, result, timestamp, file or link, IP address, and browser
signature. Secrets, passwords, and share tokens are redacted or never stored in audit details.

## Quality checks

```powershell
cd client
npm run format:check
npm run lint
npm run build

cd ..\server
npm run format:check
npm test
```

Use `npm run format` in either package to format its source files. S3-dependent server tests require compatible test credentials or an S3 mock/LocalStack instance; missing credentials can cause upload tests to fail.

## Deployment

Pushing to `main` starts [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml), which:

1. Installs server dependencies and runs tests.
2. Builds the client. Vercel deploys the client automatically from the connected GitHub repository.
3. Pulls the repository on EC2, rebuilds the client, installs production server dependencies, and restarts PM2.
4. Checks `https://api.srikesav.site/api/health`.

Production URLs:

- Client: [https://secure-share-lime.vercel.app](https://secure-share-lime.vercel.app)
- API health: [https://api.srikesav.site/api/health](https://api.srikesav.site/api/health)

Set `FRONTEND_URL` on the EC2 server to the Vercel production URL (and any comma-separated custom frontend domains) so browser API requests and file downloads pass CORS validation.

Keep deployment credentials in GitHub Secrets. The workflow uses the AWS credentials and region needed for EC2 Systems Manager deployment. Vercel uses its native GitHub integration for the frontend. See [`docs/deployment/deployment-guide.md`](docs/deployment/deployment-guide.md).

## Security and contributing

Read [`SECURITY.md`](SECURITY.md) for reporting guidance and [`docs/security/`](docs/security/) for the security design. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development checklist.

## License

See [`LICENSE`](LICENSE).
