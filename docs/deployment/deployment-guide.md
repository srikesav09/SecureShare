# SecureShare deployment guide

SecureShare uses one production deployment path:

```text
GitHub main branch
  ├─ Vercel native Git integration -> React/Vite client
  └─ GitHub Actions + AWS SSM -> EC2 API + PM2
```

## Production endpoints

- Frontend: https://secure-share-lime.vercel.app
- API: https://api.srikesav.site
- Health check: https://api.srikesav.site/api/health
- AWS region: `ap-south-1`

The suspended cPanel deployment is not part of the current project. Do not add cPanel, FTP, or
domain secrets back to the repository or GitHub Actions.

## Vercel

The Vercel project is connected to `srikesav09/SecureShare` with the client root directory set to
`client`. Every push to `main` creates a new Vercel deployment. Set `VITE_API_URL` only when the
API origin needs to differ from the default `https://api.srikesav.site`.

## EC2

The EC2 instance must have the `SecureShareEC2Role` IAM role and SSM access. The deployment workflow
pulls `main`, builds the client, installs production server dependencies, restarts the PM2 process,
and checks the API health endpoint.

If a manual deployment is required:

```bash
cd /home/ubuntu/SecureShare
sudo chown -R ubuntu:ubuntu .
git pull origin main
cd client && npm ci && npm run build
cd ../server && npm ci --omit=dev
pm2 restart secureshare
pm2 save
curl -i https://api.srikesav.site/api/health
```

Keep `server/.env` on the server only. It must contain the MongoDB, S3, JWT, and
`FRONTEND_URL=https://secure-share-lime.vercel.app` configuration. Never commit secrets.
