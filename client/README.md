# SecureShare client

This directory contains the React/Vite frontend for SecureShare.

## Commands

```powershell
npm ci
npm run dev
npm run lint
npm run build
npm run format
npm run format:check
```

Set `VITE_API_URL` in `client/.env` to override the default API URL:

```env
VITE_API_URL=http://localhost:5000
```

The production client uses `https://api.srikesav.site` by default.
