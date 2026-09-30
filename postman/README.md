# SecureShare API collection

This folder contains the Postman collection and environments used to test the SecureShare backend APIs.

---

## Files

- `SecureShare.postman_collection.json`
- `local.postman_environment.json`
- `production.postman_environment.json`

---

## Import

1. Open Postman
2. Click **Import**
3. Import both JSON files

---

## Environment

Select either the **local** or **production** environment.

| Variable | Value |
|----------|--------------------------|
| baseUrl | http://localhost:5000 |

The production environment uses `https://api.srikesav.site`.

---

## Running the Backend

```bash
cd server
npm install
npm run dev
```
