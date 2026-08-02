# 🚀 SecureShare API Collection

This folder contains the Postman collection and environments used to test the SecureShare backend APIs.

---

## Files

- `SecureShare.postman_collection.json`
- `Local.postman_environment.json`

---

## Import

1. Open Postman
2. Click **Import**
3. Import both JSON files

---

## Environment

Select the **local** environment.

| Variable | Value |
|----------|--------------------------|
| baseUrl | http://localhost:5000 |

---

## Running the Backend

```bash
cd server
npm install
npm run dev