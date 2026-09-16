# Contributing to SecureShare

## Before opening a change

1. Work in the intended repository and branch.
2. Keep secrets, `.env` files, build output, caches, and uploads out of commits.
3. Run the formatter and relevant tests.
4. Describe deployment or environment changes in the pull request.

## Formatting and checks

```powershell
cd client
npm run format:check
npm run lint
npm run build

cd ..\server
npm run format:check
npm test
```

Use `npm run format` in the relevant package when files need formatting.

## Commit guidance

Use small, focused commits with clear messages, for example:

```text
feat: add file preview action
fix: handle expired share links
docs: update deployment instructions
```

Do not commit credentials or private file contents.
