# cPanel deployment

Every push to `main` builds the React client and publishes two GitHub Actions artifacts:

- `secureshare-client-dist` contains the deployable client files.
- `secureshare-ui-zip` contains a cPanel-ready ZIP archive.

The EC2 deployment runs automatically through AWS SSM. cPanel deployment is enabled by setting this repository variable:

```text
CPANEL_DEPLOY=true
```

Add these repository secrets before enabling it:

```text
CPANEL_FTP_SERVER
CPANEL_FTP_USERNAME
CPANEL_FTP_PASSWORD
```

The workflow uploads the built client to:

```text
/public_html/secureshare/dist/
```

The cPanel domain document root must point to that directory. The client production build uses `https://api.srikesav.site` for API requests.
