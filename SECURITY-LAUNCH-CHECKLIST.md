# Production security checklist

The application now restricts browser origins, sets defensive HTTP headers,
expires login sessions after eight hours, limits repeated authentication
attempts, protects document downloads behind login, validates upload types and
limits password-reset requests.

Before publishing:

1. Copy `.env.example` to `.env`, set `NODE_ENV=production`, and set
   `ALLOWED_ORIGINS` to the exact `https://` domain used by the site.
2. Change all initial/default passwords before the first launch. Use at least
   12 unique characters for every administrator and manager account.
3. Deploy behind HTTPS (for example Nginx, a hosting platform TLS endpoint, or
   Cloudflare). Redirect HTTP to HTTPS and keep server ports private.
4. Do not upload `.env`, `data/db.json`, backups, or the `data/uploads` folder
   to public storage. Back up encrypted copies outside the web root.
5. Run `npm audit` and apply dependency updates during each maintenance window.
6. Restrict hosting-panel, database, and backup access with MFA and separate
   admin accounts. Review server logs and backups regularly.

No internet-connected system can promise that it will never be attacked. These
controls reduce common risks; keeping the server, dependencies, TLS, secrets,
and backups maintained is still necessary.
