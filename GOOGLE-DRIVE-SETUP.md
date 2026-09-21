# Land Help Center — Production Storage Setup

Google Drive is the final production file storage for customer documents, order attachments and the active site logo.

## Google Drive
1. Create a dedicated Drive folder such as "Land Help Center / Customer Files".
2. Copy its Folder ID into `GOOGLE_DRIVE_FOLDER_ID`.
3. Use either OAuth refresh-token credentials or a service account.
4. For a service account, share the target folder with the service-account email as Editor.
5. Keep all credentials only in Vercel Environment Variables.

## Persistent application state
Preferred: set `POSTGRES_URL` to a managed PostgreSQL connection string.

If you want Google Drive to be the single durable backend, this version can also store the application state JSON in the same Drive folder. In that mode, customer accounts, balances, orders, top-ups, notifications and login sessions are persisted in `landhelpcenter-state.json` on Google Drive. Do not rely on Vercel's temporary filesystem.

## Required Vercel variables
`GOOGLE_DRIVE_FOLDER_ID`
and either:
- `GOOGLE_DRIVE_CLIENT_ID`, `GOOGLE_DRIVE_CLIENT_SECRET`, `GOOGLE_DRIVE_REFRESH_TOKEN`
or:
- `GOOGLE_SERVICE_ACCOUNT_EMAIL`, `GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY`

For Google Drive-backed state, `POSTGRES_URL` is optional. Optional: `GOOGLE_DRIVE_STATE_FILE_NAME` (defaults to `landhelpcenter-state.json`).

## Verification
After adding variables and redeploying:
- `/api/health`
- Admin storage-health endpoint
- Registration/login/refresh/logout
- Customer order upload
- Admin delivery
- Customer-only file download

Never expose credentials in frontend code.
