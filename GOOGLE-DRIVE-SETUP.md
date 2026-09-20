# Land Help Center — Production Storage Setup

Google Drive is the final production file storage for customer documents, order attachments and the active site logo.

## Google Drive
1. Create a dedicated Drive folder such as "Land Help Center / Customer Files".
2. Copy its Folder ID into `GOOGLE_DRIVE_FOLDER_ID`.
3. Use either OAuth refresh-token credentials or a service account.
4. For a service account, share the target folder with the service-account email as Editor.
5. Keep all credentials only in Vercel Environment Variables.

## Persistent database
Set `POSTGRES_URL` to a managed PostgreSQL connection string. Customer accounts, balances, orders, top-ups, notifications and sessions should not depend on Vercel's temporary filesystem.

## Required Vercel variables
`POSTGRES_URL`
`GOOGLE_DRIVE_FOLDER_ID`
and either:
- `GOOGLE_DRIVE_CLIENT_ID`, `GOOGLE_DRIVE_CLIENT_SECRET`, `GOOGLE_DRIVE_REFRESH_TOKEN`
or:
- `GOOGLE_SERVICE_ACCOUNT_EMAIL`, `GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY`

## Verification
After adding variables and redeploying:
- `/api/health`
- Admin storage-health endpoint
- Registration/login/refresh/logout
- Customer order upload
- Admin delivery
- Customer-only file download

Never expose credentials in frontend code.
