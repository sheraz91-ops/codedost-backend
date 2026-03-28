# CodeDost Backend API

Node.js + Express + MongoDB backend for CodeDost.

## Setup

```bash
npm install
cp .env.example .env
# Fill in your .env values
npm run dev
```

## Email configuration

The backend requires SMTP credentials to send verification and welcome emails.

Add the following values to your `.env` file:

- `EMAIL_HOST`
- `EMAIL_PORT`
- `EMAIL_SECURE`
- `EMAIL_USER`
- `EMAIL_PASS`
- `EMAIL_FROM`

For development, if SMTP credentials are not provided, the app will automatically create an Ethereal test account and log the email preview URL.

## Endpoints

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST | /api/auth/register | None | Create account |
| POST | /api/auth/login | None | Login |
| POST | /api/auth/logout | JWT | Logout |
| POST | /api/auth/refresh | Cookie | Refresh access token |
| GET  | /api/auth/me | JWT | Get profile |
| PATCH | /api/auth/updateProfile | JWT | Update profile |
| PATCH | /api/auth/changePassword | JWT | Change password |
| POST | /api/analyze | Optional JWT | Log analysis + check quota |
| GET  | /api/analyze/quota | Optional JWT | Check remaining quota |
| POST | /api/subscription/activate | JWT | Activate Pro with Gumroad key |
| GET  | /api/subscription/status | JWT | Check subscription status |
| GET  | /api/health | None | Health check |

## Tier Limits

| Tier | Analyses/Month | Max Lines |
|------|---------------|-----------|
| Guest (no login) | 5 | 300 |
| Free (logged in) | 20 | 1000 |
| Pro ($0.99/mo) | Unlimited | Unlimited |
