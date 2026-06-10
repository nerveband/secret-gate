# Secret Gate

GitHub Actions approval gate that sends a Telegram notification before waiting on a protected GitHub Environment.

## GitHub setup

Create these repository secrets in GitHub:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID` set to `123456789`

Optional, only for Telegram group topics:

- `TELEGRAM_THREAD_ID`

Create a GitHub Environment named `secret-gate` and add the required reviewer(s). The workflow pauses at that environment after sending the Telegram message.

## Run

Use **Actions** -> **Secret Gate** -> **Run workflow** and enter the reason for approval.
