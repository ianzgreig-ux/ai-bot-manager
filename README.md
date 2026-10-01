# AI Bot Manager

A Cloudflare Worker portal for managing change requests across selected chatbot repositories.

## Initial access roles

- **Super Admin**: all bots
- **Run/Haven Admin**: Run Energy, Haven and Glues N Tools bots
- **Confidence Admin**: Confidence Bar and Confidence Lab bots

Users enter a six-digit PIN. The PIN determines their role, and the server filters all bot access.

## Initial bots

- [Topex Search Bot](https://github.com/ianzgreig-ux/topex-search-bot)
- [Glues N Tools Chatbot](https://github.com/ianzgreig-ux/glues-n-tools-chatbot)
- [Confidence Schedule](https://github.com/ianzgreig-ux/confidence-office-schedule)

## Cloudflare setup

Connect this repository to a new Cloudflare Worker named `ai-bot-manager`.

Build command:

```
npm install
```

Deploy command:

```
npx wrangler deploy
```

Add these as encrypted Cloudflare secrets:

```
SUPER_ADMIN_PIN
RUN_HAVEN_ADMIN_PIN
CONFIDENCE_ADMIN_PIN
SESSION_SECRET
GITHUB_TOKEN
```

All three PIN values must contain exactly six digits. Use different PINs for each role.

Generate a strong session secret locally:

```
openssl rand -base64 48
```

The GitHub token is optional for signing in and viewing bots. It is required to create GitHub change-request issues. Give it access only to the managed repositories, with **Issues: Read and write** and **Metadata: Read-only**.

Set secrets through Cloudflare:

```
npx wrangler secret put SUPER_ADMIN_PIN
npx wrangler secret put RUN_HAVEN_ADMIN_PIN
npx wrangler secret put CONFIDENCE_ADMIN_PIN
npx wrangler secret put SESSION_SECRET
npx wrangler secret put GITHUB_TOKEN
```

## Current workflow

1. Sign in with a role PIN.
2. Select an authorised chatbot.
3. Describe the requested change.
4. Submit it as a tracked GitHub issue.
5. The development change, pull-request preview and deployment approval workflow can be added as the next phase.

## Security

- PINs and GitHub credentials remain in Cloudflare encrypted secrets.
- Authentication uses a signed, HttpOnly, Secure cookie.
- Every API request is authorised server-side.
- PIN attempts are rate limited.
- The browser never receives repository credentials.

## Local development

Copy `.dev.vars.example` to `.dev.vars`, replace the placeholders, and run:

```
npm install
npm run dev
```

Never commit `.dev.vars`.
