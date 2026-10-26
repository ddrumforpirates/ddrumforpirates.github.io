<div align="center">

<img src="https://rum.naveengupta.info/img/profile-pic.jpg" width="120" alt="Datadog RUM Pirate logo" />

# ☠️ Datadog RUM for Pirates

**Arrr Matey!** A step-by-step guide to setting up Real User Monitoring on your GitHub Pages site using Datadog.

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-enabled-22863a?style=for-the-badge&logo=github)](https://pages.github.com/)
[![Datadog RUM](https://img.shields.io/badge/Datadog-RUM-632ca6?style=for-the-badge&logo=datadog&logoColor=white)](https://app.datadoghq.com/rum)
[![JS App](https://img.shields.io/badge/App%20Type-JS%20Application-f0db4f?style=for-the-badge&logo=javascript&logoColor=black)](https://app.datadoghq.com/rum/application/create)

</div>

---

## 🗺️ Before You Begin — Prerequisites

> 📌 **Make sure you are in your Datadog Sandbox before starting!**

<details>
<summary><b>Step 1 — Open the RUM Application Creator</b></summary>
<br>

Navigate to the RUM application creator in your Datadog Sandbox:

👉 https://app.datadoghq.com/rum/application/create

</details>

<details>
<summary><b>Step 2 — Create a New RUM Application</b></summary>
<br>

- Set **Application type** to `JS Application`
- Give your application a name
- Click **+ Create New RUM Application**

</details>

<details open>
<summary><b>Step 3 — Save Your Credentials ⚠️ Don't skip this!</b></summary>
<br>

You'll need both of these values in the next section:

| Credential | 
|---|
| 🔑 **Client Token** |
| 🪪 **Application ID** |

> ⚠️ Neither of these is the same as your Datadog **Application Key** or **API Key**.

</details>

---

## 🚀 Setup Steps

### Step 1 — Fork this repo

Click **Fork** in the top-right corner of this page to get your own copy.

---

### Step 2 — Inject your RUM credentials

Go to `js/dd-config.js` and update the values accordingly

---

### Step 3 — Update credentials _before_ renaming

> ⚠️ **Important:** Complete Step 2 before renaming the repository. Updating credentials first avoids token mismatches on your live site.

---

### Step 4 — Rename the repository

In your repo **Settings**, rename it to:

```
<yourGitHubUsername>.github.io
```

---

### Step 5 — Enable GitHub Pages

Follow GitHub's official guide:

👉 https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site

Once live, `yourGitHubUsername.github.io` is your RUM testing ground — visit it to start capturing real user sessions! 🏴‍☠️

---

## ⚙️ Central Datadog config

The RUM **application ID**, **client token**, **site** and release **version** live in one file: [`js/dd-config.js`](js/dd-config.js). Every page loads it before the Datadog SDK and reads `DD_CONFIG.*` in its `DD_RUM.init` / `DD_LOGS.init` call.

- **New app / token / site:** edit `js/dd-config.js` only. If you change `site`, also update the region in the SDK `<script>` URL (`…/us1/v7/…`).
- **Releasing:** bump `version` in `js/dd-config.js` (currently `2.2.0`).
- **Adding a page:** add `<script src="/js/dd-config.js"></script>` before the SDK script and use `DD_CONFIG.*` instead of literals.
- `service` and `env` stay per-page on purpose (landing page, tools and rumresources report as different services).
- A RUM client token is public by design, so keeping it in a committed JS file is expected.

---

## 🔒 Privacy — Session Replay & the Tools

All pages initialise RUM with `defaultPrivacyLevel: 'mask'` and `enablePrivacyForActionName: true`, so text, inputs and click-target names are masked in Session Replay.

The two tools (`/tools/har-analyzer/`, `/tools/rum-event-parser/`) handle uploaded/pasted data, so they go further.

**Telemetry (what could reach Datadog)**

- Result containers use `data-dd-privacy="hidden"`, so parsed content is not recorded at all.
- Files are parsed locally in the browser; nothing is uploaded. Custom RUM actions send counts/sizes only (never filenames or contents); event types are reported only if they are on a fixed allowlist.
- JSON parse errors report only a line/column, never the browser's message (which quotes part of the input).
- A RUM `beforeSend` hook redacts error message/stack/causes/fingerprint and click-target names. The Logs SDK is not loaded on the tools.

**In-page redaction (what you see, copy and export)** — `js/redact.js`

- **Redact PII in this view** is on by default. It masks emails, IPv4/IPv6 addresses, JWTs and bearer tokens, card numbers (Luhn-checked), SSNs, phone numbers, `Authorization`/`Cookie`/`X-Forwarded-For`-style headers, `dd-api-key` (first 4 characters only), `usr.*` and other personal fields by key name, geo city/coordinates, and URL query-string values and fragments.
- Masked values become stable tags such as `[email:3fa91c]`, so two different values stay distinguishable.
- **Copy summary and Export JSON are always redacted**, whatever the toggle says, and omit the original filename.
- Datadog session/view/application IDs, trace IDs, SDK versions and service/env/version are intentionally left visible — they are what the tools exist to show.
- Limits: pattern matching cannot recognise free-text names, street addresses or opaque customer IDs inside arbitrary strings. Review before sharing a screenshot.

If you add a new page or widget that displays user-supplied data, put `data-dd-privacy="hidden"` on its container, escape everything you put in `innerHTML`, and route displayed values through `PIIRedact`.

---

## 🏴 Already Have a GitHub Pages Site?

GitHub only allows **one** `username.github.io` per user account. Here's the workaround:

1. **Create a GitHub Organization** under your personal account
2. **Navigate** to that organization
3. **Repeat Steps 1–5** above inside the organization — it gets its own `orgname.github.io` page

---

<div align="center">

*Yo ho ho and a bottle of RUM data!* 🍾

[![Live Site](https://img.shields.io/badge/Live%20Site-rum.naveengupta.info-632ca6?style=for-the-badge&logo=google-chrome&logoColor=white)](https://rum.naveengupta.info)

</div>
