# ☠️ datadogrumforpirates.github.io

> A step-by-step guide to setting up **Real User Monitoring (RUM)** on your GitHub Pages site using Datadog.

---

## 🗺️ Before You Begin — Prerequisites

Complete these steps first to get your Datadog RUM credentials ready.

### 1. Open the RUM Application Creator

Make sure you're logged into your **Datadog Sandbox**, then go to:

👉 https://app.datadoghq.com/rum/application/create

### 2. Create a New RUM Application

- Set **Application type** to `JS Application`
- Give your application a name
- Click **+ Create New RUM Application**

### 3. Save Your Credentials

You'll need both of the following — keep them handy!

| Credential | Where to find it |
|---|---|
| 🔑 **Client Token** | RUM Application settings |
| 🪪 **Application ID** | RUM Application settings |

> ⚠️ **Note:** The Client Token is _not_ the same as your Datadog Application Key or Datadog API Key.

> ⚠️ **Note:** The Application ID is _not_ the same as your Datadog Application Key or Datadog API Key.

---

## 🚀 Setup Steps

### Step 1 — Fork this repo

Click **Fork** in the top-right corner of GitHub to create your own copy.

---

### Step 2 — Inject your RUM credentials

Open each of the files below and replace the placeholder client token and application ID with the values from your RUM application:

- `📄 /index.html`
- `📄 /games/tic.html`
- `📄 /test/index.html`

---

### Step 3 — Update credentials _before_ renaming

> ⚠️ **Important:** Make sure you've completed Step 2 before renaming the repository. Updating credentials first avoids any token mismatches on your live site.

---

### Step 4 — Rename the repository

In your repo **Settings**, rename it to:

```
<yourGitHubUsername>.github.io
```

---

### Step 5 — Enable GitHub Pages

Follow GitHub's official guide to publish your site:

👉 https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site

Once live, `yourGitHubUsername.github.io` becomes your RUM testing ground — visit it to start capturing real user sessions!

---

## 🏴 Already Have a GitHub Pages Site?

GitHub only allows **one** `username.github.io` page per user account. Here's the workaround:

1. **Create a GitHub Organization** under your personal account
2. **Navigate** to that organization
3. **Repeat Steps 1–5** above inside the organization — it gets its own `orgname.github.io` page
