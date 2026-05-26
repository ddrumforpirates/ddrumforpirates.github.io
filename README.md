<div align="center">

<img src="https://rum.naveengupta.info/images/datadogrum.png" width="120" alt="Datadog RUM Pirate logo" />

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

| Credential | Where to find it |
|---|---|
| 🔑 **Client Token** | RUM Application page |
| 🪪 **Application ID** | RUM Application page |

> ⚠️ Neither of these is the same as your Datadog **Application Key** or **API Key**.

</details>

---

## 🚀 Setup Steps

### Step 1 — Fork this repo

Click **Fork** in the top-right corner of this page to get your own copy.

---

### Step 2 — Inject your RUM credentials

Open each of the files below and replace the placeholder client token and application ID with the values saved in Prerequisite Step 3:

| File | |
|---|---|
| `/index.html` | 📄 Main page |
| `/games/tic.html` | 🎮 Tic-tac-toe game |
| `/test/index.html` | 🧪 Test page |
| `/rumresources/index.html` | 📊 RUM Resources page |

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
