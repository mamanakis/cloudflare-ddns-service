# Omada Cloudflare DDNS

⚠️ **STATUS: ALPHA / WORK IN PROGRESS**  
*This project is currently in active development (Alpha) and has not yet been thoroughly tested in production environments. Features and configurations may change. Use at your own risk.*

---

A highly secure, serverless Dynamic DNS (DDNS) updater designed for TP-Link Omada SDN controllers. It leverages Cloudflare Workers to dynamically update or create DNS records, backed by Cloudflare KV for progressive rate-limiting and dynamic GitOps configuration.

## Features
* **Native Omada Support:** Uses standard HTTP Basic Authentication and Omada's `[DOMAIN]` variables.
* **Serverless Edge:** Runs entirely on Cloudflare Workers (no VPS, no local IdP dependencies).
* **Modular ES Architecture:** Cleanly separated logic (`config.js`, `security.js`, `validation.js`, `cloudflare.js`) for easy testing and expansion.
* **Idempotent Updates:** Compares incoming IP to existing Cloudflare records and skips unnecessary API writes to reduce log noise.
* **GitOps Configuration:** Update allowlists, blocklists, and limits via `config.json` without redeploying the Worker.
* **Progressive Rate Limiting:** Built-in protection against brute-force attacks with progressive timeout penalties (e.g., 1hr, 10hr, 100hr blocks) stored in Cloudflare KV.
* **Dynamic Record Creation:** Can optionally create new DNS records on the fly if they don't already exist.
* **Granular Security:** Restrict DDNS updates to specific domains, specific prefixes (including wildcards), and block profanity.

## Repository Structure
This repository uses a GitOps workflow. The GitHub Actions automatically separate code deployments from configuration updates.

```text
omada-cloudflare-ddns/
├── .github/
│   └── workflows/
│       ├── deploy-worker.yml   # Triggers on changes to src/ or wrangler.toml
│       └── update-config.yml   # Triggers on changes to config.json
├── src/
│   ├── index.js                # Main Worker entry point
│   ├── config.js               # KV configuration fetcher
│   ├── security.js             # Rate limiting and HTTP Basic Auth
│   ├── validation.js           # Hostname constraints and regex
│   └── cloudflare.js           # Cloudflare API operations & Webhooks
├── .gitignore
├── config.json                 # Dynamic allowlists/blocklists for KV
├── README.md
└── wrangler.toml               # Infrastructure bindings
```

## Prerequisites
1. A Cloudflare Account with an active domain zone.
2. A TP-Link Omada SDN Controller.
3. A GitHub repository to host this code and run Actions.

---

## Setup Instructions

### 1. Cloudflare Preparation
You need to generate two API tokens in your Cloudflare dashboard (My Profile > API Tokens):
1. **GitHub Actions Deploy Token (`CF_API_TOKEN`):** 
   * Permissions: `Account` -> `Workers Scripts` -> `Edit`
2. **Worker Execution Token (`API_TOKEN`):** 
   * Permissions: `Zone` -> `DNS` -> `Edit` 
   * Resources: Include your specific Zone(s).

Next, create a Cloudflare KV namespace to hold your rate limits and configuration:
```bash
npx wrangler kv:namespace create "RATE_LIMIT_KV"
```
*(Note the generated ID)*

### 2. GitHub Secrets Configuration
In your GitHub repository, navigate to **Settings > Secrets and variables > Actions** and add the following repository secrets:

* `CF_API_TOKEN`: Your Cloudflare deploy token.
* `CF_ACCOUNT_ID`: Your Cloudflare Account ID.
* `CF_KV_NAMESPACE_ID`: The ID of the KV namespace you just created.
* `API_TOKEN`: Your Cloudflare DNS Edit token.
* `ZONE_ID`: The Zone ID for your domain.
* `USERNAME`: A custom username for your router to use (e.g., `ddns-updater`).
* `PASSWORD`: A secure custom password for your router.

### 3. Repository Configuration
Update the `wrangler.toml` file in this repository with your KV Namespace ID. Note that `main` must point to the `src/index.js` file:

```toml
name = "omada-cloudflare-ddns"
main = "src/index.js"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "RATE_LIMIT_KV"
id = "YOUR_KV_NAMESPACE_ID_HERE"
```

Update the `config.json` file with your allowed domains and prefixes. When you push this to the `main` branch, GitHub Actions will automatically deploy the worker and push the configuration to Cloudflare KV.

### 4. Omada Controller Configuration
Once the GitHub Action completes successfully, configure your Omada router to trigger the updates. 

In the Omada SDN Controller, go to **Settings > Services > Dynamic DNS** and create a new entry:

* **Service Provider:** Custom
* **Interface:** Your active WAN port
* **Username:** The `USERNAME` you set in GitHub Secrets
* **Password:** The `PASSWORD` you set in GitHub Secrets
* **Domain Name:** The exact subdomain to update (e.g., `router.example.com`)
* **Update URL:** Use the following format, replacing `<YOUR_WORKER_SUBDOMAIN>` with your actual Workers.dev URL:
```text
https://[USERNAME]:[PASSWORD]@omada-cloudflare-ddns.<YOUR_WORKER_SUBDOMAIN>.workers.dev/?hostname=[DOMAIN]
```

Save the profile. Omada will connect to your Worker, securely pass the credentials, and update your Cloudflare DNS record.
