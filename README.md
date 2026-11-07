# Omada to Cloudflare DDNS Updater

A secure, modern Cloudflare Worker script designed to handle Dynamic DNS (DDNS) updates directly from TP-Link Omada SDN controllers. It automatically detects IPv4/IPv6 formats, handles HTTP Basic Authentication, and updates Cloudflare DNS records using secure environment variables. It also returns standard DynDNS-style success codes (`good <ip>`) to ensure the Omada controller UI registers the update correctly.

## Features

* **Omada Native Compatibility:** Returns specific plain-text responses so your Omada controller correctly marks the DDNS status as "Successful."
* **IPv4 & IPv6 Support:** Automatically detects the IP version connecting to the worker and updates `A` or `AAAA` records accordingly.
* **Modern & Secure:** Built using Cloudflare Workers ES Modules. Credentials and API tokens are stored securely in Cloudflare Secrets, not hardcoded in the script.
* **Basic Authentication:** Protects your worker endpoint from unauthorized updates.

## Prerequisites

1. A Cloudflare account with your domain's DNS managed by Cloudflare.
2. A Cloudflare API Token with `Zone:DNS:Edit` permissions.
3. Your Cloudflare Zone ID.
4. A TP-Link Omada SDN Controller.

## Setup Instructions

### 1. Retrieve your DNS Record IDs

Before deploying the worker, you need the unique IDs for the DNS records you want to update. Use the following `curl` command in your terminal (replace `YOUR_ZONE_ID` and `YOUR_API_TOKEN`):

```bash
curl -X GET "https://api.cloudflare.com/client/v4/zones/YOUR_ZONE_ID/dns_records" \
     -H "Authorization: Bearer YOUR_API_TOKEN" \
     -H "Content-Type: application/json"
```
Find the `id` for your target `A` and/or `AAAA` records in the JSON response.

### 2. Create the Cloudflare Worker

1. Log into the Cloudflare Dashboard and navigate to **Workers & Pages**.
2. Click **Create Application** -> **Create Worker**.
3. Name your worker (e.g., `omada-ddns`) and deploy it.
4. Click **Edit Code**.
5. Paste the provided `worker.js` script into the editor.
6. Update the `DDNS_RECORDS_IPV4` and `DDNS_RECORDS_IPV6` mapping objects at the top of the script with your domain names and the Record IDs you fetched in step 1.
7. Click **Deploy**.

### 3. Configure Environment Variables (Secrets)

In your Cloudflare Dashboard, go to the settings for your new Worker:
Navigate to **Settings** -> **Variables** -> **Environment Variables**. Add the following as **encrypted** variables:

| Variable Name | Description |
| :--- | :--- |
| `API_TOKEN` | Your Cloudflare API Token (Needs `Zone:DNS:Edit` permissions). |
| `ZONE_ID` | The Zone ID for your domain (found on the domain's overview page). |
| `USERNAME` | The username you will configure in the Omada controller. |
| `PASSWORD` | The password you will configure in the Omada controller. |

### 4. Configure TP-Link Omada Controller

1. Log into your Omada Controller and go to **Settings** -> **Services** -> **Dynamic DNS**.
2. Click **Create New DDNS**.
3. Fill in the following details:
   * **Service Provider:** Custom
   * **Update URL:** `https://your-worker-name.your-subdomain.workers.dev/?hostname=[DOMAIN]`
   * **Domain Name:** The domain you are updating (e.g., `wan.yourdomain.com`)
   * **Username:** The `USERNAME` you set in your Cloudflare Worker variables.
   * **Password:** The `PASSWORD` you set in your Cloudflare Worker variables.
4. Save and enable the DDNS profile.

## Troubleshooting

* **Omada says "Failed":** Ensure you are returning `good <ip>` on success. Double-check your Update URL to ensure `?hostname=[DOMAIN]` is appended.
* **Worker returns 401 Unauthorized:** Verify the Username and Password in Omada exactly match the Environment Variables in Cloudflare.
* **Worker returns 500 or API errors:** Check your `API_TOKEN` permissions and ensure your `ZONE_ID` and Record IDs are correct.
