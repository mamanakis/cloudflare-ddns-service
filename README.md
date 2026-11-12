# cloudflare-ddns-service

A zero-dependency, multi-tenant, dual-stack (`A` / `AAAA`) DynDNS2 Cloudflare Worker package with self-service KV PIN onboarding and automatic stale DNS record pruning.

Designed for routers (**TP-Link Omada**, **MikroTik RouterOS**, **Ubiquiti UniFi**, **OPNsense/pfSense**, and standard `ddclient`/`inadyn` daemons) that only have built in support for DynDNS like DDNS to update IPv4 and IPv6 records across multiple Cloudflare zones without using Cloudflare API tokens.

---

## Key Features

- **Dual-Stack State Reconciliation & Pruning:** Concurrently creates, updates, or deletes `A` and `AAAA` records. When a router explicitly reports an empty IPv6 or IPv4 parameter (e.g., ISP prefix drop), the stale record is automatically pruned from Cloudflare DNS.
- **Safe Passive Auto-Detection:** If a client calls the endpoint without IP query parameters (`?hostname=node.example.com`), the Worker detects the connecting IP via `CF-Connecting-IP` and updates the corresponding `A` or `AAAA` record *without* pruning the opposite address family.
- **$O(1)$ Keyed Authentication & Constant-Time Crypto:** Stores per-user salted SHA-256 credentials under isolated `user:<username>` KV keys. Uses `crypto.subtle.timingSafeEqual` and dummy hash burning to prevent timing side-channels and username enumeration.
- **Dark Self-Service Onboarding Portal:** Exposes an optional onboarding web UI on a dedicated hostname (`ONBOARD_HOST`). The portal returns an empty `404` unless an active `invite:<username>` key exists in KV.
- **Multi-Zone Routing:** Maps multiple root domains to their respective Cloudflare Zone IDs via a single `zone:map` KV entry, falling back to `env.CF_ZONE_ID`.
- **Non-Blocking Telemetry:** Writes auto-expiring (`audit:<timestamp>:<id>`) security events via `ctx.waitUntil()` with zero impact on response latency.

---

## Installation & GitOps Wrapper Usage

Install the package in your Cloudflare Worker project or GitOps monorepo:

```bash
npm install cloudflare-ddns-service