# cloudflare-ddns-service

A zero-dependency, multi-tenant, dual-stack (`A` / `AAAA`) DynDNS2 Cloudflare Worker service with stealth KV PIN onboarding, multi-zone routing, logarithmic brute-force protection, and automatic stale DNS record pruning[cite: 1].

Built for locked-down router appliances that lack native Cloudflare API integration or custom scripting, as well as scriptable routers where storing a Cloudflare API token on the device is undesirable[cite: 1].

---

## Supported Hardware & Client Ecosystems

### 1. Locked-Down Appliances (No Native Cloudflare API or Scripting)
These devices only support legacy HTTP GET DynDNS2 / Custom URL providers in their web UI and **cannot** call Cloudflare's JSON REST API (`PATCH`/`POST` with Bearer headers and Zone/Record ID lookups):
- **TP-Link Omada SDN Gateways** (ER605, ER7206, ER8411 via Omada Controller or standalone Custom DDNS)
- **Consumer & Prosumer Mesh Routers** (ASUSWRT standard UI, Netgear Orbi/Nighthawk, TP-Link Deco/Archer, Linksys Velop, Synology SRM)
- **ISP Residential Gateways & 5G CPEs** (AT&T BGW, Verizon/Frontier routers, Zyxel, Cudy, Teltonika RUTX standard DDNS UI)
- **Hardware Firewalls & Legacy Appliances** (SonicWall, WatchGuard, Cisco Meraki / RV Series, DrayTek Vigor, FortiGate GUI DDNS)
- **NAS, NVR & IoT Appliances** (Synology DSM, QNAP QTS, TrueNAS, Hikvision/Dahua NVRs)

### 2. Native / Scriptable Routers (Zero-Trust Token Offloading)
While **newer Ubiquiti UniFi OS** releases include native Cloudflare support, **MikroTik RouterOS** can run custom `/tool fetch` scripts, and **OPNsense / pfSense / OpenWrt** have `ddclient` or `inadyn` packages, using this Worker still provides major security and operational advantages:
- **No Cloudflare API Tokens on Edge Hardware:** Even a "scoped" Cloudflare API token can read/modify every DNS record inside a zone. With this Worker, a compromised branch router can only update its single assigned hostname (`gw-branch1.example.com`)[cite: 1].
- **Automatic Stale IPv6 Pruning:** Native `ddclient` and UniFi `inadyn` implementations update `A` and `AAAA` records independently, leaving dead `AAAA` records in DNS if an ISP drops IPv6 prefix delegation. This Worker automatically deletes the stale record[cite: 1].
- **Zero-Math MikroTik & Cron Updates:** Instead of maintaining multi-step JSON parsing scripts in RouterOS to look up Zone IDs and Record IDs, MikroTik only needs a single one-line `/tool fetch` GET request.

---

## Key Features

- **Dual-Stack State Reconciliation & Pruning:** Concurrently creates, updates, or deletes `A` and `AAAA` records. When a client explicitly sends an empty `ipv6=` or `ip=` parameter (e.g., ISP prefix drop), the stale record is automatically removed from Cloudflare DNS[cite: 1].
- **Safe Passive Auto-Detection:** Calling `/nic/update?hostname=node.example.com` without IP parameters detects the client IP via `CF-Connecting-IP` and updates the corresponding `A` or `AAAA` record *without* pruning the opposite address family[cite: 1].
- **Stealth Self-Service PIN Onboarding Portal:** Serves a credential registration UI on `onboard-ddns.<domain>` **only** while an active `invite:<username>` key exists in KV. When no invites exist, the portal returns an empty `404`[cite: 1].
- **Constant-Time Keyed Auth & Logarithmic Rate-Limiting:** Stores per-user salted SHA-256 credentials under isolated `user:<username>` KV keys, uses `crypto.subtle.timingSafeEqual` with dummy hash burning to prevent timing enumeration, and locks out abusive IPs with configurable fixed or logarithmic backoff[cite: 1].
- **Zero-Hardcoding GitOps Deployment:** Keep forked/cloned repositories 100% free of personal domain names by configuring a single `DDNS_ZONE_MAP` GitHub Repository Variable[cite: 1].

---

## Quick Start (Forking / Cloning This Repository)

You do **not** need to edit any tracked source files (`wrangler.jsonc`, `default-config.json`, or `.github/workflows/ci.yml`) to deploy this Worker to your own domains[cite: 1].

### 1. Configure GitHub Secrets & Repository Variables

In your GitHub repository, navigate to **Settings → Secrets and variables → Actions**:

#### Secrets Tab (`Repository secrets`)
| Secret Name | Required | Description |
| :--- | :---: | :--- |
| `CF_ACCOUNT_ID` | **Yes** | Your 32-character Cloudflare Account ID[cite: 1]. |
| `CF_API_TOKEN_DEPLOY` | **Yes** | Cloudflare API token used by GitHub Actions / Wrangler to deploy the Worker, manage KV, and bind Custom Domains (`Workers Scripts:Edit`, `Workers KV Storage:Edit`, `Zone DNS:Edit`, `Workers Routes:Edit`)[cite: 1]. |
| `CF_API_TOKEN` | **Yes** | Least-privilege runtime API token injected into the Worker as a secret (`Zone → DNS → Edit` scoped to your DDNS zones)[cite: 1]. |
| `NPM_TOKEN` | Optional | NPM automation token (only needed if publishing releases via `publish-npm.yml`)[cite: 1]. |

#### Variables Tab (`Repository variables`)
| Variable Name | Example Value | Description |
| :--- | :--- | :--- |
| `DDNS_ZONE_MAP` | `{"example.net":"0000...0001","example.com":"0000...0002"}` | JSON object mapping each root domain to its 32-character Cloudflare Zone ID. **The first key in this map is used as the primary domain for CI live smoke tests**[cite: 1]. |

When pushed to `main`, `.github/workflows/ci.yml` automatically:
1. Runs TypeScript typechecking and the `workerd` integration suite (`npm test`).
2. Generates `wrangler.deploy.jsonc` with custom domain routes for `ddns.<domain>` and `onboard-ddns.<domain>` across every domain in `DDNS_ZONE_MAP`.
3. Auto-provisions the `<worker-name>-kv` namespace, syncs `CF_API_TOKEN`, and seeds `config:settings` and `zone:map` into KV.
4. Uploads a preview Worker version and executes 5 live edge `curl` smoke tests (auth, constant-time rejection, `nohost` isolation, RFC 1918 bogon rejection, and PIN onboarding lifecycle)[cite: 1].

---

## Local Development & Testing

### Prerequisites
- **Node.js** `>= 20` (Node 24 recommended)
- **jq** and **curl** (for the `ddns-admin.sh` CLI helper)

### Install & Run Tests
```bash
npm ci
npm run typecheck
npm test
npm run build
```

All unit and integration tests in `test/ddns.spec.ts` run inside the real Cloudflare `workerd` runtime via `@cloudflare/vitest-plugin` using RFC 2606 (`example.com`), RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and RFC 3849 (`2001:db8::/32`) test addresses.

### Local Configuration (`config.json`)
To manage your deployment from your local terminal without dirtying `git status`:
```bash
cp default-config.json config.json
```

Edit `config.json` (which is gitignored) with your real `zone_map` and push it to KV:
```bash
./scripts/ddns-admin.sh seed-config config.json
```

---

## Configuration Reference (`default-config.json` / `config.json`)

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `zone_map` | `{"example.com": "..."}` | Maps each permitted root domain (no leading dot) to its 32-char Cloudflare Zone ID. |
| `block_list` | `["admin","root","test","hack","onboard-ddns","ddns"]` | Forbidden leftmost subdomain labels that can never be created or updated via DDNS. |
| `allow_creation` | `true` | When `true`, creates missing `A`/`AAAA` records automatically; when `false`, only updates existing records. |
| `default_ttl` | `60` | DNS TTL in seconds (`60` is Cloudflare's minimum non-proxied TTL; `1` = Automatic). |
| `default_proxied` | `false` | Whether DDNS records enable Cloudflare proxy (orange cloud). Keep `false` for routers/VPNs. |
| `allow_ipv6_auto_clear` | `true` | Automatically deletes stale `AAAA` records when a client sends an explicit empty `ipv6=` parameter. |
| `rate_limit_max_fails` | `3` | Failed auth attempts allowed from a single IP within `rate_limit_window_sec` before lockout. |
| `rate_limit_window_sec` | `300` | Sliding window (seconds) for counting failed authentication attempts. |
| `rate_limit_block_sec` | `3600` | Base lockout duration (seconds) when an IP exceeds `rate_limit_max_fails`. |
| `penalty_type` | `"logarithmic"` | `"fixed"` (always `rate_limit_block_sec`) or `"logarithmic"` (doubles on repeat lockouts up to `max_penalty_sec`). |
| `max_penalty_sec` | `3600000` | Maximum lockout ceiling in seconds (~41.6 days). |
| `max_zone_records` | `150` | Maximum total DNS records allowed in a zone before refusing new record creation (`0` = unlimited). |
| `alert_webhook_url` | `""` | Optional webhook URL (`POST` JSON) triggered on IP lockouts or security events[cite: 1]. |

---

## Managing Users & Onboarding (`scripts/ddns-admin.sh`)

```bash
# 1. Create a 24-hour 8-digit PIN invite (wakes up https://onboard-ddns.<domain>/)
./scripts/ddns-admin.sh invite home-router 24

# 2. Authorize an exact FQDN or wildcard suffix for the user
./scripts/ddns-admin.sh allow-exact home-router gw.example.com
./scripts/ddns-admin.sh allow-suffix home-router .vpn.example.com

# 3. Inspect users, active invites, or recent audit logs
./scripts/ddns-admin.sh show-user home-router
./scripts/ddns-admin.sh list-users
./scripts/ddns-admin.sh list-invites
./scripts/ddns-admin.sh audit 20

# 4. Revoke a hostname or suffix
./scripts/ddns-admin.sh revoke-host home-router gw.example.com
```

---

## Router & Client Update URL Examples

- **Dual-Stack Explicit (TP-Link Omada Custom DDNS / MikroTik `/tool fetch`):**
  ```text
  https://<username>:<secret>@[ddns.example.com/nic/update?hostname=gw.example.com&ip=](https://ddns.example.com/nic/update?hostname=gw.example.com&ip=)<ipv4>&ipv6=<ipv6>
  ```
- **Standard DynDNS2 Comma-Separated (`ddclient` / `inadyn` / UniFi):**
  ```text
  https://<username>:<secret>@[ddns.example.com/nic/update?hostname=gw.example.com&myip=](https://ddns.example.com/nic/update?hostname=gw.example.com&myip=)<ipv4>,<ipv6>
  ```
- **Passive Auto-Detect (Single Family via `CF-Connecting-IP`):**
  ```text
  https://<username>:<secret>@[ddns.example.com/nic/update?hostname=gw.example.com](https://ddns.example.com/nic/update?hostname=gw.example.com)
  ```

---

## Importing as an NPM Package

You can also import `cloudflare-ddns-service` into an existing Cloudflare Worker or GitOps monorepo:

```typescript
import { ddnsHandler } from "cloudflare-ddns-service";

export default {
  fetch: ddnsHandler,
};
```

## License

MIT