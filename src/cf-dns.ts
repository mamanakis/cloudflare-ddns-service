import { UserRule, ServiceConfig, CloudflareDnsRecord, CloudflareListResponse } from "./types";

export function isHostAllowed(
  hostname: string,
  user: UserRule,
  serviceConfig?: ServiceConfig | null
): boolean {
  const target = hostname.toLowerCase();
  const labels = target.split(".");

  if (labels.some((label) => label.startsWith("_"))) return false;

  // Enforce global BLOCK_LIST from config.json if present
  if (serviceConfig?.BLOCK_LIST?.length) {
    const subPrefix = labels[0];
    if (serviceConfig.BLOCK_LIST.some((blocked) => subPrefix.includes(blocked.toLowerCase()))) {
      return false;
    }
  }

  if (user.allowed_exact.some((exact) => target === exact.toLowerCase())) {
    return true;
  }

  return user.allowed_suffixes.some((suffix) => {
    const norm = suffix.toLowerCase();
    const bounded = norm.startsWith(".") ? norm : `.${norm}`;
    return target.endsWith(bounded) && target.length > bounded.length;
  });
}

export function isValidPublicIp(ip: string, expectedType: "A" | "AAAA"): boolean {
  if (expectedType === "A") {
    const ipv4Regex =
      /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
    if (!ipv4Regex.test(ip)) return false;
    const p = ip.split(".").map(Number);
    if (
      p[0] === 10 ||
      p[0] === 127 ||
      p[0] === 0 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
    ) {
      return false;
    }
    return true;
  }

  if (expectedType === "AAAA") {
    try {
      new URL(`http://[${ip}]`);
    } catch {
      return false;
    }
    const l = ip.toLowerCase();
    if (
      l === "::1" ||
      l === "::" ||
      l.startsWith("fe80:") ||
      l.startsWith("fc") ||
      l.startsWith("fd") ||
      l.startsWith("2001:db8:")
    ) {
      return false;
    }
    return true;
  }

  return false;
}

export async function reconcileDualStackRecords(
  zoneId: string,
  apiToken: string,
  hostname: string,
  ipv4: string | null,
  ipv6: string | null,
  isAutoDetected: boolean
): Promise<{ status: "good" | "nochg"; summary: string }> {
  const baseUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`;
  const headers = {
    Authorization: `Bearer ${apiToken}`,
    "Content-Type": "application/json",
  };

  const lookupRes = await fetch(`${baseUrl}?name=${encodeURIComponent(hostname)}`, { headers });
  if (!lookupRes.ok) throw new Error(`Cloudflare API lookup HTTP ${lookupRes.status}`);

  const lookupData: CloudflareListResponse = await lookupRes.json();
  if (!lookupData.success) throw new Error("Cloudflare API returned success: false");

  const recordA = lookupData.result.find((r) => r.type === "A");
  const recordAAAA = lookupData.result.find((r) => r.type === "AAAA");

  let changed = false;

  async function syncRecord(ip: string | null, type: "A" | "AAAA", existing?: CloudflareDnsRecord) {
    if (ip) {
      const payload = JSON.stringify({ type, name: hostname, content: ip, ttl: 120, proxied: false });
      if (existing) {
        if (existing.content !== ip || existing.proxied !== false) {
          const res = await fetch(`${baseUrl}/${existing.id}`, { method: "PUT", headers, body: payload });
          if (!res.ok) throw new Error(`Failed to update ${type} record`);
          changed = true;
        }
      } else {
        const res = await fetch(baseUrl, { method: "POST", headers, body: payload });
        if (!res.ok) throw new Error(`Failed to create ${type} record`);
        changed = true;
      }
    } else if (existing && !isAutoDetected) {
      const res = await fetch(`${baseUrl}/${existing.id}`, { method: "DELETE", headers });
      if (!res.ok) throw new Error(`Failed to delete stale ${type} record`);
      changed = true;
    }
  }

  await Promise.all([
    syncRecord(ipv4, "A", recordA),
    syncRecord(ipv6, "AAAA", recordAAAA),
  ]);

  const activeIps = [ipv4, ipv6].filter(Boolean).join(" ");
  return {
    status: changed ? "good" : "nochg",
    summary: `${changed ? "good" : "nochg"} ${activeIps}`.trim(),
  };
}