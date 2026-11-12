import { UserRule, ServiceConfig, RateLimitState } from "./types";

const DUMMY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqualString(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const bufA = enc.encode(a);
  const bufB = enc.encode(b);
  if (bufA.byteLength !== bufB.byteLength) return false;
  return crypto.subtle.timingSafeEqual(bufA, bufB);
}

export function generateAlphanumeric(len: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const maxValidByte = 248;
  let result = "";
  const buf = new Uint8Array(len * 2);

  while (result.length < len) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && result.length < len; i++) {
      if (buf[i] < maxValidByte) {
        result += chars[buf[i] % chars.length];
      }
    }
  }
  return result;
}

export function generateHex(byteLen: number): string {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function validatePasswordComplexity(pw: string): string | null {
  if (pw.length < 12 || pw.length > 64) {
    return "Password must be between 12 and 64 characters.";
  }
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) {
    return "Password must include uppercase, lowercase, and at least one number.";
  }
  if (/[:@\s]/.test(pw)) {
    return "Password cannot contain spaces, colons (:), or @ symbols (they break legacy routers).";
  }
  return null;
}

export function extractCredentials(
  request: Request,
  url: URL
): { username: string; secret: string } | null {
  const authHeader = request.headers.get("Authorization") || "";

  if (authHeader.startsWith("Basic ")) {
    try {
      const decoded = atob(authHeader.slice(6).trim());
      const colonIdx = decoded.indexOf(":");
      if (colonIdx === -1) return null;
      return {
        username: decoded.slice(0, colonIdx).trim().toLowerCase(),
        secret: decoded.slice(colonIdx + 1),
      };
    } catch {
      return null;
    }
  }

  if (authHeader.startsWith("Bearer ")) {
    const rawToken = authHeader.slice(7).trim();
    const colonIdx = rawToken.indexOf(":");
    if (colonIdx !== -1) {
      return {
        username: rawToken.slice(0, colonIdx).trim().toLowerCase(),
        secret: rawToken.slice(colonIdx + 1),
      };
    }
    const queryUser = url.searchParams.get("user") || url.searchParams.get("username");
    if (queryUser && rawToken) {
      return { username: queryUser.trim().toLowerCase(), secret: rawToken };
    }
  }

  const queryUser = url.searchParams.get("user") || url.searchParams.get("username");
  const queryPass =
    url.searchParams.get("pass") ||
    url.searchParams.get("password") ||
    url.searchParams.get("token");

  if (queryUser && queryPass) {
    return { username: queryUser.trim().toLowerCase(), secret: queryPass };
  }

  return null;
}

export async function authenticateUserByKey(
  creds: { username: string; secret: string },
  kv: KVNamespace
): Promise<UserRule | null> {
  const user = await kv.get<UserRule>(`user:${creds.username}`, "json");

  if (!user) {
    const dummyComputed = await sha256Hex(`dummysalt${creds.secret}`);
    timingSafeEqualString(dummyComputed, DUMMY_HASH);
    return null;
  }

  const incomingHash = await sha256Hex(`${user.salt}${creds.secret}`);
  if (timingSafeEqualString(incomingHash, user.secret_hash.toLowerCase())) {
    return user;
  }

  return null;
}

export async function isIpBlocked(kv: KVNamespace, ip: string): Promise<boolean> {
  if (!ip || ip === "unknown") return false;
  const blocked = await kv.get(`blocked_ip:${ip}`);
  return blocked !== null;
}

export async function sendAlertWebhook(
  webhookUrl: string | undefined,
  payload: Record<string, unknown>
): Promise<void> {
  if (!webhookUrl || webhookUrl.trim() === "") return;
  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    // Non-blocking alert failure
  }
}

export async function recordAuthFailure(
  kv: KVNamespace,
  ip: string,
  reason: string,
  config?: ServiceConfig | null
): Promise<boolean> {
  if (!ip || ip === "unknown") return false;
  const maxFails = config?.rate_limit_max_fails ?? 3;
  const windowSec = config?.rate_limit_window_sec ?? 300;
  const baseBlockSec = config?.rate_limit_block_sec ?? 3600;
  const penaltyType = config?.penalty_type ?? "logarithmic";
  const maxPenaltySec = config?.max_penalty_sec ?? 3600000;

  const stateKey = `ratelimit:${ip}`;
  const now = Date.now();
  const current = await kv.get<RateLimitState>(stateKey, "json");

  let fails = 1;
  let offenses = current?.offenses ?? 0;
  let firstFailMs = now;

  if (current && now - current.first_fail_ms <= windowSec * 1000) {
    fails = current.fails + 1;
    firstFailMs = current.first_fail_ms;
  }

  if (fails >= maxFails) {
    offenses += 1;
    const multiplier =
      penaltyType === "logarithmic" ? Math.pow(2, Math.max(0, offenses - 1)) : 1;
    const blockSec = Math.max(60, Math.min(maxPenaltySec, Math.floor(baseBlockSec * multiplier)));

    await Promise.all([
      kv.put(`blocked_ip:${ip}`, JSON.stringify({ reason, blocked_at: new Date(now).toISOString(), blockSec }), {
        expirationTtl: blockSec,
      }),
      kv.put(stateKey, JSON.stringify({ fails: 0, offenses, first_fail_ms: now } satisfies RateLimitState), {
        expirationTtl: Math.max(windowSec, blockSec * 2),
      }),
      sendAlertWebhook(config?.alert_webhook_url, {
        event: "ip_rate_limited",
        ip,
        reason,
        offenses,
        block_seconds: blockSec,
      }),
    ]);
    return true;
  }

  await kv.put(
    stateKey,
    JSON.stringify({ fails, offenses, first_fail_ms: firstFailMs } satisfies RateLimitState),
    { expirationTtl: Math.max(60, windowSec * 2) }
  );
  return false;
}