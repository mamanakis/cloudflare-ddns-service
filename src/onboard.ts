import { Env, InviteRecord, UserRule, AuditEntry } from "./types";
import {
  sha256Hex,
  generateAlphanumeric,
  generateHex,
  timingSafeEqualString,
  validatePasswordComplexity,
} from "./security";

const MAX_PIN_ATTEMPTS = 3;
const AUDIT_TTL_SECONDS = 90 * 86400;
const DEFAULT_INVITE_TTL_SECONDS = 86400;

function jsonResponse(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function hasActiveInvite(kv: KVNamespace): Promise<boolean> {
  try {
    const listResult = await kv.list({ prefix: "invite:", limit: 1 });
    return listResult.keys.length > 0;
  } catch {
    return false;
  }
}

export async function writeAuditLog(kv: KVNamespace, entry: AuditEntry): Promise<void> {
  try {
    const key = `audit:${entry.timestamp}:${generateHex(4)}`;
    await kv.put(key, JSON.stringify(entry), { expirationTtl: AUDIT_TTL_SECONDS });
  } catch {
    // Ignore telemetry write errors
  }
}

export async function handleOnboardSubmit(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
  const country = request.headers.get("CF-IPCountry") || "unknown";
  const userAgent = request.headers.get("User-Agent") || "unknown";

  const isBlocked = await env.KV.get(`blocked_ip:${clientIp}`);
  if (isBlocked !== null) {
    return jsonResponse({ error: "Access denied." }, 403);
  }

  let body: { username?: string; pin?: string; mode?: string; password?: string };
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid request payload." }, 400);
  }

  const username = (body.username || "").trim().toLowerCase();
  const pin = (body.pin || "").trim();
  const mode = body.mode === "password" ? "password" : "token";

  if (!/^[a-z0-9_-]{2,32}$/.test(username) || !/^\d{8}$/.test(pin)) {
    return jsonResponse({ error: "Invalid username or 8-digit PIN." }, 400);
  }

  const inviteKey = `invite:${username}`;
  const userKey = `user:${username}`;

  const [inviteWithMeta, existingUser] = await Promise.all([
    env.KV.getWithMetadata<InviteRecord, { exp?: number }>(inviteKey, "json"),
    env.KV.get<UserRule>(userKey, "json"),
  ]);

  const invite = inviteWithMeta.value;

  if (!invite) {
    ctx.waitUntil(
      writeAuditLog(env.KV, {
        timestamp: new Date().toISOString(),
        event: "unknown_or_expired_invite",
        username,
        ip: clientIp,
        country,
        user_agent: userAgent,
      })
    );
    return jsonResponse({ error: "Invalid or expired username/PIN." }, 403);
  }

  if (existingUser) {
    return jsonResponse({ error: "User already exists. Contact admin to reset." }, 409);
  }

  if (!timingSafeEqualString(invite.pin, pin)) {
    const attempts = (invite.attempts || 0) + 1;

    if (attempts >= MAX_PIN_ATTEMPTS) {
      await env.KV.delete(inviteKey);
      ctx.waitUntil(
        writeAuditLog(env.KV, {
          timestamp: new Date().toISOString(),
          event: "invite_burned_max_attempts",
          username,
          ip: clientIp,
          country,
          user_agent: userAgent,
        })
      );
      return jsonResponse(
        { error: "Too many failed attempts. This invite has been locked and deleted." },
        403
      );
    }

    const remainingTtl = inviteWithMeta.metadata?.exp
      ? Math.max(60, Math.floor((inviteWithMeta.metadata.exp - Date.now()) / 1000))
      : DEFAULT_INVITE_TTL_SECONDS;

    invite.attempts = attempts;
    await env.KV.put(inviteKey, JSON.stringify(invite), {
      expirationTtl: remainingTtl,
      metadata: inviteWithMeta.metadata,
    });

    const remaining = MAX_PIN_ATTEMPTS - attempts;
    return jsonResponse(
      { error: `Invalid username or PIN. ${remaining} attempt(s) remaining.` },
      403
    );
  }

  let finalSecret = "";
  if (mode === "token") {
    finalSecret = generateAlphanumeric(16);
  } else {
    const pw = body.password || "";
    const pwError = validatePasswordComplexity(pw);
    if (pwError) return jsonResponse({ error: pwError }, 400);
    finalSecret = pw;
  }

  const salt = generateHex(8);
  const secret_hash = await sha256Hex(`${salt}${finalSecret}`);

  const newUser: UserRule = {
    id: username,
    salt,
    secret_hash,
    allowed_exact: [],
    allowed_suffixes: [],
  };

  await Promise.all([
    env.KV.put(userKey, JSON.stringify(newUser, null, 2)),
    env.KV.delete(inviteKey),
  ]);

  ctx.waitUntil(
    writeAuditLog(env.KV, {
      timestamp: new Date().toISOString(),
      event: "onboard_success",
      username,
      ip: clientIp,
      country,
      user_agent: userAgent,
    })
  );

  return jsonResponse({ username, secret: finalSecret, mode }, 200);
}