export * from "./types";
export * from "./cf-dns";
export * from "./security";
export * from "./onboard";

import { Env, ServiceConfig } from "./types";
import { ONBOARD_HTML } from "./onboard-html";
import { hasActiveInvite, handleOnboardSubmit } from "./onboard";
import {
  extractCredentials,
  authenticateUserByKey,
  isIpBlocked,
  recordAuthFailure,
} from "./security";
import { isHostAllowed, isValidPublicIp, reconcileDualStackRecords } from "./cf-dns";

function textResponse(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function isOnboardRequest(request: Request, url: URL, env: Env): boolean {
  const host = (request.headers.get("X-Onboard-Host") || url.hostname).toLowerCase();
  if (env.ONBOARD_HOST && host === env.ONBOARD_HOST.toLowerCase()) {
    return true;
  }
  const prefix = (env.ONBOARD_PREFIX || "onboard-ddns.").toLowerCase();
  return host.startsWith(prefix);
}

async function resolveZoneAndConfig(
  hostname: string,
  env: Env,
  preloadedConfig?: ServiceConfig | null
): Promise<{ zoneId: string | null; serviceConfig: ServiceConfig | null }> {
  const [zoneMap, serviceConfig] = await Promise.all([
    env.KV.get<Record<string, string>>("zone:map", "json"),
    preloadedConfig !== undefined
      ? Promise.resolve(preloadedConfig)
      : env.KV.get<ServiceConfig>("config:settings", "json"),
  ]);

  for (const [domain, id] of Object.entries(zoneMap || {})) {
    const cleanDomain = domain.toLowerCase().replace(/^\./, "");
    if (hostname === cleanDomain || hostname.endsWith(`.${cleanDomain}`)) {
      return { zoneId: id, serviceConfig };
    }
  }

  return { zoneId: env.CF_ZONE_ID || null, serviceConfig };
}

function parseDualStackIps(
  request: Request,
  url: URL
): { ipv4: string | null; ipv6: string | null; isAutoDetected: boolean; hasInvalidIp: boolean } {
  const paramIp = url.searchParams.get("ip");
  const paramIpv6 = url.searchParams.get("ipv6");
  const paramMyIp = url.searchParams.get("myip");

  let ipv4: string | null = null;
  let ipv6: string | null = null;
  let hasInvalidIp = false;

  if (paramIp !== null || paramIpv6 !== null) {
    if (paramIp && paramIp.trim() !== "") {
      const candidate4 = paramIp.trim();
      if (isValidPublicIp(candidate4, "A")) ipv4 = candidate4;
      else hasInvalidIp = true;
    }
    if (paramIpv6 && paramIpv6.trim() !== "") {
      const candidate6 = paramIpv6.trim();
      if (isValidPublicIp(candidate6, "AAAA")) ipv6 = candidate6;
      else hasInvalidIp = true;
    }
    return { ipv4, ipv6, isAutoDetected: false, hasInvalidIp };
  }

  if (paramMyIp !== null && paramMyIp.trim() !== "") {
    const parts = paramMyIp.split(",").map((s) => s.trim()).filter(Boolean);
    for (const part of parts) {
      if (isValidPublicIp(part, "A")) ipv4 = part;
      else if (isValidPublicIp(part, "AAAA")) ipv6 = part;
      else hasInvalidIp = true;
    }
    return { ipv4, ipv6, isAutoDetected: false, hasInvalidIp };
  }

  const cfIp = (request.headers.get("CF-Connecting-IP") || "").trim();
  if (isValidPublicIp(cfIp, "A")) {
    ipv4 = cfIp;
  } else if (isValidPublicIp(cfIp, "AAAA")) {
    ipv6 = cfIp;
  } else {
    hasInvalidIp = true;
  }

  return { ipv4, ipv6, isAutoDetected: true, hasInvalidIp };
}

export async function ddnsHandler(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(request.url);

  // 1. Domain-Agnostic Onboarding Subdomain (matches onboard-ddns.*)
  if (isOnboardRequest(request, url, env)) {
    if (!(await hasActiveInvite(env.KV))) {
      return new Response(null, { status: 404 });
    }

    if (url.pathname === "/" && request.method === "GET") {
      return new Response(ONBOARD_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    if ((url.pathname === "/" || url.pathname === "/onboard") && request.method === "POST") {
      return handleOnboardSubmit(request, env, ctx);
    }

    return new Response(null, { status: 404 });
  }

  // 2. DDNS Update Endpoint
  if (url.pathname === "/nic/update" || url.pathname === "/") {
    const clientIp = (request.headers.get("CF-Connecting-IP") || "").trim();
    if (clientIp && (await isIpBlocked(env.KV, clientIp))) {
      return textResponse("badauth", 403);
    }

    const creds = extractCredentials(request, url);
    if (!creds) {
      return new Response("badauth", {
        status: 401,
        headers: { "Content-Type": "text/plain", "WWW-Authenticate": 'Basic realm="DDNS"' },
      });
    }

    const [user, serviceConfig] = await Promise.all([
      authenticateUserByKey(creds, env.KV),
      env.KV.get<ServiceConfig>("config:settings", "json"),
    ]);

    if (!user) {
      if (clientIp) {
        ctx.waitUntil(recordAuthFailure(env.KV, clientIp, `badauth:${creds.username}`, serviceConfig));
      }
      return textResponse("badauth", 403);
    }

    const rawHost = url.searchParams.get("hostname");
    if (!rawHost) return textResponse("notfqdn", 400);
    const hostname = rawHost.trim().toLowerCase().replace(/\.$/, "");

    const { zoneId } = await resolveZoneAndConfig(hostname, env, serviceConfig);
    if (!zoneId || !isHostAllowed(hostname, user, serviceConfig)) {
      return textResponse("nohost", 403);
    }

    const { ipv4, ipv6, isAutoDetected, hasInvalidIp } = parseDualStackIps(request, url);
    if (hasInvalidIp || (!ipv4 && !ipv6 && isAutoDetected)) {
      return textResponse("dnserr", 400);
    }

    try {
      const result = await reconcileDualStackRecords(
        zoneId,
        env.CF_API_TOKEN,
        hostname,
        ipv4,
        ipv6,
        isAutoDetected,
        serviceConfig
      );
      return textResponse(result.summary, 200);
    } catch {
      return textResponse("911", 502);
    }
  }

  return textResponse("notfound", 404);
}

export default {
  fetch: ddnsHandler,
};