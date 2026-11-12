import {
  env,
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ddnsHandler } from "../src/index";
import { sha256Hex } from "../src/security";
import type { Env, UserRule, ServiceConfig } from "../src/types";

declare module "cloudflare:test" {
  interface ProvidedEnv extends Env {}
}

const ZONE_ID = "00000000000000000000000000000001";
const HOSTNAME = "kb.example.com";

describe("cloudflare-ddns-service workerd suite", () => {
  beforeEach(async () => {
    await env.KV.put(
      "zone:map",
      JSON.stringify({ "example.com": ZONE_ID })
    );
    await env.KV.put(
      "config:settings",
      JSON.stringify({
        block_list: ["admin", "root", "test", "hack", "onboard-ddns", "ddns"],
        allow_creation: true,
        default_ttl: 60,
        default_proxied: false,
        allow_ipv6_auto_clear: true,
        rate_limit_max_fails: 3,
        rate_limit_window_sec: 300,
        rate_limit_block_sec: 3600,
        penalty_type: "logarithmic",
        max_penalty_sec: 3600000,
      } satisfies ServiceConfig)
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps onboarding portal dark (404) when no active invite exists", async () => {
    const req = new Request("https://onboard-ddns.example.com/");
    const ctx = createExecutionContext();
    const res = await ddnsHandler(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(404);
  });

  it("completes PIN onboarding, burns invite key, and creates isolated user:<id> record", async () => {
    await env.KV.put(
      "invite:omada-router",
      JSON.stringify({ pin: "84920174" }),
      { expirationTtl: 3600 }
    );

    const getCtx = createExecutionContext();
    const getRes = await ddnsHandler(
      new Request("https://onboard-ddns.example.com/"),
      env,
      getCtx
    );
    await waitOnExecutionContext(getCtx);
    expect(getRes.status).toBe(200);

    const postCtx = createExecutionContext();
    const postRes = await ddnsHandler(
      new Request("https://onboard-ddns.example.com/onboard", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "203.0.113.10",
        },
        body: JSON.stringify({
          username: "omada-router",
          pin: "84920174",
          mode: "token",
        }),
      }),
      env,
      postCtx
    );
    await waitOnExecutionContext(postCtx);

    expect(postRes.status).toBe(200);
    const data = (await postRes.json()) as { username: string; secret: string };
    expect(data.username).toBe("omada-router");
    expect(data.secret).toHaveLength(16);

    const burnedInvite = await env.KV.get("invite:omada-router");
    expect(burnedInvite).toBeNull();

    const storedUser = await env.KV.get<UserRule>(
      "user:omada-router",
      "json"
    );
    expect(storedUser).not.toBeNull();
    const expectedHash = await sha256Hex(`${storedUser!.salt}${data.secret}`);
    expect(storedUser!.secret_hash).toBe(expectedHash);
  });

  it("burns invite key after 3 failed PIN attempts", async () => {
    await env.KV.put(
      "invite:brute-user",
      JSON.stringify({ pin: "12345678" }),
      { expirationTtl: 3600 }
    );

    for (let attempt = 1; attempt <= 3; attempt++) {
      const ctx = createExecutionContext();
      const res = await ddnsHandler(
        new Request("https://onboard-ddns.example.com/onboard", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "CF-Connecting-IP": "198.51.100.77",
          },
          body: JSON.stringify({
            username: "brute-user",
            pin: "00000000",
            mode: "token",
          }),
        }),
        env,
        ctx
      );
      await waitOnExecutionContext(ctx);
      expect(res.status).toBe(403);
    }

    const deletedInvite = await env.KV.get("invite:brute-user");
    expect(deletedInvite).toBeNull();
  });

  it("reconciles explicit dual-stack IPs and deletes stale AAAA record when IPv6 is dropped", async () => {
    const salt = "a1b2c3d4e5f60718";
    const secret = "MyRouterToken123";
    const secret_hash = await sha256Hex(`${salt}${secret}`);

    await env.KV.put(
      "user:omada",
      JSON.stringify({
        id: "omada",
        salt,
        secret_hash,
        allowed_exact: [HOSTNAME],
        allowed_suffixes: [],
      } satisfies UserRule)
    );

    const calls: Array<{ url: string; method: string }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const method = init?.method || (input instanceof Request ? input.method : "GET");
      calls.push({ url, method });

      if (method === "GET" && url.includes(`/zones/${ZONE_ID}/dns_records`)) {
        return Response.json({
          success: true,
          result: [
            { id: "rec_a_1", type: "A", name: HOSTNAME, content: "198.51.100.1", proxied: false },
            { id: "rec_aaaa_stale", type: "AAAA", name: HOSTNAME, content: "2001:db8:1234::1", proxied: false },
          ],
        });
      }
      if (method === "PUT" && url.endsWith("/dns_records/rec_a_1")) {
        return Response.json({ success: true, result: {} });
      }
      if (method === "DELETE" && url.endsWith("/dns_records/rec_aaaa_stale")) {
        return Response.json({ success: true, result: { id: "rec_aaaa_stale" } });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    const req = new Request(
      `https://ddns.example.com/nic/update?hostname=${HOSTNAME}&ip=192.0.2.99&ipv6=`,
      { headers: { Authorization: `Basic ${btoa(`omada:${secret}`)}` } }
    );
    const ctx = createExecutionContext();
    const res = await ddnsHandler(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("good 192.0.2.99");
    expect(calls).toHaveLength(3);
    expect(calls.some((c) => c.method === "DELETE" && c.url.endsWith("/rec_aaaa_stale"))).toBe(true);
  });

  it("preserves existing AAAA record when updating A record via passive CF-Connecting-IP auto-detect", async () => {
    const salt = "1122334455667788";
    const secret = "PassiveToken9999";
    const secret_hash = await sha256Hex(`${salt}${secret}`);

    await env.KV.put(
      "user:pi-node",
      JSON.stringify({
        id: "pi-node",
        salt,
        secret_hash,
        allowed_exact: [HOSTNAME],
        allowed_suffixes: [],
      } satisfies UserRule)
    );

    const calls: Array<{ url: string; method: string }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const method = init?.method || (input instanceof Request ? input.method : "GET");
      calls.push({ url, method });

      if (method === "GET" && url.includes(`/zones/${ZONE_ID}/dns_records`)) {
        return Response.json({
          success: true,
          result: [
            { id: "rec_a_1", type: "A", name: HOSTNAME, content: "198.51.100.1", proxied: false },
            { id: "rec_aaaa_keep", type: "AAAA", name: HOSTNAME, content: "2001:db8:9999::5", proxied: false },
          ],
        });
      }
      if (method === "PUT" && url.endsWith("/dns_records/rec_a_1")) {
        return Response.json({ success: true, result: {} });
      }
      throw new Error(`Unexpected fetch (e.g. unwanted DELETE): ${method} ${url}`);
    });

    const req = new Request(`https://ddns.example.com/nic/update?hostname=${HOSTNAME}`, {
      headers: {
        Authorization: `Bearer pi-node:${secret}`,
        "CF-Connecting-IP": "203.0.113.250",
      },
    });

    const ctx = createExecutionContext();
    const res = await ddnsHandler(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("good 203.0.113.250");
    expect(calls).toHaveLength(2);
  });

  it("returns 'nochg' without calling PUT/POST when dual-stack records already match", async () => {
    const salt = "abcdef0123456789";
    const secret = "NoChgSecretToken";
    const secret_hash = await sha256Hex(`${salt}${secret}`);

    await env.KV.put(
      "user:router-nochg",
      JSON.stringify({
        id: "router-nochg",
        salt,
        secret_hash,
        allowed_exact: [HOSTNAME],
        allowed_suffixes: [],
      } satisfies UserRule)
    );

    vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      Response.json({
        success: true,
        result: [
          { id: "rec_a_1", type: "A", name: HOSTNAME, content: "192.0.2.50", proxied: false },
          { id: "rec_aaaa_1", type: "AAAA", name: HOSTNAME, content: "2001:db8::50", proxied: false },
        ],
      })
    );

    const req = new Request(
      `https://ddns.example.com/nic/update?hostname=${HOSTNAME}&myip=192.0.2.50,2001:db8::50`,
      { headers: { Authorization: `Basic ${btoa(`router-nochg:${secret}`)}` } }
    );
    const ctx = createExecutionContext();
    const res = await ddnsHandler(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("nochg 192.0.2.50 2001:db8::50");
  });

  it("enforces block_list even when user has a matching allowed_suffixes wildcard", async () => {
    const salt = "fedcba9876543210";
    const secret = "SuffixWildcard12";
    const secret_hash = await sha256Hex(`${salt}${secret}`);

    await env.KV.put(
      "user:wildcard-user",
      JSON.stringify({
        id: "wildcard-user",
        salt,
        secret_hash,
        allowed_exact: [],
        allowed_suffixes: [".example.com"],
      } satisfies UserRule)
    );

    const req = new Request(
      "https://ddns.example.com/nic/update?hostname=admin.example.com&ip=192.0.2.10",
      { headers: { Authorization: `Basic ${btoa(`wildcard-user:${secret}`)}` } }
    );
    const ctx = createExecutionContext();
    const res = await ddnsHandler(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(403);
    expect(await res.text()).toBe("nohost");
  });

  it("locks out client IP after exceeding rate_limit_max_fails failed auth attempts", async () => {
    for (let i = 0; i < 3; i++) {
      const ctx = createExecutionContext();
      const res = await ddnsHandler(
        new Request("https://ddns.example.com/nic/update?hostname=kb.example.com", {
          headers: {
            Authorization: `Basic ${btoa("nonexistent:wrongpass")}`,
            "CF-Connecting-IP": "198.51.100.200",
          },
        }),
        env,
        ctx
      );
      await waitOnExecutionContext(ctx);
      expect(res.status).toBe(403);
    }

    const blockedEntry = await env.KV.get("blocked_ip:198.51.100.200");
    expect(blockedEntry).not.toBeNull();
  });
});