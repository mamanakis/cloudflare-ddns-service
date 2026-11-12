import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          CF_API_TOKEN: "test-cloudflare-api-token",
          ONBOARD_PREFIX: "onboard-ddns.",
          CF_ZONE_ID: "zone_default_123",
        },
      },
    }),
  ],
});