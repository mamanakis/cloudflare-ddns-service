export interface Env {
  CF_API_TOKEN: string;
  CF_ZONE_ID?: string;
  KV: KVNamespace;
  ONBOARD_PREFIX?: string; // Defaults to "onboard-ddns." (domain-agnostic)
  ONBOARD_HOST?: string;   // Optional exact hostname override
}

export interface ServiceConfig {
  ALLOWED_TRIES?: number;
  PENALTY_TYPE?: "logarithmic" | "linear" | "flat";
  BASE_PENALTY_SECONDS?: number;
  MAX_PENALTY_SECONDS?: number;
  ALLOW_CREATION?: boolean;
  ALLOW_LIST_DOMAINS?: Record<string, string>;
  ALLOW_LIST_PREFIXES?: string[];
  BLOCK_LIST?: string[];
  MAX_ZONE_RECORDS?: number;
  ALERT_WEBHOOK_URL?: string;
}

export interface UserRule {
  id: string;
  salt: string;
  secret_hash: string;
  allowed_exact: string[];
  allowed_suffixes: string[];
}

export interface InviteRecord {
  pin: string;
  attempts?: number;
}

export interface AuditEntry {
  timestamp: string;
  event: string;
  username: string;
  ip: string;
  country: string;
  user_agent: string;
}

export interface CloudflareDnsRecord {
  id: string;
  type: "A" | "AAAA";
  name: string;
  content: string;
  proxied: boolean;
}

export interface CloudflareListResponse {
  success: boolean;
  result: CloudflareDnsRecord[];
}