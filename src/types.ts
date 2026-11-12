export interface Env {
  CF_API_TOKEN: string;
  CF_ZONE_ID?: string;
  KV: KVNamespace;
  ONBOARD_PREFIX?: string; // Defaults to "onboard-ddns." (domain-agnostic)
  ONBOARD_HOST?: string;   // Optional exact hostname override
}

export interface ServiceConfig {
  block_list?: string[];
  allow_creation?: boolean;
  default_ttl?: number;
  default_proxied?: boolean;
  allow_ipv6_auto_clear?: boolean;
  rate_limit_max_fails?: number;
  rate_limit_window_sec?: number;
  rate_limit_block_sec?: number;
  penalty_type?: "logarithmic" | "fixed";
  max_penalty_sec?: number;
  max_zone_records?: number;
  max_pin_attempts?: number;
  audit_ttl_days?: number;
  alert_webhook_url?: string;
}

export interface RateLimitState {
  fails: number;
  offenses: number;
  first_fail_ms: number;
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
  ttl?: number;
}

export interface CloudflareListResponse {
  success: boolean;
  result: CloudflareDnsRecord[];
  result_info?: {
    total_count?: number;
  };
}