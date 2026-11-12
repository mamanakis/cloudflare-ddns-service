#!/usr/bin/env bash
set -euo pipefail

BINDING="KV"

# Auto-discover KV Namespace ID (<worker-name>-kv)
KV_ID=$(npx wrangler kv namespace list 2>/dev/null | jq -r '.[] | select(.title | ascii_downcase | endswith("-kv")) | .id' | head -n 1 || true)

if [[ -n "$KV_ID" ]]; then
  TARGET_ARGS=(--namespace-id="$KV_ID" --remote)
else
  TARGET_ARGS=(--binding="$BINDING" --remote)
fi

usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [arguments]

Commands:
  seed-config [config.json]             Load config.json into KV (config:settings & zone:map)
  invite <username> [ttl_hours]         Generate an 8-digit PIN invite (default: 24h)
  allow-exact <username> <fqdn>         Authorize an exact hostname (e.g., kb.example.com)
  allow-suffix <username> <suffix>      Authorize a domain suffix (e.g., .vpn.example.net)
  revoke-host <username> <host_or_suf>  Remove a hostname or suffix from a user
  show-user <username>                  Display a user's current KV record
  list-users                            List all registered users
  list-invites                          List all active pending invites
  audit [limit]                         Fetch and format recent audit logs (default: 10)
EOF
  exit 1
}

[[ $# -lt 1 ]] && usage
CMD="$1"
shift

case "$CMD" in
  seed-config)
    FILE="${1:-config.json}"
    [[ -f "$FILE" ]] || { echo "Error: Config file '$FILE' not found." >&2; exit 1; }
    # Strip _comment_* keys and zone_map object before writing config:settings
    SETTINGS_JSON=$(jq -c 'with_entries(select(.key | startswith("_comment") | not)) | del(.zone_map)' "$FILE")
    npx wrangler kv key put "config:settings" "$SETTINGS_JSON" "${TARGET_ARGS[@]}"
    echo "Seeded config:settings from $FILE"

    # If zone_map is defined in the config file, seed zone:map automatically
    if jq -e '.zone_map and (.zone_map | type == "object")' "$FILE" >/dev/null 2>&1; then
      ZONE_MAP_JSON=$(jq -c '.zone_map' "$FILE")
      npx wrangler kv key put "zone:map" "$ZONE_MAP_JSON" "${TARGET_ARGS[@]}"
      echo "Seeded zone:map from $FILE"
    fi
    ;;

  invite)
    USER="${1:-}"
    TTL_HOURS="${2:-24}"
    [[ -z "$USER" ]] && { echo "Error: username required"; usage; }
    USER=$(echo "$USER" | tr '[:upper:]' '[:lower:]')

    PIN=$(od -An -N4 -tu4 /dev/urandom | awk '{printf "%08d", $1 % 100000000}')
    TTL_SEC=$(( TTL_HOURS * 3600 ))
    EXP_MS=$(( ( $(date +%s) + TTL_SEC ) * 1000 ))

    PAYLOAD=$(jq -nc --arg pin "$PIN" '{pin: $pin}')
    META=$(jq -nc --argjson exp "$EXP_MS" '{exp: $exp}')

    npx wrangler kv key put "invite:${USER}" "$PAYLOAD" \
      --ttl="$TTL_SEC" \
      --metadata="$META" \
      "${TARGET_ARGS[@]}" > /dev/null

    echo "=========================================="
    echo " Invite Created for: ${USER}"
    echo " 8-Digit PIN:        ${PIN}"
    echo " Expires in:         ${TTL_HOURS} hours"
    echo "=========================================="
    ;;

  allow-exact|allow-suffix)
    USER="${1:-}"
    TARGET="${2:-}"
    [[ -z "$USER" || -z "$TARGET" ]] && { echo "Error: username and target required"; usage; }
    USER=$(echo "$USER" | tr '[:upper:]' '[:lower:]')
    TARGET=$(echo "$TARGET" | tr '[:upper:]' '[:lower:]')
    KEY="user:${USER}"

    RAW=$(npx wrangler kv key get "$KEY" "${TARGET_ARGS[@]}" 2>/dev/null || true)
    [[ -z "$RAW" ]] && { echo "Error: User '${USER}' not found in KV."; exit 1; }

    if [[ "$CMD" == "allow-exact" ]]; then
      UPDATED=$(echo "$RAW" | jq --arg h "$TARGET" '.allowed_exact = ((.allowed_exact + [$h]) | unique)')
    else
      UPDATED=$(echo "$RAW" | jq --arg s "$TARGET" '.allowed_suffixes = ((.allowed_suffixes + [$s]) | unique)')
    fi

    npx wrangler kv key put "$KEY" "$UPDATED" "${TARGET_ARGS[@]}" > /dev/null
    echo "$UPDATED" | jq '{id, allowed_exact, allowed_suffixes}'
    ;;

  revoke-host)
    USER="${1:-}"
    TARGET="${2:-}"
    [[ -z "$USER" || -z "$TARGET" ]] && { echo "Error: username and target required"; usage; }
    USER=$(echo "$USER" | tr '[:upper:]' '[:lower:]')
    TARGET=$(echo "$TARGET" | tr '[:upper:]' '[:lower:]')
    KEY="user:${USER}"

    RAW=$(npx wrangler kv key get "$KEY" "${TARGET_ARGS[@]}" 2>/dev/null || true)
    [[ -z "$RAW" ]] && { echo "Error: User '${USER}' not found."; exit 1; }

    UPDATED=$(echo "$RAW" | jq --arg t "$TARGET" '.allowed_exact -= [$t] | .allowed_suffixes -= [$t]')
    npx wrangler kv key put "$KEY" "$UPDATED" "${TARGET_ARGS[@]}" > /dev/null
    echo "$UPDATED" | jq '{id, allowed_exact, allowed_suffixes}'
    ;;

  show-user)
    USER="${1:-}"
    [[ -z "$USER" ]] && { echo "Error: username required"; usage; }
    npx wrangler kv key get "user:${USER}" "${TARGET_ARGS[@]}" | jq .
    ;;

  list-users)
    npx wrangler kv key list --prefix="user:" "${TARGET_ARGS[@]}" | jq -r '.[].name'
    ;;

  list-invites)
    npx wrangler kv key list --prefix="invite:" "${TARGET_ARGS[@]}" | jq .
    ;;

  audit)
    LIMIT="${1:-10}"
    KEYS=$(npx wrangler kv key list --prefix="audit:" "${TARGET_ARGS[@]}" | jq -r "sort_by(.name) | reverse | .[:${LIMIT}][].name")
    for k in $KEYS; do
      npx wrangler kv key get "$k" "${TARGET_ARGS[@]}" | jq -c .
    done
    ;;

  *)
    usage
    ;;
esac