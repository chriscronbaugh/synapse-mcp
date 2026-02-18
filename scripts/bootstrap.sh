#!/usr/bin/env bash
# Bootstrap the full Synapse stack (AHA + Axon + JSONStor + Cortex).
# This script handles one-time provisioning and initial user setup.
# After first run, just use: docker compose up -d
#
# Usage:
#   ./scripts/bootstrap.sh              # stack only
#   ./scripts/bootstrap.sh --load-data  # stack + import .nodes files from data/
set -euo pipefail

cd "$(dirname "$0")/.."

LOAD_DATA=false
for arg in "$@"; do
    case "$arg" in
        --load-data) LOAD_DATA=true ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

ENV_FILE=".env"
CORTEX_URL="https://localhost:4443"
USER="root"
PASS="secret"

# ── Step 1: Start AHA ──────────────────────────────────────────────
echo "Starting AHA service..."
docker compose up -d aha
echo "Waiting for AHA to be healthy..."
until docker inspect --format='{{.State.Health.Status}}' syn-aha 2>/dev/null | grep -q healthy; do
    printf "."
    sleep 2
done
echo " ready."

# ── Step 2: Generate provisioning URLs ──────────────────────────────
echo "Generating provisioning URLs..."

get_provision_url() {
    local service_name="$1"
    docker exec syn-aha python -m synapse.tools.aha.provision.service "$service_name" \
        2>&1 | grep "one-time use URL:" | sed 's/.*one-time use URL: //'
}

AXON_URL=$(get_provision_url "axon")
JSONSTOR_URL=$(get_provision_url "jsonstor")
CORTEX_URL_PROV=$(get_provision_url "cortex")

if [[ -z "$AXON_URL" || -z "$JSONSTOR_URL" || -z "$CORTEX_URL_PROV" ]]; then
    echo "ERROR: Failed to generate one or more provisioning URLs."
    echo "  AXON_URL=$AXON_URL"
    echo "  JSONSTOR_URL=$JSONSTOR_URL"
    echo "  CORTEX_URL_PROV=$CORTEX_URL_PROV"
    exit 1
fi

echo "  Axon:     $AXON_URL"
echo "  JSONStor: $JSONSTOR_URL"
echo "  Cortex:   $CORTEX_URL_PROV"

# Write provisioning URLs to .env for docker compose
cat > "$ENV_FILE" <<EOF
AXON_PROVISION_URL=$AXON_URL
JSONSTOR_PROVISION_URL=$JSONSTOR_URL
CORTEX_PROVISION_URL=$CORTEX_URL_PROV
EOF
echo "Provisioning URLs written to $ENV_FILE"

# ── Step 3: Start remaining services ────────────────────────────────
echo ""
echo "Starting Axon, JSONStor, and Cortex..."
docker compose up -d

echo "Waiting for Cortex HTTPS to be ready..."
until curl -sk "$CORTEX_URL/api/v1/active" 2>/dev/null | grep -q "true\|false"; do
    printf "."
    sleep 3
done
echo " ready."

# ── Step 4: Create root user ───────────────────────────────────────
echo ""
echo "Setting up root user..."
docker exec syn-cortex python -m synapse.tools.service.moduser --add --admin true "$USER"
docker exec syn-cortex python -m synapse.tools.service.moduser --passwd "$PASS" "$USER"

# ── Step 5: Load .nodes files (optional) ────────────────────────────
if [[ "$LOAD_DATA" == true ]]; then
    NODE_FILES=$(find data -name '*.nodes' 2>/dev/null || true)
    if [[ -n "$NODE_FILES" ]]; then
        echo ""
        echo "Loading .nodes files from data/..."
        for f in $NODE_FILES; do
            BASENAME=$(basename "$f")
            echo "  Importing $BASENAME..."
            docker exec syn-cortex python -m synapse.tools.cortex.feed \
                --cortex "cell:///vertex/storage" \
                --format syn.nodes \
                "/data/$BASENAME"
        done
        echo "Data import complete."
    else
        echo ""
        echo "No .nodes files found in data/."
    fi
else
    echo ""
    echo "Skipping data import (use --load-data to import .nodes files from data/)."
fi

# ── Done ────────────────────────────────────────────────────────────
echo ""
echo "=== Synapse stack is ready ==="
echo ""
echo "  Cortex API: $CORTEX_URL"
echo "  User:       $USER"
echo "  Pass:       $PASS"
echo ""
echo "  Services:"
docker compose ps --format "  {{.Name}}\t{{.Status}}"
echo ""
echo "To run the MCP server:"
echo "  SYNAPSE_URL=$CORTEX_URL SYNAPSE_USER=$USER SYNAPSE_PASS=$PASS SYNAPSE_VERIFY_SSL=false .venv/bin/synapse-mcp"
