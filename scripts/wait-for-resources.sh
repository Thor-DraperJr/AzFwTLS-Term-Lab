#!/bin/bash
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-rg-azfw-tls-lab}"
SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-}"
WAIT_INTERVAL="${WAIT_INTERVAL:-30}"
MAX_WAIT_TIME="${MAX_WAIT_TIME:-1800}"

if [[ -n "$SUBSCRIPTION_ID" ]]; then
    az account set --subscription "$SUBSCRIPTION_ID"
fi

start_time=$(date +%s)
while true; do
    states=$(az resource list --resource-group "$RESOURCE_GROUP" --query "[].properties.provisioningState" --output tsv 2>/dev/null || true)

    if [[ -z "$states" ]]; then
        echo "No resources found in $RESOURCE_GROUP."
        exit 1
    fi

    if ! grep -Eq 'Creating|Updating|Running|Accepted' <<< "$states"; then
        az resource list --resource-group "$RESOURCE_GROUP" --query "[].{Name:name,Type:type,State:properties.provisioningState}" --output table
        exit 0
    fi

    if (( $(date +%s) - start_time >= MAX_WAIT_TIME )); then
        echo "Timed out waiting for resources in $RESOURCE_GROUP."
        exit 1
    fi

    echo "Resources are still provisioning; checking again in ${WAIT_INTERVAL}s."
    sleep "$WAIT_INTERVAL"
done
