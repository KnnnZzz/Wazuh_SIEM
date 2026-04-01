#!/bin/bash

# Read the JSON-formatted log sent by Wazuh
read INPUT_JSON

# Extract the attacker's IP from the JSON
IP=$(echo $INPUT_JSON | grep -o '"srcip":"[^"]*' | cut -d'"' -f4)

# If no IP found, abort
if [ -z "$IP" ]; then
    exit 1
fi

# ==========================================
# OPNSENSE CONFIGURATION
# ==========================================
API_KEY="YOUR_OPNSENSE_API_KEY"
API_SECRET="YOUR_OPNSENSE_API_SECRET"
OPNSENSE_IP="YOUR_OPNSENSE_IP" # OPNsense management IP
# ==========================================

# Command to add the IP to the OPNsense firewall alias
curl -X POST -k -u "$API_KEY":"$API_SECRET" \
     -H "Content-Type: application/json" \
     -d "{\"address\":\"$IP\"}" \
     "https://$OPNSENSE_IP/api/firewall/alias_util/add/Wazuh_Blacklist"

echo "JSON RECEBIDO: $INPUT_JSON" >> /tmp/wazuh_debug.log
echo "IP EXTRAIDO: $IP" >> /tmp/wazuh_debug.log
