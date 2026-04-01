#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2026, CIRCL, Luciano Righetti and Francisco Gomes
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the AGPL-3.0 license

import json
import os
import re
import sys
import ipaddress
import urllib3
from socket import AF_UNIX, SOCK_DGRAM, socket

# Suppress InsecureRequestWarning when verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_HASHES = 3
ERR_NO_RESPONSE_MISP = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
    from requests.exceptions import Timeout
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration:
# <integration>
#   <name>misp_file_hashes.py</name>
#   <hook_url>misp_url</hook_url> <!-- Replace with your MISP host -->
#   <api_key>API_KEY</api_key> <!-- Replace with your MISP API key -->
#   <group>syscheck</group>
#   <alert_format>json</alert_format>
#   <options>{
#       "timeout": 10,
#       "retries": 3,
#       "debug": false,
#       "tags": ["tlp:white", "tlp:clear", "malware"],
#       "push_sightings": true,
#       "sightings_source": "wazuh"
#   }</options>
# </integration>

# Global vars
debug_enabled = False
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Log and socket path
LOG_FILE = f"{pwd}/logs/integrations.log"
SOCKET_ADDR = f"{pwd}/queue/sockets/queue"

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2
MISP_URL_INDEX = 3
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7


def main(args):
    global debug_enabled
    global timeout
    global retries
    global json_options
    try:
        # Read arguments
        bad_arguments: bool = False
        msg = ""
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == "debug"

        # Logging the call
        with open(LOG_FILE, "a") as f:
            f.write(msg)

        if bad_arguments:
            debug("# Error: Exiting, bad arguments. Inputted: %s" % args)
            sys.exit(ERR_BAD_ARGUMENTS)
        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    global debug_enabled
    global timeout
    global retries
    global json_options
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields

    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug("# Running MISP File Hashes script")

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    misp_url: str = args[MISP_URL_INDEX]
    apikey: str = args[APIKEY_INDEX]
    options_file_location: str = ""

    # Look for options file location
    for idx in range(4, len(args)):
        if args[idx][-7:] == "options":
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(
        f"# Opening options file at '{options_file_location}' with '{json_options}'"
    )
    if "timeout" in json_options:
        if isinstance(json_options["timeout"],
                      int) and json_options["timeout"] > 0:
            timeout = json_options["timeout"]
        else:
            debug("# Warning: Invalid timeout value. Using default")

    if "retries" in json_options:
        if isinstance(json_options["retries"],
                      int) and json_options["retries"] >= 0:
            retries = json_options["retries"]
        else:
            debug("# Warning: Invalid retries value. Using default")
    if "debug" in json_options:
        if isinstance(json_options["debug"], bool):
            debug_enabled = json_options["debug"]
        else:
            debug("# Warning: Invalid debug value. Using default")

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(
        f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    # Request MISP info
    debug("# Requesting MISP information")
    msg: any = request_misp_info(json_alert, misp_url, apikey)

    if not msg:
        debug("# Empty message or no valid IoCs found. Exiting gracefully.")
        sys.exit(0)

    # --- ACTIVE RESPONSE MODIFICATION ---
    # Copy the file path from the original alert into the MISP message
    # This allows the 'remove-threat.sh' script to find the file to delete
    if 'syscheck' in json_alert and 'path' in json_alert['syscheck']:
        msg['syscheck'] = {}
        msg['syscheck']['path'] = json_alert['syscheck']['path']
        debug(
            f"# Path injected for Active Response: {msg['syscheck']['path']}")
    # --- END MODIFICATION ---

    send_msg(msg, json_alert["agent"])


def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled

    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")


def request_hash_from_api(iocs: list, alert_output: dict, misp_url: str,
                          api_key: str):
    """
    Search for a list of IoCs in MISP using the restSearch API.
    """
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # MISP accepts a list of values in the 'value' field. It will search for any of them.
    payload = {
        "value": iocs,
        "to_ids": 1,  # Search only for attributes marked for IDS
        "returnFormat": "json"
    }

    url = f"{misp_url}/attributes/restSearch"

    try:
        # [Improvement 1] Security Risk: Use a valid cert path instead of False when in production
        # response = requests.post(url, headers=headers, json=payload, verify='/etc/ssl/certs/internal-ca.pem', timeout=timeout)
        response = requests.post(url,
                                 headers=headers,
                                 json=payload,
                                 verify=False,
                                 timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        debug(f"# Error communicating with MISP: {e}")
        # [Improvement 6] Better Exception Handling: Re-raise the exception so Wazuh logs the integration failure
        raise Exception(f"MISP request failed: {e}")


def push_misp_sighting(misp_url: str, api_key: str, hashes: dict):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Python library-client-Wazuh-MISP",
        "Authorization": api_key,
    }

    debug("# Querying MISP API")

    add_sighting_payload = {"values": list(hashes.values()), "source": "wazuh"}

    if "sightings_source" in json_options:
        if isinstance(json_options["sightings_source"], str):
            add_sighting_payload["source"] = json_options["sightings_source"]
        else:
            debug("# Warning: Invalid sightings_source value. Ignoring")

    debug("# MISP API request payload: %s" %
          (json.dumps(add_sighting_payload)))

    response = requests.post(f"{misp_url}/sightings/add",
                             json=add_sighting_payload,
                             headers=headers,
                             timeout=timeout,
                             verify=False)

    if response.status_code == 200:
        debug("# MISP Sighting pushed successfully")
    else:
        debug("# An error occurred pushing MISP sighting: %s" %
              (response.text))


def request_misp_info(alert: any, misp_url: str, api_key: str):
    alert_output = {"misp_file_hashes": {}, "integration": "misp_file_hashes"}
    iocs_to_check = []
    ioc_type = "unknown"
    ioc_source = "unknown"

    # 1. ATTEMPT TO EXTRACT HASHES (FIM / Syscheck Mode)
    if "syscheck" in alert and not "registry" in alert["syscheck"]:
        debug("# Alert is Syscheck File. Extracting hashes.")
        if alert["syscheck"].get("md5_after"):
            iocs_to_check.append(alert["syscheck"]["md5_after"])
        if alert["syscheck"].get("sha1_after"):
            iocs_to_check.append(alert["syscheck"]["sha1_after"])
        if alert["syscheck"].get("sha256_after"):
            iocs_to_check.append(alert["syscheck"]["sha256_after"])
        ioc_type = "hash"
        ioc_source = alert["syscheck"].get("path", "unknown file")

    # 2. ATTEMPT TO EXTRACT REGISTRY KEYS (Windows Syscheck)
    elif "syscheck" in alert and "registry" in alert["syscheck"]:
        debug("# Alert is Syscheck Registry. Extracting Key.")
        iocs_to_check.append(alert["syscheck"]["path"])
        ioc_type = "regkey"
        ioc_source = "Windows Registry"

    # 3. ATTEMPT TO EXTRACT DOMAINS (DNS / Sysmon Event 22)
    elif "data" in alert and "win" in alert["data"] and "eventdata" in alert[
            "data"]["win"] and "queryName" in alert["data"]["win"]["eventdata"]:
        debug("# Alert is Sysmon DNS. Extracting Domain.")
        iocs_to_check.append(alert["data"]["win"]["eventdata"]["queryName"])
        ioc_type = "domain"
        ioc_source = "Sysmon DNS Query"

    # 4.5. ATTEMPT TO EXTRACT PROCESSES (Windows Native Event 4688)
    # D. Windows Processes (Event ID 4688)
    elif "data" in alert and "win" in alert["data"] and "system" in alert[
            "data"]["win"] and alert["data"]["win"]["system"].get(
                "eventID") == "4688":
        # 1. Try to catch a hidden IP in the command line (e.g., ping 1.2.3.4)
        cmdline = alert["data"]["win"]["eventdata"].get("commandLine", "")
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', cmdline)

        if ip_match:
            iocs_to_check.append(ip_match.group(0))
            ioc_type = "ip"
            source_info = "Windows Command Line (Deep Inspection)"
        else:
            # 2. If no IP found, analyze the program name (e.g., malware.exe)
            raw_path = alert["data"]["win"]["eventdata"].get(
                "newProcessName", "")
            clean_path = raw_path.replace("\\\\", "\\")
            if clean_path:
                iocs_to_check.append(clean_path)
                ioc_type = "filename"
                source_info = "Windows Native Process Creation"

# 5. ATTEMPT TO EXTRACT GENERIC IPs AND DOMAINS (Network / Web)
    elif "data" in alert:
        if "srcip" in alert["data"]:
            iocs_to_check.append(alert["data"]["srcip"])
            ioc_type = "ip"
            ioc_source = "Network Connection"
        if "domain" in alert["data"]:
            iocs_to_check.append(alert["data"]["domain"])
            ioc_type = "domain"
            ioc_source = "Web/DNS Log"
        if "srcaddr" in alert["data"]:
            iocs_to_check.append(alert["data"]["srcaddr"])
            ioc_type = "ip"
            ioc_source = "MikroTik Network Connection"

    elif "srcip" in alert:
        iocs_to_check.append(alert["srcip"])
        ioc_type = "ip"
        ioc_source = "Network Connection"

    # 6. CHECK IF WE FOUND ANYTHING VALID
    iocs_to_check = [ioc for ioc in iocs_to_check if ioc]
    if not iocs_to_check:
        debug("# No supported IoCs found in the alert. Exiting.")
        return None

    # 6.5. ENTERPRISE WHITELIST (Skip known-good traffic and native processes)
    # [Improvement 4] Hardcoded Whitelist (Maintainability): Try to read whitelist from JSON options; fall back to defaults
    WHITELIST_IOCS = json_options.get("whitelist", [
        "127.0.0.1", "0.0.0.0", "8.8.8.8",
        "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\taskeng.exe",
        "C:\\Windows\\System32\\services.exe"
    ])

    # [Improvement 3] Bug Risk: Whitelist Case-Sensitivity Check
    WHITELIST_IOCS_LOWER = [ioc.lower() for ioc in WHITELIST_IOCS]

    # Filter IoCs by removing whitelisted entries and private IPs
    filtered_iocs = []
    for ioc in iocs_to_check:
        if ioc.lower() in WHITELIST_IOCS_LOWER:
            continue

        # [Improvement 2] Efficiency: Prevent Internal IP / RFC1918 Queries
        # DISABLED FOR TESTING: We are attacking via local networks
        # if ioc_type == "ip":
        #    try:
        #        if ipaddress.ip_address(ioc).is_private:
        #            continue
        #    except ValueError:
        #        pass

        filtered_iocs.append(ioc)

    iocs_to_check = filtered_iocs

    if not iocs_to_check:
        debug(
            "# Whitelist/Private IP: All detected IoCs are trusted or private and were ignored. Exiting."
        )
        return None

    # --- INITIALIZE OUTPUT BLOCK ---
    alert_output["misp_file_hashes"]["found"] = 0
    alert_output["misp_file_hashes"]["source"] = {
        "alert_id": alert.get("id", "unknown"),
        "ioc_type": ioc_type,
        "source_info": ioc_source
    }
    # ---------------------------------------------

    # 7. QUERY MISP
    misp_response_data = request_hash_from_api(iocs_to_check, alert_output,
                                               misp_url, api_key)

    # 8. ANALYZE MISP RESPONSE
    if misp_response_data and misp_response_data.get("response", {}).get(
            "Attribute", []) != []:
        alert_output["misp_file_hashes"]["found"] = 1

        # Get the first match for details
        misp_attribute = misp_response_data.get("response").get("Attribute")[0]
        event_uuid = misp_attribute.get("Event").get("uuid")
        attribute_uuid = misp_attribute.get("uuid")

        # Extract additional context for SOC analyst (Enrichment)
        category = misp_attribute.get("category", "Unknown")
        event_id = misp_attribute.get("event_id", "Unknown")

        alert_output["misp_file_hashes"].update({
            "type":
            misp_attribute.get("type"),
            "value":
            misp_attribute.get("value"),
            "category":
            category,
            "uuid":
            attribute_uuid,
            "timestamp":
            misp_attribute.get("timestamp"),
            "event_uuid":
            event_uuid,
            "event_id":
            event_id,
            "permalink":
            f"{misp_url}/events/view/{event_id}",
        })
        debug(
            f"# Match found in MISP! Type: {misp_attribute.get('type')}, Value: {misp_attribute.get('value')}"
        )
    else:
        debug("# No match found in MISP for the provided IoCs.")

    # 9. INJECT DATA FOR ACTIVE RESPONSE TO WORK
    if alert_output["misp_file_hashes"]["found"] == 1:
        if ioc_type == "ip":
            # Keep only the srcip at the root level, which is 100% safe for Elasticsearch
            alert_output["srcip"] = alert_output["misp_file_hashes"]["value"]
        elif ioc_type == "hash" and 'syscheck' in alert and 'path' in alert[
                'syscheck']:
            # [Improvement 7] Safer Dictionary Overrides for Active Response
            alert_output.setdefault('syscheck',
                                    {})['path'] = alert['syscheck']['path']
    return alert_output


# [Improvement 5] Dead Code / Technical Debt: Removed 'query_api' duplicate legacy function


def send_msg(msg: any, agent: any = None) -> None:
    if not agent or agent["id"] == "000":
        string = "1:misp_file_hashes:{0}".format(json.dumps(msg))
    else:
        location = "[{0}] ({1}) {2}".format(
            agent["id"], agent["name"],
            agent["ip"] if "ip" in agent else "any")
        location = location.replace("|", "||").replace(":", "|:")
        string = "1:{0}->misp_file_hashes:{1}".format(location,
                                                      json.dumps(msg))

    debug("# Request result from MISP server: %s" % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug("# Error: Unable to open socket connection at %s" % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug("Failed getting JSON alert. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> any:
    """Read JSON options object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    #except FileNotFoundError:
    #    debug("# JSON file for options %s doesn't exist" % file_location)
    #except BaseException as e:
    #    debug("Failed getting JSON options. Error: %s" % e)
    #    sys.exit(ERR_INVALID_JSON)
    except Exception as e:
        debug(
            "# JSON file for options %s doesn't exist or is invalid. Error: %s"
            % (file_location, e))
        return {}


if __name__ == "__main__":
    main(sys.argv)
