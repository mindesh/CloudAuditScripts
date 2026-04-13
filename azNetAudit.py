#!/usr/bin/env python3
"""
Azure Network Auditor v2.0 — Resource Graph Edition.

Drop-in replacement for aznetaudit.py (v1.2) that uses Azure Resource Graph
bulk queries + direct REST API calls instead of az CLI subprocesses.
Produces identical JSON snapshot format for full backward compatibility.

Performance: ~3-5 minutes for 43 subscriptions (vs ~45 minutes with CLI).

Requires: Python 3.6+, Azure CLI (for auth token), requests library.
Designed for Azure Cloud Shell.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.stderr.write("Installing 'requests' library...\n")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

VERSION = "2.0.0"

# ─── Colors ───────────────────────────────────────────────────────────────────

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

if not sys.stderr.isatty():
    RED = GREEN = YELLOW = CYAN = BOLD = NC = ""

# ─── Constants ────────────────────────────────────────────────────────────────

SYSTEM_SUBNETS = {
    "GatewaySubnet",
    "AzureFirewallSubnet",
    "AzureFirewallManagementSubnet",
    "AzureBastionSubnet",
    "RouteServerSubnet",
}

NETWORK_POLICY_KEYWORDS = re.compile(
    r"network|route|firewall|nsg|subnet|vnet|udr|traffic|ip.address|public.ip|"
    r"private.endpoint|security.group|virtual.network|expressroute|vpn|gateway|ddos|waf",
    re.IGNORECASE,
)

SNAPSHOT_PATTERN = re.compile(r"^snapshot-(\d{8}-\d{6})\.json$")

HIGH_RISK_INBOUND_PORTS = {"22", "3389", "445", "1433", "3306", "5432"}
WIDE_OPEN_SOURCES = {"*", "Internet", "0.0.0.0/0", "Any"}

_print_lock = threading.Lock()

BAR_FILL = "█"
BAR_EMPTY = "░"
BAR_WIDTH = 30
SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# ARM API endpoint
ARM_BASE = "https://management.azure.com"
ARG_API = "2022-10-01"

# ─── Resource Graph Queries ───────────────────────────────────────────────────

ARG_QUERIES = {
    "vnets_subnets": """
        Resources
        | where type == "microsoft.network/virtualnetworks"
        | mv-expand subnet = properties.subnets
        | project subscriptionId, vnetId=id, vnetName=name, rg=resourceGroup, location,
            addressSpace=properties.addressSpace.addressPrefixes,
            ddos=properties.enableDdosProtection,
            ddosPlan=properties.ddosProtectionPlan.id,
            subnetName=subnet.name,
            subnetPrefix=coalesce(subnet.properties.addressPrefix, subnet.properties.addressPrefixes[0]),
            nsgId=subnet.properties.networkSecurityGroup.id,
            rtId=subnet.properties.routeTable.id,
            svcEndpoints=subnet.properties.serviceEndpoints,
            delegations=subnet.properties.delegations,
            natGw=subnet.properties.natGateway.id
    """,
    "peerings": """
        Resources
        | where type == "microsoft.network/virtualnetworks"
        | mv-expand peering = properties.virtualNetworkPeerings
        | where isnotnull(peering)
        | project subscriptionId, vnetId=id, vnetName=name,
            peerName=peering.name,
            remoteVnetId=peering.properties.remoteVirtualNetwork.id,
            state=peering.properties.peeringState,
            allowVNetAccess=peering.properties.allowVirtualNetworkAccess,
            allowFwdTraffic=peering.properties.allowForwardedTraffic,
            allowGwTransit=peering.properties.allowGatewayTransit,
            useRemoteGw=peering.properties.useRemoteGateways
    """,
    "route_tables": """
        Resources
        | where type == "microsoft.network/routetables"
        | project subscriptionId, id, name, resourceGroup,
            disableBgp=properties.disableBgpRoutePropagation,
            routes=properties.routes
    """,
    "nsgs": """
        Resources
        | where type == "microsoft.network/networksecuritygroups"
        | project subscriptionId, id, name, resourceGroup, location,
            customRules=properties.securityRules,
            defaultRules=properties.defaultSecurityRules,
            subnets=properties.subnets
    """,
    "public_ips": """
        Resources
        | where type == "microsoft.network/publicipaddresses"
        | project subscriptionId, id, name, resourceGroup,
            ip=properties.ipAddress,
            allocation=properties.publicIPAllocationMethod,
            ipConfigId=properties.ipConfiguration.id
    """,
    "nics": """
        Resources
        | where type == "microsoft.network/networkinterfaces"
        | project subscriptionId, id, name, resourceGroup,
            ipConfigs=properties.ipConfigurations,
            vmId=properties.virtualMachine.id,
            nicNsgId=properties.networkSecurityGroup.id
    """,
    "gateways": """
        Resources
        | where type == "microsoft.network/virtualnetworkgateways"
        | project subscriptionId, id, name, resourceGroup,
            gwType=properties.gatewayType, vpnType=properties.vpnType,
            sku=properties.sku.name, state=properties.provisioningState,
            subnetId=properties.ipConfigurations[0].properties.subnet.id
    """,
    "private_endpoints": """
        Resources
        | where type == "microsoft.network/privateendpoints"
        | project subscriptionId, id, name, resourceGroup,
            subnetId=properties.subnet.id,
            connections=properties.privateLinkServiceConnections
    """,
    "private_dns_zones": """
        Resources
        | where type == "microsoft.network/privatednszones"
        | project subscriptionId, id, name, resourceGroup,
            recordCount=properties.numberOfRecordSets
    """,
    "private_dns_links": """
        Resources
        | where type == "microsoft.network/privatednszones/virtualnetworklinks"
        | project subscriptionId, id, linkName=name,
            vnetId=properties.virtualNetwork.id,
            registrationEnabled=properties.registrationEnabled,
            zoneName=tostring(split(id, '/')[8]),
            zoneRg=resourceGroup
    """,
    "network_watchers": """
        Resources
        | where type == "microsoft.network/networkwatchers"
        | project subscriptionId, name, location,
            state=properties.provisioningState
    """,
    "flow_logs": """
        Resources
        | where type == "microsoft.network/networkwatchers/flowlogs"
        | project subscriptionId, name,
            targetNsgId=properties.targetResourceId,
            enabled=properties.enabled,
            storageId=properties.storageId,
            retentionDays=properties.retentionPolicy.days,
            analyticsEnabled=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled,
            workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceResourceId
    """,
    "app_services": """
        Resources
        | where type == "microsoft.web/sites"
        | project subscriptionId, id, name, resourceGroup, kind, location,
            state=properties.state, httpsOnly=properties.httpsOnly,
            publicNetworkAccess=properties.publicNetworkAccess,
            vnetSubnetId=properties.virtualNetworkSubnetId,
            peCount=array_length(properties.privateEndpointConnections)
    """,
    "storage_accounts": """
        Resources
        | where type == "microsoft.storage/storageaccounts"
        | project subscriptionId, id, name, resourceGroup, kind,
            publicNetworkAccess=properties.publicNetworkAccess,
            allowBlobPublicAccess=properties.allowBlobPublicAccess,
            httpsOnly=properties.supportsHttpsTrafficOnly,
            defaultAction=properties.networkAcls.defaultAction,
            ipRulesCount=array_length(properties.networkAcls.ipRules),
            vnetRulesCount=array_length(properties.networkAcls.virtualNetworkRules),
            peCount=array_length(properties.privateEndpointConnections)
    """,
}

ARG_POLICY_QUERY = """
    PolicyResources
    | where type == "microsoft.authorization/policyassignments"
    | where properties.displayName contains "network"
        or properties.displayName contains "public"
        or properties.displayName contains "ip"
        or properties.displayName contains "nsg"
    | project subscriptionId, name,
        definitionId=properties.policyDefinitionId,
        scope=properties.scope,
        enforcement=properties.enforcementMode,
        description=properties.displayName
"""


# ─── Utility ──────────────────────────────────────────────────────────────────


def printerr(*args, **kwargs):
    with _print_lock:
        print(*args, file=sys.stderr, **kwargs)


def resource_id_name(resource_id):
    if not resource_id:
        return ""
    return str(resource_id).rstrip("/").split("/")[-1]


def resource_id_rg(resource_id):
    if not resource_id:
        return ""
    parts = str(resource_id).split("/")
    return parts[4] if len(parts) > 4 else ""


def resource_id_sub(resource_id):
    if not resource_id:
        return ""
    parts = str(resource_id).split("/")
    return parts[2] if len(parts) > 2 else ""


def extract_vnet_id_from_subnet(subnet_id):
    """Extract VNet resource ID from a subnet resource ID."""
    if not subnet_id:
        return ""
    idx = subnet_id.lower().find("/subnets/")
    if idx > 0:
        return subnet_id[:idx]
    return ""


def classify_internet_access(routes):
    """Classify subnet internet access based on its routes."""
    if not routes:
        return "Direct"
    for r in routes:
        if r.get("prefix") == "0.0.0.0/0":
            hop = r.get("next_hop_type", "")
            if hop == "VirtualAppliance":
                return "Via Firewall"
            elif hop == "None":
                return "Blocked"
            else:
                return "Direct"
    return "Direct"


# ─── Progress Tracker ─────────────────────────────────────────────────────────


class ProgressTracker:
    def __init__(self, total, label="Processing"):
        self.total = total
        self.label = label
        self.completed = 0
        self.errors = 0
        self.active = {}
        self.start_time = time.time()
        self._lock = threading.Lock()
        self._spin_idx = 0
        self._stop_event = threading.Event()
        self._timer_thread = None
        self._is_tty = sys.stderr.isatty()
        self._bar_lines = 1

    def start(self):
        if self._is_tty:
            self._redraw()
            self._timer_thread = threading.Thread(target=self._tick, daemon=True)
            self._timer_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._timer_thread:
            self._timer_thread.join(timeout=2)
        if self._is_tty:
            self._clear_bar()

    def _tick(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(1.0)
            if not self._stop_event.is_set():
                self._redraw()

    def set_active(self, name, phase):
        with self._lock:
            self.active[name] = phase
        if self._is_tty:
            self._redraw()

    def mark_done(self, name, summary=""):
        with self._lock:
            self.completed += 1
            self.active.pop(name, None)
        self._log(f"  {GREEN}✓{NC} {name} — {summary}")

    def mark_error(self, name, error=""):
        with self._lock:
            self.errors += 1
            self.active.pop(name, None)
        self._log(f"  {RED}✗{NC} {name} — {RED}{error}{NC}")

    def log(self, message):
        self._log(message)

    def _log(self, message):
        with _print_lock:
            if self._is_tty:
                self._clear_bar_lines()
                sys.stderr.write(f"{message}\n")
                self._draw_bar()
            else:
                sys.stderr.write(f"{message}\n")
            sys.stderr.flush()

    def _clear_bar_lines(self):
        for _ in range(self._bar_lines):
            sys.stderr.write("\033[2K\033[A")
        sys.stderr.write("\033[2K\r")

    def _redraw(self):
        with _print_lock:
            self._draw_bar()

    def _draw_bar(self):
        if not self._is_tty:
            return
        with self._lock:
            done = self.completed
            errs = self.errors
            active_count = len(self.active)
            active_names = list(self.active.items())[:3]
            spin = SPINNER[self._spin_idx % len(SPINNER)]
            self._spin_idx += 1

        elapsed = time.time() - self.start_time
        mins, secs = divmod(int(elapsed), 60)
        pct = done / self.total if self.total > 0 else 0
        filled = int(BAR_WIDTH * pct)
        bar = BAR_FILL * filled + BAR_EMPTY * (BAR_WIDTH - filled)

        parts = [f"{spin} [{bar}] {done}/{self.total}"]
        if active_count > 0:
            parts.append(f"{CYAN}{active_count} active{NC}")
        if errs > 0:
            parts.append(f"{RED}{errs} err{NC}")
        parts.append(f"{mins}m {secs:02d}s")

        status_line = " | ".join(parts)
        lines = 1
        if active_names:
            active_str = ", ".join(f"{n[:20]}:{CYAN}{p}{NC}" for n, p in active_names)
            if active_count > 3:
                active_str += f" +{active_count - 3} more"
            status_line += f"\n  {active_str}"
            lines = 2

        self._bar_lines = lines
        sys.stderr.write(f"\033[2K\r{status_line}")
        sys.stderr.flush()

    def _clear_bar(self):
        with _print_lock:
            self._clear_bar_lines()
            sys.stderr.write("\r")
            sys.stderr.flush()


# ─── Azure Client ─────────────────────────────────────────────────────────────


class AzureClient:
    """HTTP client for Azure Resource Graph and ARM REST API."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"
        self._token = None
        self._token_expiry = 0
        self._token_lock = threading.Lock()
        self._refresh_token()

    def _refresh_token(self):
        """Get a fresh Bearer token from az CLI."""
        try:
            result = subprocess.run(
                'az account get-access-token --resource https://management.azure.com '
                '--query "{token:accessToken, expires:expiresOn}" -o json',
                shell=True, capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                printerr(f"{RED}Failed to get access token. Run: az login{NC}")
                sys.exit(1)
            data = json.loads(result.stdout)
            self._token = data["token"]
            # Parse expiry — "2026-04-01 15:30:00.000000" format
            try:
                exp_str = data["expires"]
                exp_dt = datetime.strptime(exp_str[:19], "%Y-%m-%d %H:%M:%S")
                self._token_expiry = exp_dt.timestamp()
            except (ValueError, KeyError):
                # Default: 50 minutes from now
                self._token_expiry = time.time() + 3000
            self.session.headers["Authorization"] = f"Bearer {self._token}"
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            printerr(f"{RED}Cannot get Azure token: {e}{NC}")
            printerr(f"Ensure Azure CLI is installed and you are logged in (az login)")
            sys.exit(1)

    def _ensure_token(self):
        """Refresh token if it will expire within 5 minutes."""
        with self._token_lock:
            if time.time() > self._token_expiry - 300:
                self._refresh_token()

    def resource_graph_query(self, query, subscription_ids):
        """Execute an Azure Resource Graph query across subscriptions.

        Handles pagination via $skipToken. Returns list of all result rows.
        """
        self._ensure_token()
        url = f"{ARM_BASE}/providers/Microsoft.ResourceGraph/resources?api-version={ARG_API}"
        body = {
            "query": query,
            "subscriptions": subscription_ids,
            "options": {"resultFormat": "objectArray"},
        }

        all_rows = []
        pages = 0
        max_pages = 200

        while pages < max_pages:
            resp = self._do_request("POST", url, json_body=body)
            if resp is None:
                break

            data = resp.get("data", [])
            all_rows.extend(data)

            skip_token = resp.get("$skipToken")
            if not skip_token:
                break

            body["options"]["$skipToken"] = skip_token
            pages += 1

        return all_rows

    def arm_get(self, url, api_version="2023-05-01"):
        """Make a GET request to an ARM REST endpoint."""
        self._ensure_token()
        separator = "&" if "?" in url else "?"
        full_url = f"{url}{separator}api-version={api_version}"
        return self._do_request("GET", full_url) or {}

    def _do_request(self, method, url, json_body=None, _retries=3):
        """Execute an HTTP request with retry on 429/5xx."""
        for attempt in range(_retries):
            try:
                if method == "POST":
                    resp = self.session.post(url, json=json_body, timeout=120)
                else:
                    resp = self.session.get(url, timeout=120)

                if resp.status_code == 200:
                    return resp.json()

                if resp.status_code == 401:
                    # Token expired — refresh and retry
                    with self._token_lock:
                        self._refresh_token()
                    continue

                if resp.status_code == 429 or resp.status_code >= 500:
                    retry_after = int(resp.headers.get("Retry-After", 2 ** attempt * 5))
                    time.sleep(min(retry_after, 60))
                    continue

                # Other error
                return None

            except (requests.RequestException, json.JSONDecodeError):
                if attempt < _retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return None

        return None

    def get_subscriptions(self):
        """Get list of enabled subscriptions via az CLI."""
        try:
            result = subprocess.run(
                'az account list --query "[?state==\'Enabled\'].{id:id, name:name}" -o json',
                shell=True, capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return []


# ─── Phase 1: Discovery ──────────────────────────────────────────────────────


def run_discovery(client, sub_ids):
    """Run all Resource Graph queries. Returns dict of query_name → row list."""
    raw = {}
    queries = list(ARG_QUERIES.items()) + [("policies", ARG_POLICY_QUERY)]
    total = len(queries)

    for i, (name, query) in enumerate(queries, 1):
        printerr(f"  [{i}/{total}] Querying {name}...")
        try:
            rows = client.resource_graph_query(query, sub_ids)
            raw[name] = rows
            printerr(f"  [{i}/{total}] {name}: {GREEN}{len(rows)} row(s){NC}")
        except Exception as e:
            printerr(f"  [{i}/{total}] {name}: {RED}failed — {e}{NC}")
            raw[name] = []

        # Rate limit: 500ms between queries
        if i < total:
            time.sleep(0.5)

    return raw


# ─── Phase 2: Data Assembly ──────────────────────────────────────────────────


def assemble_snapshot(sub_list, raw):
    """Transform flat ARG rows into the v1.2-compatible nested snapshot dict."""
    # Build lookup maps
    rt_map = {}  # route table ID (lower) → {name, routes, disableBgp}
    for rt in raw.get("route_tables", []):
        rt_id = (rt.get("id") or "").lower()
        routes_raw = rt.get("routes") or []
        routes = []
        for r in routes_raw:
            props = r.get("properties", {})
            routes.append({
                "name": r.get("name", ""),
                "prefix": props.get("addressPrefix", ""),
                "next_hop_type": props.get("nextHopType", ""),
                "next_hop_ip": props.get("nextHopIpAddress") or "",
            })
        rt_map[rt_id] = {
            "name": rt.get("name", ""),
            "routes": routes,
            "disable_bgp": bool(rt.get("disableBgp")),
        }

    nsg_map = {}  # NSG ID (lower) → {name, rg, location, customRules, defaultRules}
    for nsg in raw.get("nsgs", []):
        nsg_id = (nsg.get("id") or "").lower()
        nsg_map[nsg_id] = {
            "name": nsg.get("name", ""),
            "resource_group": nsg.get("resourceGroup", ""),
            "location": nsg.get("location", ""),
            "custom_rules": nsg.get("customRules") or [],
            "default_rules": nsg.get("defaultRules") or [],
            "subscription_id": nsg.get("subscriptionId", ""),
        }

    nic_map = {}  # NIC ID (lower) → {ipConfigs, vmId}
    for nic in raw.get("nics", []):
        nic_id = (nic.get("id") or "").lower()
        nic_map[nic_id] = {
            "name": nic.get("name", ""),
            "ip_configs": nic.get("ipConfigs") or [],
            "vm_id": nic.get("vmId") or "",
            "resource_group": nic.get("resourceGroup", ""),
            "nsg_id": (nic.get("nicNsgId") or "").lower(),
        }

    pip_map = {}  # Public IP ID (lower) → {name, ip, allocation, ipConfigId}
    for pip in raw.get("public_ips", []):
        pip_id = (pip.get("id") or "").lower()
        pip_map[pip_id] = {
            "name": pip.get("name", ""),
            "ip": pip.get("ip") or "",
            "allocation": pip.get("allocation", ""),
            "ip_config_id": (pip.get("ipConfigId") or "").lower(),
            "resource_group": pip.get("resourceGroup", ""),
            "subscription_id": pip.get("subscriptionId", ""),
        }

    # Build subscription name map
    sub_name_map = {s["id"]: s["name"] for s in sub_list}

    # Initialize subscriptions dict
    subscriptions = {}
    for s in sub_list:
        subscriptions[s["id"]] = {
            "name": s["name"],
            "vnets": {},
            "public_ips": [],
            "policies": [],
            "flow_logs": [],
            "network_watchers": [],
            "private_dns_zones": [],
            "app_services": [],
            "gaps": [],
            "nsg_analysis": [],
            "storage_accounts": [],
        }

    # ── Build VNet + Subnet hierarchy ──
    vnet_seen = set()  # track VNet IDs to avoid duplicating VNet-level data
    for row in raw.get("vnets_subnets", []):
        sub_id = row.get("subscriptionId", "")
        if sub_id not in subscriptions:
            continue

        vnet_id = row.get("vnetId", "")
        vnet_id_lower = vnet_id.lower()
        vnets = subscriptions[sub_id]["vnets"]

        # Create VNet entry if first time seen
        if vnet_id not in vnets:
            ddos_plan_id = row.get("ddosPlan") or ""
            vnets[vnet_id] = {
                "name": row.get("vnetName", ""),
                "resource_group": row.get("rg", ""),
                "location": row.get("location", ""),
                "address_space": row.get("addressSpace") or [],
                "ddos_protection": bool(row.get("ddos")),
                "ddos_plan": resource_id_name(ddos_plan_id) if ddos_plan_id else None,
                "subnets": {},
                "peerings": [],
                "gateways": [],
            }

        # Add subnet
        sn_name = row.get("subnetName", "")
        if not sn_name or sn_name in vnets[vnet_id]["subnets"]:
            continue

        # Resolve route table
        rt_id = (row.get("rtId") or "").lower()
        rt_info = rt_map.get(rt_id, {})
        rt_name = rt_info.get("name") if rt_id else None
        routes = rt_info.get("routes", []) if rt_id else []
        bgp = not rt_info.get("disable_bgp", False) if rt_id else True

        # Resolve NSG name
        nsg_id = (row.get("nsgId") or "").lower()
        nsg_name = nsg_map[nsg_id]["name"] if nsg_id and nsg_id in nsg_map else None

        # Service endpoints
        svc_eps_raw = row.get("svcEndpoints") or []
        svc_endpoints = [
            ep.get("service", "") for ep in svc_eps_raw if ep.get("service")
        ]

        # Delegations
        deleg_raw = row.get("delegations") or []
        delegations = [
            d.get("properties", {}).get("serviceName", "") or d.get("serviceName", "")
            for d in deleg_raw
        ]
        delegations = [d for d in delegations if d]

        # NAT gateway
        nat_gw_id = row.get("natGw") or ""
        nat_gw_name = resource_id_name(nat_gw_id) if nat_gw_id else None

        inet = classify_internet_access(routes)

        vnets[vnet_id]["subnets"][sn_name] = {
            "prefix": row.get("subnetPrefix") or "",
            "nsg": nsg_name,
            "route_table": rt_name,
            "routes": routes,
            "bgp_propagation": bgp,
            "internet_access": inet,
            "service_endpoints": svc_endpoints,
            "delegations": delegations,
            "nat_gateway": nat_gw_name,
            "resources": [],
        }

    # ── Attach peerings to VNets ──
    for row in raw.get("peerings", []):
        sub_id = row.get("subscriptionId", "")
        vnet_id = row.get("vnetId", "")
        if sub_id not in subscriptions:
            continue
        vnets = subscriptions[sub_id]["vnets"]
        if vnet_id not in vnets:
            continue

        remote_id = row.get("remoteVnetId") or ""
        vnets[vnet_id]["peerings"].append({
            "name": row.get("peerName", ""),
            "remote_vnet": resource_id_name(remote_id),
            "remote_vnet_id": remote_id,
            "state": row.get("state", ""),
            "allow_vnet_access": bool(row.get("allowVNetAccess")),
            "allow_forwarded_traffic": bool(row.get("allowFwdTraffic")),
            "allow_gateway_transit": bool(row.get("allowGwTransit")),
            "use_remote_gateways": bool(row.get("useRemoteGw")),
        })

    # ── Attach gateways to VNets ──
    for gw in raw.get("gateways", []):
        sub_id = gw.get("subscriptionId", "")
        subnet_id = gw.get("subnetId") or ""
        gw_vnet_id = extract_vnet_id_from_subnet(subnet_id)
        if sub_id not in subscriptions:
            continue
        vnets = subscriptions[sub_id]["vnets"]
        # Match by case-insensitive VNet ID
        matched_vnet_id = None
        for vid in vnets:
            if vid.lower() == gw_vnet_id.lower():
                matched_vnet_id = vid
                break
        if matched_vnet_id:
            vnets[matched_vnet_id]["gateways"].append({
                "name": gw.get("name", ""),
                "type": gw.get("gwType", ""),
                "vpn_type": gw.get("vpnType", ""),
                "sku": gw.get("sku", ""),
                "state": gw.get("state", ""),
            })

    # ── Map resources to subnets via NICs ──
    # Build subnet_id → (sub_id, vnet_id, sn_name) reverse lookup
    subnet_lookup = {}
    for sub_id, sub_data in subscriptions.items():
        for vnet_id, vnet in sub_data["vnets"].items():
            for sn_name in vnet["subnets"]:
                sn_full_id = f"{vnet_id}/subnets/{sn_name}".lower()
                subnet_lookup[sn_full_id] = (sub_id, vnet_id, sn_name)

    for nic_id, nic_info in nic_map.items():
        vm_id = nic_info["vm_id"]
        vm_name = resource_id_name(vm_id) if vm_id else ""
        for ip_cfg in nic_info["ip_configs"]:
            props = ip_cfg.get("properties", {})
            sn_id = (props.get("subnet", {}).get("id") or "").lower()
            if sn_id in subnet_lookup:
                sid, vid, sn_name = subnet_lookup[sn_id]
                sn = subscriptions[sid]["vnets"][vid]["subnets"][sn_name]
                if vm_name:
                    # Avoid duplicates
                    if not any(r["name"] == vm_name for r in sn["resources"]):
                        sn["resources"].append({
                            "name": vm_name,
                            "type": "VirtualMachine",
                            "resource_group": nic_info["resource_group"],
                        })

    # ── Map private endpoints to subnets ──
    for pe in raw.get("private_endpoints", []):
        sub_id = pe.get("subscriptionId", "")
        sn_id = (pe.get("subnetId") or "").lower()
        if sn_id in subnet_lookup:
            sid, vid, sn_name = subnet_lookup[sn_id]
            sn = subscriptions[sid]["vnets"][vid]["subnets"][sn_name]
            pe_name = pe.get("name", "")
            if not any(r["name"] == pe_name for r in sn["resources"]):
                sn["resources"].append({
                    "name": pe_name,
                    "type": "PrivateEndpoint",
                    "resource_group": pe.get("resourceGroup", ""),
                })

    # ── Build public IPs per subscription ──
    # Build NIC ipConfigId → (vm_name, subnet, vnet) map
    ip_config_map = {}  # ipConfigId (lower) → {vm_name, subnet, vnet}
    for nic_id, nic_info in nic_map.items():
        for ip_cfg in nic_info["ip_configs"]:
            cfg_id = (ip_cfg.get("id") or "").lower()
            props = ip_cfg.get("properties", {})
            sn_id = (props.get("subnet", {}).get("id") or "").lower()
            vm_name = resource_id_name(nic_info["vm_id"]) if nic_info["vm_id"] else ""
            nic_nsg_name = resource_id_name(nic_info["nsg_id"]) if nic_info["nsg_id"] else ""
            if sn_id in subnet_lookup:
                sid, vid, sn_name = subnet_lookup[sn_id]
                ip_config_map[cfg_id] = {
                    "vm_name": vm_name,
                    "subnet": sn_name,
                    "vnet": subscriptions[sid]["vnets"][vid]["name"],
                    "nic_nsg": nic_nsg_name,
                }
            else:
                ip_config_map[cfg_id] = {
                    "vm_name": vm_name,
                    "subnet": "",
                    "vnet": "",
                    "nic_nsg": nic_nsg_name,
                }

    for pip_id, pip_info in pip_map.items():
        sub_id = pip_info["subscription_id"]
        if sub_id not in subscriptions:
            continue

        associated_name = ""
        associated_type = ""
        vnet = ""
        subnet = ""
        nic_nsg = ""

        cfg_id = pip_info["ip_config_id"]
        if cfg_id and cfg_id in ip_config_map:
            ctx = ip_config_map[cfg_id]
            associated_name = ctx["vm_name"]
            associated_type = "VirtualMachine" if ctx["vm_name"] else ""
            vnet = ctx["vnet"]
            subnet = ctx["subnet"]
            nic_nsg = ctx.get("nic_nsg", "")

        subscriptions[sub_id]["public_ips"].append({
            "name": pip_info["name"],
            "ip": pip_info["ip"],
            "allocation": pip_info["allocation"],
            "resource_group": pip_info["resource_group"],
            "associated_type": associated_type,
            "associated_name": associated_name,
            "vnet": vnet,
            "subnet": subnet,
            "nic_nsg": nic_nsg,
        })

    # ── Policies per subscription ──
    for pol in raw.get("policies", []):
        sub_id = pol.get("subscriptionId", "")
        if sub_id not in subscriptions:
            continue
        subscriptions[sub_id]["policies"].append({
            "name": pol.get("name", ""),
            "definition_id": pol.get("definitionId", ""),
            "scope": pol.get("scope", ""),
            "enforcement": pol.get("enforcement", ""),
            "description": pol.get("description", ""),
        })

    # ── Network Watchers per subscription ──
    for w in raw.get("network_watchers", []):
        sub_id = w.get("subscriptionId", "")
        if sub_id not in subscriptions:
            continue
        subscriptions[sub_id]["network_watchers"].append({
            "name": w.get("name", ""),
            "location": w.get("location", ""),
            "state": w.get("state", ""),
        })

    # ── Flow Logs — cross-reference with NSGs ──
    # Build nsg_name (lower) → {name, region} from nsg_map
    nsg_name_info = {}  # (sub_id, nsg_name_lower) → {name, region}
    for nsg_id_l, nsg_info in nsg_map.items():
        key = (nsg_info["subscription_id"], nsg_info["name"].lower())
        nsg_name_info[key] = {
            "name": nsg_info["name"],
            "region": nsg_info["location"],
        }

    # Build flow log target map: nsg_id (lower) → flow_log_info
    fl_target_map = {}
    for fl in raw.get("flow_logs", []):
        target_id = (fl.get("targetNsgId") or "").lower()
        target_name = resource_id_name(target_id).lower()
        target_sub = resource_id_sub(target_id)
        storage_id = fl.get("storageId") or ""
        workspace_id = fl.get("workspaceId") or ""
        fl_target_map[(target_sub, target_name)] = {
            "enabled": bool(fl.get("enabled")),
            "storage_account": resource_id_name(storage_id),
            "retention_days": fl.get("retentionDays") or 0,
            "traffic_analytics_enabled": bool(fl.get("analyticsEnabled")),
            "workspace_id": resource_id_name(workspace_id) if workspace_id else "",
        }

    # For each NSG on non-system subnets, build flow log entry
    for sub_id, sub_data in subscriptions.items():
        nsgs_seen = set()
        for vnet_id, vnet in sub_data["vnets"].items():
            for sn_name, sn in vnet["subnets"].items():
                if sn_name in SYSTEM_SUBNETS:
                    continue
                nsg_name = sn.get("nsg")
                if not nsg_name:
                    continue
                nsg_key = nsg_name.lower()
                if nsg_key in nsgs_seen:
                    continue
                nsgs_seen.add(nsg_key)

                nsg_info_entry = nsg_name_info.get((sub_id, nsg_key), {})
                fl_info = fl_target_map.get((sub_id, nsg_key))

                entry = {
                    "nsg_name": nsg_name,
                    "nsg_region": nsg_info_entry.get("region", ""),
                }
                if fl_info:
                    entry.update(fl_info)
                else:
                    entry.update({
                        "enabled": False,
                        "storage_account": "",
                        "retention_days": 0,
                        "traffic_analytics_enabled": False,
                        "workspace_id": "",
                    })
                sub_data["flow_logs"].append(entry)

    # ── Private DNS Zones + VNet Links ──
    # Group links by (subscriptionId, zoneName, zoneRg)
    zone_links = {}  # (sub, zone_name, zone_rg) → [link_entries]
    for link in raw.get("private_dns_links", []):
        sub_id = link.get("subscriptionId", "")
        zone_name = link.get("zoneName", "")
        zone_rg = link.get("zoneRg", "")
        key = (sub_id, zone_name.lower(), zone_rg.lower())
        if key not in zone_links:
            zone_links[key] = []
        vnet_id = link.get("vnetId") or ""
        zone_links[key].append({
            "name": link.get("linkName", ""),
            "vnet_id": vnet_id,
            "vnet_name": resource_id_name(vnet_id),
            "registration_enabled": bool(link.get("registrationEnabled")),
        })

    for zone in raw.get("private_dns_zones", []):
        sub_id = zone.get("subscriptionId", "")
        if sub_id not in subscriptions:
            continue
        zone_name = zone.get("name", "")
        zone_rg = zone.get("resourceGroup", "")
        key = (sub_id, zone_name.lower(), zone_rg.lower())
        links = zone_links.get(key, [])
        subscriptions[sub_id]["private_dns_zones"].append({
            "name": zone_name,
            "resource_group": zone_rg,
            "record_count": zone.get("recordCount") or 0,
            "vnet_links": links,
        })

    # ── App Services (base data from ARG — verdict computed after REST enrichment) ──
    for app in raw.get("app_services", []):
        sub_id = app.get("subscriptionId", "")
        if sub_id not in subscriptions:
            continue
        vnet_sub_id = app.get("vnetSubnetId") or ""
        subscriptions[sub_id]["app_services"].append({
            "name": app.get("name", ""),
            "resource_group": app.get("resourceGroup", ""),
            "kind": app.get("kind", "app"),
            "location": app.get("location", ""),
            "https_only": bool(app.get("httpsOnly")),
            "min_tls_version": "1.0",  # Will be enriched by REST
            "public_network_access": app.get("publicNetworkAccess") or "Enabled",
            "vnet_integration": resource_id_name(vnet_sub_id) if vnet_sub_id else "",
            "private_endpoints": app.get("peCount") or 0,
            "ip_restrictions_count": 0,  # Will be enriched
            "has_ip_restrictions": False,  # Will be enriched
            "verdict": "PENDING",  # Will be computed after enrichment
            "details": "",
        })

    # ── Storage Accounts (base data from ARG — verdict after REST enrichment) ──
    for sa in raw.get("storage_accounts", []):
        sub_id = sa.get("subscriptionId", "")
        if sub_id not in subscriptions:
            continue
        subscriptions[sub_id]["storage_accounts"].append({
            "name": sa.get("name", ""),
            "resource_group": sa.get("resourceGroup", ""),
            "kind": sa.get("kind", ""),
            "subscription": sub_name_map.get(sub_id, ""),
            "public_network_access": sa.get("publicNetworkAccess") or "Enabled",
            "allow_blob_public": sa.get("allowBlobPublicAccess"),
            "https_only": bool(sa.get("httpsOnly", True)),
            "private_endpoints": sa.get("peCount") or 0,
            "default_action": sa.get("defaultAction") or "Allow",
            "ip_rules": sa.get("ipRulesCount") or 0,
            "vnet_rules": sa.get("vnetRulesCount") or 0,
            "public_containers": 0,  # Will be enriched
            "static_website": False,  # Will be enriched
            "verdict": "PENDING",  # Will be computed after enrichment
            "details": "",
        })

    # ── NSG Analysis ──
    _build_nsg_analysis(subscriptions, nsg_map)

    return subscriptions


def _build_nsg_analysis(subscriptions, nsg_map):
    """Build NSG rule analysis for non-firewalled subnets, using ARG-fetched rules."""

    def _compute_verdict(rules, direction):
        custom_deny = 0
        custom_restrict = 0
        custom_count = 0
        for r in rules:
            if r["is_default"]:
                continue
            custom_count += 1
            if r["access"] == "Deny":
                custom_deny += 1
            elif r["access"] == "Allow":
                addr = r["dest_address"] if direction == "Outbound" else r["source_address"]
                if addr not in ("*", "0.0.0.0/0"):
                    custom_restrict += 1

        if custom_deny > 0:
            verdict = "Has custom DENY"
        elif custom_restrict > 0:
            verdict = "Has restrictive ALLOW"
        elif custom_count > 0:
            verdict = f"Has {custom_count} custom rules but no deny"
        else:
            verdict = "DEFAULT ONLY"
        return verdict, custom_deny, custom_restrict

    def _parse_rules(raw_rules, direction_filter=None):
        """Parse ARG rule objects into our standard format."""
        parsed = []
        for r in (raw_rules or []):
            props = r.get("properties", {})
            prio = props.get("priority", 0)
            direction = props.get("direction", "")
            if direction_filter and direction != direction_filter:
                continue
            parsed.append({
                "name": r.get("name", ""),
                "direction": direction,
                "priority": prio,
                "access": props.get("access", ""),
                "protocol": props.get("protocol", ""),
                "source_address": props.get("sourceAddressPrefix", "") or props.get("sourceAddressPrefixes", [""])[0] if isinstance(props.get("sourceAddressPrefixes"), list) and props.get("sourceAddressPrefixes") else props.get("sourceAddressPrefix", ""),
                "source_port": props.get("sourcePortRange", "") or "*",
                "dest_address": props.get("destinationAddressPrefix", "") or props.get("destinationAddressPrefixes", [""])[0] if isinstance(props.get("destinationAddressPrefixes"), list) and props.get("destinationAddressPrefixes") else props.get("destinationAddressPrefix", ""),
                "dest_port": props.get("destinationPortRange", "") or "*",
                "is_default": prio >= 65000,
            })
        return parsed

    for sub_id, sub_data in subscriptions.items():
        nsgs_to_check = {}  # nsg_name → nsg_id (lower)
        for vnet_id, vnet in sub_data["vnets"].items():
            for sn_name, sn in vnet["subnets"].items():
                if sn_name in SYSTEM_SUBNETS:
                    continue
                has_fw = any(r.get("next_hop_type") == "VirtualAppliance" for r in sn["routes"])
                if not has_fw and sn["nsg"]:
                    nsg_name = sn["nsg"]
                    if nsg_name not in nsgs_to_check:
                        # Find NSG ID from nsg_map
                        for nsg_id_l, nsg_info in nsg_map.items():
                            if (nsg_info["name"] == nsg_name and
                                    nsg_info["subscription_id"] == sub_id):
                                nsgs_to_check[nsg_name] = nsg_id_l
                                break

        for nsg_name, nsg_id_l in nsgs_to_check.items():
            nsg_info = nsg_map.get(nsg_id_l, {})
            custom_rules = nsg_info.get("custom_rules", [])
            default_rules = nsg_info.get("default_rules", [])
            all_raw = custom_rules + default_rules

            outbound_rules = _parse_rules(all_raw, "Outbound")
            inbound_rules = _parse_rules(all_raw, "Inbound")

            out_v, out_deny, out_restrict = _compute_verdict(outbound_rules, "Outbound")
            in_v, in_deny, in_restrict = _compute_verdict(inbound_rules, "Inbound")

            sub_data["nsg_analysis"].append({
                "nsg": nsg_name,
                "resource_group": nsg_info.get("resource_group", ""),
                "outbound_verdict": out_v,
                "outbound_custom_deny_count": out_deny,
                "outbound_custom_restrict_count": out_restrict,
                "inbound_verdict": in_v,
                "inbound_custom_deny_count": in_deny,
                "inbound_custom_restrict_count": in_restrict,
                "outbound_rules": outbound_rules,
                "inbound_rules": inbound_rules,
            })


# ─── Phase 3: REST Enrichment ────────────────────────────────────────────────


def enrich_with_rest(client, subscriptions):
    """Enrich app services and storage accounts with data ARG doesn't expose."""
    tasks = []

    # Collect app service enrichment tasks
    for sub_id, sub_data in subscriptions.items():
        for i, app in enumerate(sub_data["app_services"]):
            if app["public_network_access"] == "Disabled":
                continue
            tasks.append(("app", sub_id, i, app["resource_group"], app["name"]))

    # Collect storage enrichment tasks
    for sub_id, sub_data in subscriptions.items():
        for i, sa in enumerate(sub_data["storage_accounts"]):
            if sa["public_network_access"] == "Disabled":
                continue
            tasks.append(("storage", sub_id, i, sa["resource_group"], sa["name"]))

    if not tasks:
        _compute_all_verdicts(subscriptions)
        return

    printerr(f"  Enriching {len(tasks)} resource(s) via REST API...")

    def _do_enrich(task):
        kind, sub_id, idx, rg, name = task
        if kind == "app":
            return _enrich_app(client, sub_id, rg, name)
        else:
            return _enrich_storage(client, sub_id, rg, name)

    results = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        future_map = {pool.submit(_do_enrich, t): t for t in tasks}
        for future in as_completed(future_map):
            task = future_map[future]
            try:
                results[task] = future.result()
            except Exception:
                results[task] = None

    # Merge results back
    for task, result in results.items():
        kind, sub_id, idx, rg, name = task
        if result is None:
            continue

        if kind == "app":
            app = subscriptions[sub_id]["app_services"][idx]
            app["ip_restrictions_count"] = result.get("ip_restrictions_count", 0)
            app["has_ip_restrictions"] = result.get("has_ip_restrictions", False)
            app["min_tls_version"] = result.get("min_tls_version", "1.0")
        else:
            sa = subscriptions[sub_id]["storage_accounts"][idx]
            sa["public_containers"] = result.get("public_containers", 0)
            sa["static_website"] = result.get("static_website", False)

    _compute_all_verdicts(subscriptions)


def _enrich_app(client, sub_id, rg, name):
    """Fetch App Service site config for IP restrictions and TLS version."""
    url = (
        f"{ARM_BASE}/subscriptions/{sub_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.Web/sites/{name}/config/web"
    )
    data = client.arm_get(url, api_version="2023-12-01")
    props = data.get("properties", {})

    ip_rules = props.get("ipSecurityRestrictions") or []
    tls_ver = props.get("minTlsVersion") or "1.0"

    # Check for real IP restrictions (not just default allow-all)
    real_rules = [
        r for r in ip_rules
        if r.get("priority") not in (2147483647, None)
        and r.get("ipAddress") != "Any"
    ]

    return {
        "ip_restrictions_count": len(ip_rules),
        "has_ip_restrictions": len(real_rules) > 0,
        "min_tls_version": tls_ver,
    }


def _enrich_storage(client, sub_id, rg, name):
    """Fetch storage container public access and static website status."""
    containers_url = (
        f"{ARM_BASE}/subscriptions/{sub_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.Storage/storageAccounts/{name}"
        f"/blobServices/default/containers"
    )
    blob_url = (
        f"{ARM_BASE}/subscriptions/{sub_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.Storage/storageAccounts/{name}"
        f"/blobServices/default"
    )

    containers_data = client.arm_get(containers_url)
    blob_data = client.arm_get(blob_url)

    public_containers = 0
    for c in containers_data.get("value", []):
        access = c.get("properties", {}).get("publicAccess")
        if access and access != "None":
            public_containers += 1

    static_website = (
        blob_data.get("properties", {}).get("staticWebsite", {}).get("enabled", False)
    )

    return {
        "public_containers": public_containers,
        "static_website": bool(static_website),
    }


def _compute_all_verdicts(subscriptions):
    """Compute verdicts for all app services and storage accounts."""
    for sub_id, sub_data in subscriptions.items():
        # App service verdicts
        for app in sub_data["app_services"]:
            pub_access = app.get("public_network_access", "Enabled")
            pe_count = app.get("private_endpoints", 0)
            has_restrictions = app.get("has_ip_restrictions", False)

            if pub_access == "Disabled" and pe_count > 0:
                app["verdict"] = "PRIVATE_ONLY"
                app["details"] = f"Public access disabled, {pe_count} private endpoint(s)"
            elif pub_access == "Disabled":
                app["verdict"] = "RESTRICTED"
                app["details"] = "Public access disabled (no private endpoints)"
            elif has_restrictions:
                app["verdict"] = "RESTRICTED"
                app["details"] = f"Has IP restrictions ({app.get('ip_restrictions_count', 0)} rule(s))"
            elif pe_count > 0:
                app["verdict"] = "RESTRICTED"
                app["details"] = f"Publicly accessible but has {pe_count} private endpoint(s)"
            else:
                app["verdict"] = "EXPOSED"
                app["details"] = "Publicly accessible, no IP restrictions, no private endpoints"

        # Storage verdicts
        for sa in sub_data["storage_accounts"]:
            pub_access = sa.get("public_network_access", "Enabled")
            pe_count = sa.get("private_endpoints", 0)
            default_action = sa.get("default_action", "Allow")
            ip_rules = sa.get("ip_rules", 0)
            vnet_rules = sa.get("vnet_rules", 0)
            public_containers = sa.get("public_containers", 0)
            static_website = sa.get("static_website", False)

            if pub_access == "Disabled":
                sa["verdict"] = "ALREADY_DISABLED"
                sa["details"] = "Public network access already disabled"
            elif static_website:
                sa["verdict"] = "RISKY"
                sa["details"] = "Static website is enabled — would go offline"
            elif public_containers > 0:
                sa["verdict"] = "RISKY"
                sa["details"] = f"{public_containers} public container(s)"
            elif pe_count == 0 and ip_rules == 0 and vnet_rules == 0:
                sa["verdict"] = "BLOCKED"
                sa["details"] = "No private endpoints and no firewall rules"
            elif pe_count > 0 and default_action == "Deny":
                sa["verdict"] = "LIKELY_SAFE"
                sa["details"] = f"{pe_count} PE(s) + firewall defaultAction=Deny"
            elif pe_count > 0 and default_action == "Allow":
                sa["verdict"] = "REVIEW"
                sa["details"] = f"{pe_count} PE(s) but defaultAction=Allow"
            else:
                sa["verdict"] = "REVIEW"
                sa["details"] = f"No PEs, firewall rules (IP:{ip_rules} VNet:{vnet_rules})"


# ─── Phase 4: Validation (Gap Analysis) ──────────────────────────────────────


def run_validation(snapshot_subs):
    """Run all 13 gap types + cross-subscription checks."""
    # Per-subscription gaps
    all_firewall_maps = {}
    for sub_id, sub_data in snapshot_subs.items():
        gaps, fw_map = _analyze_gaps(sub_id, sub_data["name"], sub_data["vnets"])
        sub_data["gaps"] = gaps
        all_firewall_maps.update(fw_map)

    # Peering gaps (cross-subscription)
    for sub_id, sub_data in snapshot_subs.items():
        peering_gaps = _analyze_peering_gaps(
            sub_id, sub_data["name"], sub_data["vnets"], all_firewall_maps,
        )
        sub_data["gaps"].extend(peering_gaps)

    # Flow log gaps
    for sub_id, sub_data in snapshot_subs.items():
        flow_logs = sub_data.get("flow_logs", [])
        watchers = sub_data.get("network_watchers", [])

        watcher_regions = {
            w["location"].lower() for w in watchers if w.get("state") == "Succeeded"
        }
        nsg_regions = set()
        for fl in flow_logs:
            region = fl.get("nsg_region", "").lower()
            if region:
                nsg_regions.add(region)

        for region in nsg_regions - watcher_regions:
            region_nsg_count = sum(1 for fl in flow_logs if fl.get("nsg_region", "").lower() == region)
            sub_data["gaps"].append({
                "type": "NETWORK-WATCHER-DISABLED",
                "severity": "MEDIUM",
                "vnet": "", "subnet": "", "subnet_prefix": "",
                "has_nsg": False, "has_route_table": False,
                "has_firewall_route": False, "internet_access": "",
                "detail": f"Network Watcher disabled in {region} — {region_nsg_count} NSG(s) cannot have flow logs",
            })

        for fl in flow_logs:
            if not fl.get("enabled"):
                sub_data["gaps"].append({
                    "type": "FLOW-LOGS-DISABLED",
                    "severity": "MEDIUM",
                    "vnet": "", "subnet": "", "subnet_prefix": "",
                    "has_nsg": True, "has_route_table": False,
                    "has_firewall_route": False, "internet_access": "",
                    "detail": f"NSG {fl['nsg_name']} has no active flow logs — traffic is unmonitored",
                })

    # Inbound NSG gap: INBOUND-ANY-ALLOW
    for sub_id, sub_data in snapshot_subs.items():
        for nsg in sub_data.get("nsg_analysis", []):
            for rule in nsg.get("inbound_rules", []):
                if rule.get("is_default"):
                    continue
                if rule.get("access") != "Allow":
                    continue
                src = rule.get("source_address", "")
                if src not in WIDE_OPEN_SOURCES:
                    continue
                dst_port = rule.get("dest_port", "")
                is_wide = dst_port in ("*", "0-65535") or dst_port in HIGH_RISK_INBOUND_PORTS
                if not is_wide:
                    continue
                sub_data["gaps"].append({
                    "type": "INBOUND-ANY-ALLOW",
                    "severity": "HIGH",
                    "vnet": "", "subnet": "", "subnet_prefix": "",
                    "has_nsg": True, "has_route_table": False,
                    "has_firewall_route": False, "internet_access": "",
                    "detail": f"NSG {nsg['nsg']} rule '{rule['name']}' allows inbound from {src} to port {dst_port}",
                })

    # Private DNS gap: PRIVATE-DNS-MISSING (cross-subscription)
    dns_linked_vnets = set()
    for sub_id, sub_data in snapshot_subs.items():
        for zone in sub_data.get("private_dns_zones", []):
            if zone["name"].startswith("privatelink."):
                for link in zone.get("vnet_links", []):
                    vnet_id = link.get("vnet_id", "")
                    if vnet_id:
                        dns_linked_vnets.add(vnet_id.lower())

    for sub_id, sub_data in snapshot_subs.items():
        for vnet_id, vnet in sub_data.get("vnets", {}).items():
            pe_count = 0
            for sn in vnet["subnets"].values():
                pe_count += sum(1 for r in sn.get("resources", []) if r.get("type") == "PrivateEndpoint")
            if pe_count > 0 and vnet_id.lower() not in dns_linked_vnets:
                sub_data["gaps"].append({
                    "type": "PRIVATE-DNS-MISSING",
                    "severity": "HIGH",
                    "vnet": vnet["name"], "subnet": "", "subnet_prefix": "",
                    "has_nsg": False, "has_route_table": False,
                    "has_firewall_route": False, "internet_access": "",
                    "detail": f"VNet {vnet['name']} has {pe_count} private endpoint(s) but no privatelink DNS zone links",
                })

    # App Service gaps
    for sub_id, sub_data in snapshot_subs.items():
        for app in sub_data.get("app_services", []):
            kind_label = app.get("kind", "app")
            app_name = app["name"]

            if app.get("verdict") == "EXPOSED":
                https_status = "HTTPS enforced" if app.get("https_only") else "NO HTTPS"
                tls_status = f"TLS {app.get('min_tls_version', '?')}"
                sub_data["gaps"].append({
                    "type": "APP-PUBLIC-EXPOSED",
                    "severity": "HIGH",
                    "vnet": "", "subnet": "", "subnet_prefix": "",
                    "has_nsg": False, "has_route_table": False,
                    "has_firewall_route": False, "internet_access": "",
                    "detail": f"{app_name} ({kind_label}) is publicly accessible with no IP restrictions — {https_status}, {tls_status}",
                })

            if app.get("verdict") != "PRIVATE_ONLY" and not app.get("https_only"):
                sub_data["gaps"].append({
                    "type": "APP-NO-HTTPS",
                    "severity": "MEDIUM",
                    "vnet": "", "subnet": "", "subnet_prefix": "",
                    "has_nsg": False, "has_route_table": False,
                    "has_firewall_route": False, "internet_access": "",
                    "detail": f"{app_name} ({kind_label}) does not enforce HTTPS redirect",
                })

            tls_ver = app.get("min_tls_version", "1.0")
            if app.get("verdict") != "PRIVATE_ONLY" and tls_ver < "1.2":
                sub_data["gaps"].append({
                    "type": "APP-WEAK-TLS",
                    "severity": "MEDIUM",
                    "vnet": "", "subnet": "", "subnet_prefix": "",
                    "has_nsg": False, "has_route_table": False,
                    "has_firewall_route": False, "internet_access": "",
                    "detail": f"{app_name} ({kind_label}) allows TLS {tls_ver} (minimum 1.2 recommended)",
                })

    # VM + Public IP + No NSG gap analysis: VM-PUBLIC-NO-NSG
    for sub_id, sub_data in snapshot_subs.items():
        for pip in sub_data.get("public_ips", []):
            if pip.get("associated_type") != "VirtualMachine":
                continue
            if pip.get("nic_nsg"):
                continue  # NIC has an NSG -- OK
            # Check if the subnet has an NSG
            pip_vnet = pip.get("vnet", "")
            pip_subnet = pip.get("subnet", "")
            subnet_has_nsg = False
            for vnet_id, vnet in sub_data.get("vnets", {}).items():
                if vnet["name"] == pip_vnet:
                    sn = vnet["subnets"].get(pip_subnet, {})
                    if sn.get("nsg"):
                        subnet_has_nsg = True
                    break
            if not subnet_has_nsg:
                ip_addr = pip.get("ip", "unassigned")
                vm_name = pip.get("associated_name", "")
                sub_data["gaps"].append({
                    "type": "VM-PUBLIC-NO-NSG",
                    "severity": "HIGH",
                    "vnet": pip_vnet,
                    "subnet": pip_subnet,
                    "subnet_prefix": "",
                    "has_nsg": False,
                    "has_route_table": False,
                    "has_firewall_route": False,
                    "internet_access": "",
                    "detail": f"VM '{vm_name}' has public IP {ip_addr} but neither its NIC nor subnet '{pip_subnet}' has an NSG",
                })

    # Storage HTTPS gap analysis: STORAGE-HTTP-ALLOWED
    for sub_id, sub_data in snapshot_subs.items():
        for sa in sub_data.get("storage_accounts", []):
            if sa.get("public_network_access") == "Disabled":
                continue
            if sa.get("verdict") in ("PENDING", "ACCESS_DENIED"):
                continue
            if not sa.get("https_only", True):
                sub_data["gaps"].append({
                    "type": "STORAGE-HTTP-ALLOWED",
                    "severity": "MEDIUM",
                    "vnet": "", "subnet": "", "subnet_prefix": "",
                    "has_nsg": False, "has_route_table": False,
                    "has_firewall_route": False, "internet_access": "",
                    "detail": f"Storage account '{sa['name']}' allows unencrypted HTTP traffic (HTTPS not enforced)",
                })


def _analyze_gaps(sub_id, sub_name, vnets):
    """Analyze per-subnet security gaps. Returns (gaps_list, vnet_firewall_map)."""
    gaps = []
    vnet_firewall_map = {}

    for vnet_id, vnet in vnets.items():
        vnet_name = vnet["name"]
        vnet_rg = vnet["resource_group"]
        vnet_key = f"{sub_id}/{vnet_rg}/{vnet_name}"
        vnet_has_fw = False

        for sn_name, sn in vnet["subnets"].items():
            if sn_name in SYSTEM_SUBNETS:
                continue

            has_nsg = sn["nsg"] is not None
            has_rt = sn["route_table"] is not None
            has_fw = any(r.get("next_hop_type") == "VirtualAppliance" for r in sn["routes"])
            inet = sn["internet_access"]

            if has_fw:
                vnet_has_fw = True

            if not has_fw and not has_nsg:
                gaps.append({
                    "type": "NO-FIREWALL-NO-NSG", "severity": "CRITICAL",
                    "vnet": vnet_name, "subnet": sn_name,
                    "subnet_prefix": sn.get("prefix", ""),
                    "has_nsg": False, "has_route_table": has_rt,
                    "has_firewall_route": False, "internet_access": inet,
                    "detail": "No firewall routing AND no NSG — subnet is unprotected",
                })

            if inet == "Direct":
                detail = (
                    "No route table — Azure default internet routing"
                    if not has_rt
                    else "Route table present but no 0.0.0.0/0 → VirtualAppliance"
                )
                gaps.append({
                    "type": "DIRECT-INTERNET", "severity": "HIGH",
                    "vnet": vnet_name, "subnet": sn_name,
                    "subnet_prefix": sn.get("prefix", ""),
                    "has_nsg": has_nsg, "has_route_table": has_rt,
                    "has_firewall_route": False, "internet_access": inet,
                    "detail": detail,
                })

            if not has_nsg:
                gaps.append({
                    "type": "NO-NSG", "severity": "MEDIUM",
                    "vnet": vnet_name, "subnet": sn_name,
                    "subnet_prefix": sn.get("prefix", ""),
                    "has_nsg": False, "has_route_table": has_rt,
                    "has_firewall_route": has_fw, "internet_access": inet,
                    "detail": "No NSG attached — no network-level ACL filtering",
                })

            svc_eps = sn.get("service_endpoints", [])
            if has_fw and svc_eps:
                svc_list = ", ".join(svc_eps)
                gaps.append({
                    "type": "SERVICE-ENDPOINT-BYPASS", "severity": "MEDIUM",
                    "vnet": vnet_name, "subnet": sn_name,
                    "subnet_prefix": sn.get("prefix", ""),
                    "has_nsg": has_nsg, "has_route_table": has_rt,
                    "has_firewall_route": True, "internet_access": inet,
                    "detail": f"{svc_list} bypass firewall via service endpoints",
                })

        vnet_firewall_map[vnet_key] = vnet_has_fw

    return gaps, vnet_firewall_map


def _analyze_peering_gaps(sub_id, sub_name, vnets, all_firewall_maps):
    """Analyze peering-related gaps (asymmetry, forwarded traffic risk)."""
    gaps = []
    for vnet_id, vnet in vnets.items():
        vnet_name = vnet["name"]
        vnet_rg = vnet["resource_group"]
        vnet_key = f"{sub_id}/{vnet_rg}/{vnet_name}"
        local_fw = all_firewall_maps.get(vnet_key, False)

        for peer in vnet.get("peerings", []):
            if peer.get("state") != "Connected":
                continue

            remote_id = peer.get("remote_vnet_id", "")
            remote_vnet = peer.get("remote_vnet", "")
            remote_rg = resource_id_rg(remote_id)
            remote_sub = resource_id_sub(remote_id)
            remote_key = f"{remote_sub}/{remote_rg}/{remote_vnet}"

            remote_fw = all_firewall_maps.get(remote_key)

            if remote_fw is not None:
                if local_fw and not remote_fw:
                    gaps.append({
                        "type": "PEERING-ASYMMETRY", "severity": "HIGH",
                        "vnet": vnet_name, "subnet": "", "subnet_prefix": "",
                        "has_nsg": False, "has_route_table": False,
                        "has_firewall_route": False, "internet_access": "",
                        "detail": f"{vnet_name} has firewall routing but peered {remote_vnet} does not",
                    })
                elif not local_fw and remote_fw:
                    gaps.append({
                        "type": "PEERING-ASYMMETRY", "severity": "HIGH",
                        "vnet": vnet_name, "subnet": "", "subnet_prefix": "",
                        "has_nsg": False, "has_route_table": False,
                        "has_firewall_route": False, "internet_access": "",
                        "detail": f"{vnet_name} has NO firewall routing but peered {remote_vnet} does",
                    })

            if peer.get("allow_forwarded_traffic") and not local_fw:
                gaps.append({
                    "type": "FORWARDED-TRAFFIC-RISK", "severity": "HIGH",
                    "vnet": vnet_name, "subnet": "", "subnet_prefix": "",
                    "has_nsg": False, "has_route_table": False,
                    "has_firewall_route": False, "internet_access": "",
                    "detail": f"Peering {peer['name']} allows forwarded traffic into {vnet_name} which has no firewall routing",
                })

    return gaps


# ─── Snapshot Orchestrator ────────────────────────────────────────────────────


def take_snapshot():
    """Orchestrate all phases and write snapshot JSON."""
    start_time = time.time()

    printerr(f"\n{BOLD}Azure Network Auditor v{VERSION} — Resource Graph Edition{NC}")
    printerr(f"{BOLD}{'=' * 52}{NC}\n")

    # Init client
    printerr(f"{CYAN}Initializing Azure client...{NC}")
    client = AzureClient()

    # Get subscriptions
    printerr(f"{CYAN}Enumerating subscriptions...{NC}")
    subs = client.get_subscriptions()
    if not subs:
        printerr("No accessible subscriptions found.")
        sys.exit(0)

    sub_ids = [s["id"] for s in subs]
    printerr(f"Found {GREEN}{len(subs)}{NC} enabled subscription(s)\n")

    # Phase 1: Discovery (Resource Graph)
    printerr(f"{BOLD}[Phase 1/4] Discovering resources via Resource Graph...{NC}\n")
    raw = run_discovery(client, sub_ids)

    # Phase 2: Assembly
    printerr(f"\n{BOLD}[Phase 2/4] Assembling snapshot data...{NC}")
    subscriptions = assemble_snapshot(subs, raw)

    # Count what we got
    total_vnets = sum(len(s["vnets"]) for s in subscriptions.values())
    total_subnets = sum(
        len(v["subnets"]) for s in subscriptions.values() for v in s["vnets"].values()
    )
    total_nsgs = sum(len(s["nsg_analysis"]) for s in subscriptions.values())
    printerr(
        f"  {total_vnets} VNet(s), {total_subnets} subnet(s), {total_nsgs} NSG(s)"
    )

    # Phase 3: REST Enrichment
    printerr(f"\n{BOLD}[Phase 3/4] Enriching with REST API calls...{NC}")
    enrich_with_rest(client, subscriptions)

    # Phase 4: Validation
    printerr(f"\n{BOLD}[Phase 4/4] Running validation and gap analysis...{NC}")
    run_validation(subscriptions)

    # Gap summary
    all_gaps = []
    for sub_data in subscriptions.values():
        all_gaps.extend(sub_data["gaps"])

    gap_counts = {}
    for g in all_gaps:
        sev = g["severity"]
        gap_counts[sev] = gap_counts.get(sev, 0) + 1

    printerr(
        f"  Gap analysis: {RED}{gap_counts.get('CRITICAL', 0)} CRITICAL{NC}, "
        f"{RED}{gap_counts.get('HIGH', 0)} HIGH{NC}, "
        f"{YELLOW}{gap_counts.get('MEDIUM', 0)} MEDIUM{NC}"
    )

    outbound_default_only = sum(
        1 for s in subscriptions.values()
        for n in s["nsg_analysis"] if n.get("outbound_verdict") == "DEFAULT ONLY"
    )
    inbound_default_only = sum(
        1 for s in subscriptions.values()
        for n in s["nsg_analysis"] if n.get("inbound_verdict") == "DEFAULT ONLY"
    )
    printerr(
        f"  NSG analysis: {total_nsgs} NSG(s), "
        f"{outbound_default_only} outbound DEFAULT-ONLY, "
        f"{inbound_default_only} inbound DEFAULT-ONLY"
    )

    total_apps = sum(len(s.get("app_services", [])) for s in subscriptions.values())
    apps_exposed = sum(
        1 for s in subscriptions.values()
        for a in s.get("app_services", []) if a.get("verdict") == "EXPOSED"
    )
    if total_apps:
        printerr(f"  App Services: {total_apps} app(s), {RED}{apps_exposed} exposed{NC}")

    total_flow_logs = sum(len(s.get("flow_logs", [])) for s in subscriptions.values())
    flow_disabled = sum(
        1 for s in subscriptions.values()
        for fl in s.get("flow_logs", []) if not fl.get("enabled")
    )
    if total_flow_logs:
        printerr(f"  Flow logs: {total_flow_logs} NSG(s) checked, {flow_disabled} without flow logs")

    total_dns = sum(len(s.get("private_dns_zones", [])) for s in subscriptions.values())
    if total_dns:
        printerr(f"  Private DNS: {total_dns} zone(s)")

    # Write snapshot
    duration = int(time.time() - start_time)
    snapshot = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_version": f"{VERSION}-rg",
            "subscriptions_scanned": len(subscriptions),
            "skipped_subscriptions": [],
            "duration_seconds": duration,
        },
        "subscriptions": subscriptions,
    }

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"snapshot-{timestamp}.json"

    printerr(f"\nWriting snapshot...")
    with open(filename, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    file_size = os.path.getsize(filename)
    size_str = f"{file_size / 1024 / 1024:.1f} MB" if file_size > 1024 * 1024 else f"{file_size / 1024:.0f} KB"

    printerr(f"  → {BOLD}{filename}{NC} ({size_str})")

    mins, secs = divmod(duration, 60)
    printerr(
        f"\n{GREEN}Done{NC} in {mins}m {secs}s. "
        f"{len(subscriptions)} subscription(s), "
        f"{total_vnets} VNet(s), {total_subnets} subnet(s)."
    )

    return filename


# ─── Diff Engine (identical to v1.2) ─────────────────────────────────────────


def find_snapshots():
    snapshots = []
    for f in os.listdir("."):
        m = SNAPSHOT_PATTERN.match(f)
        if m:
            snapshots.append((f, m.group(1)))
    snapshots.sort(key=lambda x: x[1])
    return snapshots


def load_snapshot(path):
    with open(path) as f:
        return json.load(f)


def _count_items(snapshot):
    counts = {
        "subscriptions": len(snapshot.get("subscriptions", {})),
        "vnets": 0, "subnets": 0, "nsgs": 0, "route_tables": 0,
        "peerings": 0, "gateways": 0, "public_ips": 0, "policies": 0,
        "gaps": 0, "resources": 0, "nsg_analysis": 0, "storage": 0,
        "flow_logs": 0, "private_dns": 0, "app_services": 0,
    }
    nsg_set = set()
    rt_set = set()
    for sub_id, sub in snapshot.get("subscriptions", {}).items():
        counts["public_ips"] += len(sub.get("public_ips", []))
        counts["policies"] += len(sub.get("policies", []))
        counts["gaps"] += len(sub.get("gaps", []))
        counts["nsg_analysis"] += len(sub.get("nsg_analysis", []))
        counts["storage"] += len(sub.get("storage_accounts", []))
        counts["flow_logs"] += len(sub.get("flow_logs", []))
        counts["private_dns"] += len(sub.get("private_dns_zones", []))
        counts["app_services"] += len(sub.get("app_services", []))
        for vnet_id, vnet in sub.get("vnets", {}).items():
            counts["vnets"] += 1
            counts["peerings"] += len(vnet.get("peerings", []))
            counts["gateways"] += len(vnet.get("gateways", []))
            for sn_name, sn in vnet.get("subnets", {}).items():
                counts["subnets"] += 1
                counts["resources"] += len(sn.get("resources", []))
                if sn.get("nsg"):
                    nsg_set.add(sn["nsg"])
                if sn.get("route_table"):
                    rt_set.add(sn["route_table"])
    counts["nsgs"] = len(nsg_set)
    counts["route_tables"] = len(rt_set)
    return counts


def diff_snapshots(old, new):
    diff = {
        "old_timestamp": old.get("metadata", {}).get("timestamp", ""),
        "new_timestamp": new.get("metadata", {}).get("timestamp", ""),
        "old_counts": _count_items(old),
        "new_counts": _count_items(new),
        "categories": {},
    }

    diff["categories"]["subscriptions"] = _diff_simple_keys(
        set(old.get("subscriptions", {}).keys()),
        set(new.get("subscriptions", {}).keys()),
        lambda k: old["subscriptions"][k].get("name", k),
        lambda k: new["subscriptions"][k].get("name", k),
    )

    # VNets
    old_vnets, new_vnets = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for vnet_id, vnet in sub.get("vnets", {}).items():
            old_vnets[f"{sub.get('name', sub_id)} / {vnet['name']}"] = vnet
    for sub_id, sub in new.get("subscriptions", {}).items():
        for vnet_id, vnet in sub.get("vnets", {}).items():
            new_vnets[f"{sub.get('name', sub_id)} / {vnet['name']}"] = vnet
    diff["categories"]["vnets"] = _diff_dicts(old_vnets, new_vnets, _vnet_summary, ["address_space", "ddos_protection"])

    # Subnets
    old_sn, new_sn = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for vnet_id, vnet in sub.get("vnets", {}).items():
            for sn_name, sn in vnet.get("subnets", {}).items():
                old_sn[f"{sub.get('name', sub_id)} / {vnet['name']} / {sn_name}"] = sn
    for sub_id, sub in new.get("subscriptions", {}).items():
        for vnet_id, vnet in sub.get("vnets", {}).items():
            for sn_name, sn in vnet.get("subnets", {}).items():
                new_sn[f"{sub.get('name', sub_id)} / {vnet['name']} / {sn_name}"] = sn
    diff["categories"]["subnets"] = _diff_dicts(
        old_sn, new_sn, _subnet_summary,
        ["nsg", "route_table", "internet_access", "prefix", "service_endpoints", "delegations", "nat_gateway"]
    )

    # Routes
    old_r, new_r = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for vid, vnet in sub.get("vnets", {}).items():
            for sn, s in vnet.get("subnets", {}).items():
                for r in s.get("routes", []):
                    old_r[f"{sub.get('name', sub_id)} / {vnet['name']} / {sn} / {r['name']}"] = r
    for sub_id, sub in new.get("subscriptions", {}).items():
        for vid, vnet in sub.get("vnets", {}).items():
            for sn, s in vnet.get("subnets", {}).items():
                for r in s.get("routes", []):
                    new_r[f"{sub.get('name', sub_id)} / {vnet['name']} / {sn} / {r['name']}"] = r
    diff["categories"]["routes"] = _diff_dicts(old_r, new_r, _route_summary, ["prefix", "next_hop_type", "next_hop_ip"])

    # Peerings
    old_p, new_p = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for vid, vnet in sub.get("vnets", {}).items():
            for p in vnet.get("peerings", []):
                old_p[f"{sub.get('name', sub_id)} / {vnet['name']} / {p['name']}"] = p
    for sub_id, sub in new.get("subscriptions", {}).items():
        for vid, vnet in sub.get("vnets", {}).items():
            for p in vnet.get("peerings", []):
                new_p[f"{sub.get('name', sub_id)} / {vnet['name']} / {p['name']}"] = p
    diff["categories"]["peerings"] = _diff_dicts(
        old_p, new_p, _peering_summary,
        ["state", "allow_forwarded_traffic", "allow_gateway_transit", "use_remote_gateways"]
    )

    # Gateways
    old_g, new_g = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for vid, vnet in sub.get("vnets", {}).items():
            for g in vnet.get("gateways", []):
                old_g[f"{sub.get('name', sub_id)} / {vnet['name']} / {g['name']}"] = g
    for sub_id, sub in new.get("subscriptions", {}).items():
        for vid, vnet in sub.get("vnets", {}).items():
            for g in vnet.get("gateways", []):
                new_g[f"{sub.get('name', sub_id)} / {vnet['name']} / {g['name']}"] = g
    diff["categories"]["gateways"] = _diff_dicts(old_g, new_g, _gateway_summary, ["sku", "state", "type"])

    # Public IPs
    old_pip, new_pip = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for pip in sub.get("public_ips", []):
            old_pip[f"{sub.get('name', sub_id)} / {pip['name']}"] = pip
    for sub_id, sub in new.get("subscriptions", {}).items():
        for pip in sub.get("public_ips", []):
            new_pip[f"{sub.get('name', sub_id)} / {pip['name']}"] = pip
    diff["categories"]["public_ips"] = _diff_dicts(old_pip, new_pip, _pip_summary, ["ip", "associated_type", "associated_name"])

    # Policies
    old_pol, new_pol = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for pol in sub.get("policies", []):
            old_pol[f"{sub.get('name', sub_id)} / {pol['name']}"] = pol
    for sub_id, sub in new.get("subscriptions", {}).items():
        for pol in sub.get("policies", []):
            new_pol[f"{sub.get('name', sub_id)} / {pol['name']}"] = pol
    diff["categories"]["policies"] = _diff_dicts(old_pol, new_pol, _policy_summary, ["enforcement"])

    # Gaps
    old_gaps, new_gaps = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for g in sub.get("gaps", []):
            old_gaps[f"{sub.get('name', sub_id)} / {g['type']} / {g.get('vnet', '')} / {g.get('subnet', '')}"] = g
    for sub_id, sub in new.get("subscriptions", {}).items():
        for g in sub.get("gaps", []):
            new_gaps[f"{sub.get('name', sub_id)} / {g['type']} / {g.get('vnet', '')} / {g.get('subnet', '')}"] = g
    diff["categories"]["gaps"] = _diff_dicts(old_gaps, new_gaps, _gap_summary, ["severity"])

    # Resources
    old_res, new_res = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for vid, vnet in sub.get("vnets", {}).items():
            for sn, s in vnet.get("subnets", {}).items():
                for r in s.get("resources", []):
                    old_res[f"{sub.get('name', sub_id)} / {vnet['name']} / {sn} / {r['name']}"] = r
    for sub_id, sub in new.get("subscriptions", {}).items():
        for vid, vnet in sub.get("vnets", {}).items():
            for sn, s in vnet.get("subnets", {}).items():
                for r in s.get("resources", []):
                    new_res[f"{sub.get('name', sub_id)} / {vnet['name']} / {sn} / {r['name']}"] = r
    diff["categories"]["resources"] = _diff_dicts(old_res, new_res, _resource_summary, ["type"])

    # Storage
    old_sa, new_sa = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for sa in sub.get("storage_accounts", []):
            old_sa[f"{sub.get('name', sub_id)} / {sa['name']}"] = sa
    for sub_id, sub in new.get("subscriptions", {}).items():
        for sa in sub.get("storage_accounts", []):
            new_sa[f"{sub.get('name', sub_id)} / {sa['name']}"] = sa
    diff["categories"]["storage"] = _diff_dicts(old_sa, new_sa, _storage_summary, ["verdict", "https_only"])

    # Flow Logs
    old_fl, new_fl = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for fl in sub.get("flow_logs", []):
            old_fl[f"{sub.get('name', sub_id)} / {fl.get('nsg_name', '')}"] = fl
    for sub_id, sub in new.get("subscriptions", {}).items():
        for fl in sub.get("flow_logs", []):
            new_fl[f"{sub.get('name', sub_id)} / {fl.get('nsg_name', '')}"] = fl
    diff["categories"]["flow_logs"] = _diff_dicts(
        old_fl, new_fl, _flow_log_summary, ["enabled", "retention_days", "traffic_analytics_enabled"]
    )

    # Private DNS
    old_dns, new_dns = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for z in sub.get("private_dns_zones", []):
            old_dns[f"{sub.get('name', sub_id)} / {z['name']}"] = z
    for sub_id, sub in new.get("subscriptions", {}).items():
        for z in sub.get("private_dns_zones", []):
            new_dns[f"{sub.get('name', sub_id)} / {z['name']}"] = z
    diff["categories"]["private_dns"] = _diff_dicts(old_dns, new_dns, _dns_zone_summary, ["record_count"])

    # App Services
    old_apps, new_apps = {}, {}
    for sub_id, sub in old.get("subscriptions", {}).items():
        for app in sub.get("app_services", []):
            old_apps[f"{sub.get('name', sub_id)} / {app['name']}"] = app
    for sub_id, sub in new.get("subscriptions", {}).items():
        for app in sub.get("app_services", []):
            new_apps[f"{sub.get('name', sub_id)} / {app['name']}"] = app
    diff["categories"]["app_services"] = _diff_dicts(
        old_apps, new_apps, _app_service_summary,
        ["verdict", "https_only", "min_tls_version", "public_network_access"]
    )

    return diff


def _diff_simple_keys(old_keys, new_keys, old_labeler, new_labeler):
    return {
        "added": [new_labeler(k) for k in new_keys - old_keys],
        "removed": [old_labeler(k) for k in old_keys - new_keys],
        "modified": [],
    }


def _diff_dicts(old_dict, new_dict, summarizer, compare_fields):
    old_keys = set(old_dict.keys())
    new_keys = set(new_dict.keys())
    added = [{"key": k, "summary": summarizer(new_dict[k])} for k in sorted(new_keys - old_keys)]
    removed = [{"key": k, "summary": summarizer(old_dict[k])} for k in sorted(old_keys - new_keys)]
    modified = []
    for k in sorted(old_keys & new_keys):
        changes = []
        for field in compare_fields:
            ov = old_dict[k].get(field)
            nv = new_dict[k].get(field)
            if ov != nv:
                changes.append({"field": field, "old": ov, "new": nv})
        if changes:
            modified.append({"key": k, "changes": changes})
    return {"added": added, "removed": removed, "modified": modified}


# Summary formatters
def _vnet_summary(v):
    return f"Address: {', '.join(v.get('address_space', []))}, Location: {v.get('location', '')}"

def _subnet_summary(s):
    return f"({s.get('prefix', '')}) NSG: {s.get('nsg') or 'none'}, RT: {s.get('route_table') or 'none'}, Internet: {s.get('internet_access', '')}"

def _route_summary(r):
    hop_ip = f" ({r['next_hop_ip']})" if r.get("next_hop_ip") else ""
    return f"{r.get('prefix', '')} → {r.get('next_hop_type', '')}{hop_ip}"

def _peering_summary(p):
    return f"→ {p.get('remote_vnet', '')} ({p.get('state', '')})"

def _gateway_summary(g):
    return f"{g.get('type', '')} / {g.get('sku', '')} ({g.get('state', '')})"

def _pip_summary(p):
    return f"{p.get('ip', 'unassigned')} → {p.get('associated_type', '')}: {p.get('associated_name', '')}"

def _policy_summary(p):
    return f"Enforcement: {p.get('enforcement', '')}"

def _gap_summary(g):
    return f"[{g.get('severity', '')}] {g.get('detail', '')}"

def _resource_summary(r):
    return f"Type: {r.get('type', '')}"

def _storage_summary(s):
    return f"Verdict: {s.get('verdict', '')}"

def _flow_log_summary(fl):
    enabled = "enabled" if fl.get("enabled") else "disabled"
    return f"Flow log {enabled}, retention: {fl.get('retention_days', 0)}d"

def _dns_zone_summary(z):
    links = len(z.get("vnet_links", []))
    return f"{z.get('record_count', 0)} records, {links} VNet link(s)"

def _app_service_summary(a):
    return f"{a.get('kind', 'app')} — {a.get('verdict', '')}"


# ─── Diff Display + Export ────────────────────────────────────────────────────


def print_diff_summary(diff):
    old_c = diff["old_counts"]
    new_c = diff["new_counts"]
    print(f"\n{BOLD}=== DIFF SUMMARY ==={NC}")
    items = [
        ("Subscriptions", "subscriptions"), ("VNets", "vnets"),
        ("Subnets", "subnets"), ("NSGs", "nsgs"),
        ("Route Tables", "route_tables"), ("Peerings", "peerings"),
        ("Gateways", "gateways"), ("Public IPs", "public_ips"),
        ("Policies", "policies"), ("Flow Logs", "flow_logs"),
        ("Private DNS", "private_dns"), ("App Services", "app_services"),
        ("Gaps", "gaps"), ("Resources", "resources"),
    ]
    for label, key in items:
        ov = old_c.get(key, 0)
        nv = new_c.get(key, 0)
        delta = nv - ov
        if delta > 0:
            change = f" ({GREEN}+{delta}{NC})"
        elif delta < 0:
            change = f" ({RED}{delta}{NC})"
        else:
            change = " (no change)"
        print(f"  {label:<15} {ov} → {nv}{change}")


def print_diff_categories(diff):
    cats_with_changes = []
    for key, cat in diff["categories"].items():
        total = len(cat.get("added", [])) + len(cat.get("removed", [])) + len(cat.get("modified", []))
        if total > 0:
            cats_with_changes.append((key, cat, total))
    if not cats_with_changes:
        print(f"\n{GREEN}No changes detected between snapshots.{NC}")
        return []
    print(f"\n{BOLD}Categories with changes:{NC}")
    for i, (key, cat, total) in enumerate(cats_with_changes, 1):
        parts = []
        if cat["added"]:
            parts.append(f"{len(cat['added'])} added")
        if cat["removed"]:
            parts.append(f"{len(cat['removed'])} removed")
        if cat["modified"]:
            parts.append(f"{len(cat['modified'])} modified")
        print(f"  [{i}] {key.replace('_', ' ').title()} ({', '.join(parts)})")
    return cats_with_changes


def print_diff_detail(cat_name, cat_data):
    print(f"\n{BOLD}=== {cat_name.upper().replace('_', ' ')} CHANGES ==={NC}")
    if cat_data["added"]:
        print(f"\n{GREEN}ADDED:{NC}")
        for item in cat_data["added"]:
            print(f"  {GREEN}+{NC} {item['key']}")
            print(f"    {item['summary']}")
    if cat_data["removed"]:
        print(f"\n{RED}REMOVED:{NC}")
        for item in cat_data["removed"]:
            print(f"  {RED}-{NC} {item['key']}")
            print(f"    {item['summary']}")
    if cat_data["modified"]:
        print(f"\n{YELLOW}MODIFIED:{NC}")
        for item in cat_data["modified"]:
            print(f"  {YELLOW}~{NC} {item['key']}")
            for change in item["changes"]:
                print(f"    {change['field']}: {change['old']} → {change['new']}")


def run_diff(from_file=None, to_file=None, interactive=True, export=False):
    snapshots = find_snapshots()
    if not snapshots:
        print(f"{RED}No snapshots found in current directory.{NC}")
        return
    if from_file and to_file:
        old_file, new_file = from_file, to_file
    elif len(snapshots) < 2:
        print(f"{YELLOW}Need at least 2 snapshots to compare. Found {len(snapshots)}.{NC}")
        return
    else:
        if interactive and len(snapshots) > 2:
            print(f"\nFound {len(snapshots)} snapshots:")
            for i, (f, ts) in enumerate(snapshots, 1):
                dt = datetime.strptime(ts, "%Y%m%d-%H%M%S")
                label = " ← latest" if i == len(snapshots) else ""
                print(f"  [{i}] {f} ({dt.strftime('%b %d, %I:%M %p')}{label})")
            print(f"\nComparing: [{len(snapshots)-1}] → [{len(snapshots)}] (last two)")
            try:
                choice = input("Press Enter to confirm, or enter two numbers (e.g. '1 3'): ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            if choice:
                parts = choice.split()
                if len(parts) == 2:
                    try:
                        old_file = snapshots[int(parts[0]) - 1][0]
                        new_file = snapshots[int(parts[1]) - 1][0]
                    except (ValueError, IndexError):
                        print(f"{RED}Invalid selection.{NC}")
                        return
                else:
                    print(f"{RED}Enter two numbers separated by space.{NC}")
                    return
            else:
                old_file = snapshots[-2][0]
                new_file = snapshots[-1][0]
        else:
            old_file = snapshots[-2][0]
            new_file = snapshots[-1][0]

    print(f"\nComparing: {BOLD}{old_file}{NC} → {BOLD}{new_file}{NC}")
    try:
        old_snap = load_snapshot(old_file)
        new_snap = load_snapshot(new_file)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"{RED}Error loading snapshot: {e}{NC}")
        return

    diff = diff_snapshots(old_snap, new_snap)
    print_diff_summary(diff)
    cats_with_changes = print_diff_categories(diff)
    if not cats_with_changes:
        return
    if export:
        _export_diff(diff, cats_with_changes)
        return
    if not interactive:
        for key, cat, _ in cats_with_changes:
            print_diff_detail(key, cat)
        return

    while True:
        try:
            choice = input(f"\nDrill into (1-{len(cats_with_changes)}) or [q]uit: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if choice.lower() == "q":
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(cats_with_changes):
                print_diff_detail(cats_with_changes[idx][0], cats_with_changes[idx][1])
            else:
                print(f"{RED}Invalid selection.{NC}")
        except ValueError:
            print(f"{RED}Enter a number or 'q'.{NC}")


def _export_diff(diff, cats_with_changes):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"diff-{timestamp}.txt"
    lines = ["=== DIFF SUMMARY ===\n"]
    old_c, new_c = diff["old_counts"], diff["new_counts"]
    for label, key in [
        ("Subscriptions", "subscriptions"), ("VNets", "vnets"),
        ("Subnets", "subnets"), ("NSGs", "nsgs"),
        ("Route Tables", "route_tables"), ("Peerings", "peerings"),
        ("Gateways", "gateways"), ("Public IPs", "public_ips"),
        ("Policies", "policies"), ("Gaps", "gaps"), ("Resources", "resources"),
    ]:
        ov, nv = old_c.get(key, 0), new_c.get(key, 0)
        delta = nv - ov
        sign = f"+{delta}" if delta > 0 else str(delta)
        lines.append(f"  {label:<15} {ov} -> {nv} ({sign})\n")
    for key, cat, _ in cats_with_changes:
        lines.append(f"\n=== {key.upper().replace('_', ' ')} CHANGES ===\n")
        if cat["added"]:
            lines.append("\nADDED:\n")
            for item in cat["added"]:
                lines.append(f"  + {item['key']}\n    {item['summary']}\n")
        if cat["removed"]:
            lines.append("\nREMOVED:\n")
            for item in cat["removed"]:
                lines.append(f"  - {item['key']}\n    {item['summary']}\n")
        if cat["modified"]:
            lines.append("\nMODIFIED:\n")
            for item in cat["modified"]:
                lines.append(f"  ~ {item['key']}\n")
                for c in item["changes"]:
                    lines.append(f"    {c['field']}: {c['old']} -> {c['new']}\n")
    with open(filename, "w") as f:
        f.writelines(lines)
    print(f"\nDiff exported to: {BOLD}{filename}{NC}")


# ─── CSV Export (identical to v1.2) ──────────────────────────────────────────


def export_csv(snapshot_path):
    try:
        snapshot = load_snapshot(snapshot_path)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"{RED}Error loading snapshot: {e}{NC}")
        return

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = f"export-{timestamp}"
    os.makedirs(outdir, exist_ok=True)

    # 1. network-topology.csv
    with open(os.path.join(outdir, "network-topology.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow([
            "Subscription", "SubscriptionId", "VNet", "VNetAddressSpace",
            "ResourceGroup", "Location", "DDoSProtection",
            "Subnet", "SubnetPrefix", "NSG", "RouteTable", "BGPPropagation",
            "ServiceEndpoints", "Delegations", "NATGateway",
            "RouteName", "RoutePrefix", "NextHopType", "NextHopIP", "IsFirewall", "InternetAccess"
        ])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for vnet_id, vnet in sub.get("vnets", {}).items():
                addr_space = ",".join(vnet.get("address_space", []))
                for sn_name, sn in vnet.get("subnets", {}).items():
                    routes = sn.get("routes", [])
                    ddos = "Yes" if vnet.get("ddos_protection") else "No"
                    svc_eps = ";".join(sn.get("service_endpoints", []))
                    delegs = ";".join(sn.get("delegations", []))
                    nat_gw = sn.get("nat_gateway") or ""
                    if not routes:
                        w.writerow([
                            sub["name"], sub_id, vnet["name"], addr_space,
                            vnet["resource_group"], vnet["location"], ddos,
                            sn_name, sn.get("prefix", ""),
                            sn.get("nsg") or "", sn.get("route_table") or "",
                            "enabled" if sn.get("bgp_propagation", True) else "disabled",
                            svc_eps, delegs, nat_gw,
                            "", "", "", "", "No", sn.get("internet_access", "")
                        ])
                    else:
                        for r in routes:
                            is_fw = "Yes" if r.get("next_hop_type") == "VirtualAppliance" else "No"
                            w.writerow([
                                sub["name"], sub_id, vnet["name"], addr_space,
                                vnet["resource_group"], vnet["location"], ddos,
                                sn_name, sn.get("prefix", ""),
                                sn.get("nsg") or "", sn.get("route_table") or "",
                                "enabled" if sn.get("bgp_propagation", True) else "disabled",
                                svc_eps, delegs, nat_gw,
                                r["name"], r["prefix"], r["next_hop_type"],
                                r.get("next_hop_ip") or "", is_fw,
                                sn.get("internet_access", "")
                            ])

    # 2. peerings.csv
    with open(os.path.join(outdir, "peerings.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow([
            "Subscription", "SubscriptionId", "VNet", "ResourceGroup",
            "PeerName", "RemoteVNet", "RemoteVNetId", "PeeringState",
            "AllowVNetAccess", "AllowForwardedTraffic", "AllowGatewayTransit", "UseRemoteGateways"
        ])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for vnet_id, vnet in sub.get("vnets", {}).items():
                for p in vnet.get("peerings", []):
                    w.writerow([
                        sub["name"], sub_id, vnet["name"], vnet["resource_group"],
                        p["name"], p.get("remote_vnet", ""), p.get("remote_vnet_id", ""),
                        p.get("state", ""), p.get("allow_vnet_access", ""),
                        p.get("allow_forwarded_traffic", ""), p.get("allow_gateway_transit", ""),
                        p.get("use_remote_gateways", ""),
                    ])

    # 3. gateways.csv
    with open(os.path.join(outdir, "gateways.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Subscription", "SubscriptionId", "VNet", "ResourceGroup",
                     "GatewayName", "GatewayType", "VpnType", "Sku", "ProvisioningState"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for vnet_id, vnet in sub.get("vnets", {}).items():
                for g in vnet.get("gateways", []):
                    w.writerow([sub["name"], sub_id, vnet["name"], vnet["resource_group"],
                                g["name"], g.get("type", ""), g.get("vpn_type", ""),
                                g.get("sku", ""), g.get("state", "")])

    # 4. public-ips.csv
    with open(os.path.join(outdir, "public-ips.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Subscription", "SubscriptionId", "ResourceGroup",
                     "PublicIPName", "IPAddress", "AllocationMethod",
                     "AssociatedResourceType", "AssociatedResourceName",
                     "AssociatedSubnet", "AssociatedVNet", "NicNSG"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for pip in sub.get("public_ips", []):
                w.writerow([sub["name"], sub_id, pip.get("resource_group", ""),
                            pip["name"], pip.get("ip", ""), pip.get("allocation", ""),
                            pip.get("associated_type", ""), pip.get("associated_name", ""),
                            pip.get("subnet", ""), pip.get("vnet", ""),
                            pip.get("nic_nsg", "")])

    # 5. policies.csv
    with open(os.path.join(outdir, "policies.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Subscription", "SubscriptionId", "PolicyName",
                     "PolicyDefinitionId", "Scope", "EnforcementMode", "Description"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for pol in sub.get("policies", []):
                w.writerow([sub["name"], sub_id, pol["name"], pol.get("definition_id", ""),
                            pol.get("scope", ""), pol.get("enforcement", ""), pol.get("description", "")])

    # 6. resources.csv
    with open(os.path.join(outdir, "resources.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Subscription", "SubscriptionId", "VNet", "Subnet",
                     "ResourceName", "ResourceType", "ResourceGroup", "Location"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for vnet_id, vnet in sub.get("vnets", {}).items():
                for sn_name, sn in vnet.get("subnets", {}).items():
                    for r in sn.get("resources", []):
                        w.writerow([sub["name"], sub_id, vnet["name"], sn_name,
                                    r["name"], r.get("type", ""), r.get("resource_group", ""), ""])

    # 7. gap-analysis.csv
    with open(os.path.join(outdir, "gap-analysis.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["GapType", "Severity", "Subscription", "SubscriptionId",
                     "VNet", "ResourceGroup", "Subnet", "SubnetPrefix",
                     "HasNSG", "HasRouteTable", "HasFirewallRoute", "InternetAccess", "Detail"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for g in sub.get("gaps", []):
                vnet_rg = ""
                for vnet_id, vnet in sub.get("vnets", {}).items():
                    if vnet["name"] == g.get("vnet"):
                        vnet_rg = vnet["resource_group"]
                        break
                w.writerow([g["type"], g["severity"], sub["name"], sub_id,
                            g.get("vnet", ""), vnet_rg, g.get("subnet", ""),
                            g.get("subnet_prefix", ""),
                            "Yes" if g.get("has_nsg") else "No",
                            "Yes" if g.get("has_route_table") else "No",
                            "Yes" if g.get("has_firewall_route") else "No",
                            g.get("internet_access", ""), g.get("detail", "")])

    # 8. nsg-rules.csv
    with open(os.path.join(outdir, "nsg-rules.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["NSG", "ResourceGroup", "Subscription",
                     "OutboundVerdict", "InboundVerdict",
                     "RuleName", "Direction", "Priority", "Access", "Protocol",
                     "SourceAddress", "SourcePort", "DestAddress", "DestPort", "IsDefault"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for nsg in sub.get("nsg_analysis", []):
                out_v = nsg.get("outbound_verdict", nsg.get("verdict", ""))
                in_v = nsg.get("inbound_verdict", "")
                all_rules = nsg.get("outbound_rules", []) + nsg.get("inbound_rules", [])
                if not all_rules:
                    all_rules = nsg.get("rules", [])
                for r in all_rules:
                    w.writerow([nsg["nsg"], nsg["resource_group"], sub["name"],
                                out_v, in_v, r["name"], r["direction"], r["priority"],
                                r["access"], r["protocol"],
                                r.get("source_address", ""), r.get("source_port", ""),
                                r.get("dest_address", ""), r.get("dest_port", ""),
                                "Yes" if r.get("is_default") else "No"])

    # 9. storage-access.csv
    with open(os.path.join(outdir, "storage-access.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["StorageAccount", "Subscription", "ResourceGroup", "Kind",
                     "PublicNetworkAccess", "AllowBlobPublicAccess", "PrivateEndpoints",
                     "DefaultNetworkAction", "IPRules", "VNetRules",
                     "PublicContainers", "StaticWebsite", "HttpsOnly", "Verdict", "Details"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for sa in sub.get("storage_accounts", []):
                w.writerow([sa["name"], sa.get("subscription", sub["name"]),
                            sa.get("resource_group", ""), sa.get("kind", ""),
                            sa.get("public_network_access", ""),
                            str(sa.get("allow_blob_public", "")),
                            sa.get("private_endpoints", 0), sa.get("default_action", ""),
                            sa.get("ip_rules", 0), sa.get("vnet_rules", 0),
                            sa.get("public_containers", 0), str(sa.get("static_website", False)),
                            str(sa.get("https_only", True)),
                            sa.get("verdict", ""), sa.get("details", "")])

    # 10. flow-logs.csv
    with open(os.path.join(outdir, "flow-logs.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Subscription", "SubscriptionId", "NSG", "Region",
                     "FlowLogEnabled", "StorageAccount", "RetentionDays",
                     "TrafficAnalyticsEnabled", "WorkspaceId"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for fl in sub.get("flow_logs", []):
                w.writerow([sub["name"], sub_id, fl.get("nsg_name", ""),
                            fl.get("nsg_region", ""),
                            "Yes" if fl.get("enabled") else "No",
                            fl.get("storage_account", ""), fl.get("retention_days", 0),
                            "Yes" if fl.get("traffic_analytics_enabled") else "No",
                            fl.get("workspace_id", "")])

    # 11. private-dns.csv
    with open(os.path.join(outdir, "private-dns.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Subscription", "SubscriptionId", "ZoneName", "ResourceGroup",
                     "RecordCount", "LinkedVNets"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for zone in sub.get("private_dns_zones", []):
                linked = ";".join(lnk.get("vnet_name", "") for lnk in zone.get("vnet_links", []))
                w.writerow([sub["name"], sub_id, zone["name"],
                            zone.get("resource_group", ""), zone.get("record_count", 0), linked])

    # 12. app-services.csv
    with open(os.path.join(outdir, "app-services.csv"), "w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Subscription", "SubscriptionId", "AppName", "ResourceGroup",
                     "Kind", "Location", "PublicNetworkAccess", "HttpsOnly",
                     "MinTLSVersion", "VNetIntegration", "PrivateEndpoints",
                     "IPRestrictionsCount", "HasIPRestrictions", "Verdict", "Details"])
        for sub_id, sub in snapshot.get("subscriptions", {}).items():
            for app in sub.get("app_services", []):
                w.writerow([sub["name"], sub_id, app["name"], app.get("resource_group", ""),
                            app.get("kind", ""), app.get("location", ""),
                            app.get("public_network_access", ""),
                            "Yes" if app.get("https_only") else "No",
                            app.get("min_tls_version", ""),
                            app.get("vnet_integration", ""), app.get("private_endpoints", 0),
                            app.get("ip_restrictions_count", 0),
                            "Yes" if app.get("has_ip_restrictions") else "No",
                            app.get("verdict", ""), app.get("details", "")])

    print(f"\n{GREEN}Exported 12 CSV files to: {BOLD}{outdir}/{NC}")


# ─── List + Menu + CLI ───────────────────────────────────────────────────────


def list_snapshots_cmd():
    snapshots = find_snapshots()
    if not snapshots:
        print(f"\n{YELLOW}No snapshots found in current directory.{NC}")
        print(f"Run {BOLD}python3 aznetaudit_rg.py snapshot{NC} to create one.")
        return
    print(f"\n{BOLD}Available snapshots:{NC}")
    for i, (f, ts) in enumerate(snapshots, 1):
        dt = datetime.strptime(ts, "%Y%m%d-%H%M%S")
        size = os.path.getsize(f)
        size_str = f"{size / 1024 / 1024:.1f} MB" if size > 1024 * 1024 else f"{size / 1024:.0f} KB"
        label = " ← latest" if i == len(snapshots) else ""
        print(f"  [{i}] {f} ({dt.strftime('%b %d, %Y %I:%M %p')}, {size_str}{label})")
    print(f"\n  Total: {len(snapshots)} snapshot(s)")


def interactive_menu():
    print(f"\n{BOLD}Azure Network Auditor v{VERSION} (Resource Graph){NC}")
    print(f"{BOLD}{'=' * 45}{NC}")

    while True:
        print(f"""
  [{BOLD}1{NC}] Full snapshot — capture entire network environment
  [{BOLD}2{NC}] Diff snapshots — compare two runs and show changes
  [{BOLD}3{NC}] Export CSV — convert a snapshot to CSV files
  [{BOLD}4{NC}] List snapshots — show available snapshots
  [{BOLD}q{NC}] Quit
""")
        try:
            choice = input("  Select: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "1":
            take_snapshot()
        elif choice == "2":
            run_diff(interactive=True)
        elif choice == "3":
            snapshots = find_snapshots()
            if not snapshots:
                print(f"\n{YELLOW}No snapshots found. Run a snapshot first.{NC}")
                continue
            print(f"\n{BOLD}Available snapshots:{NC}")
            for i, (f, ts) in enumerate(snapshots, 1):
                dt = datetime.strptime(ts, "%Y%m%d-%H%M%S")
                print(f"  [{i}] {f} ({dt.strftime('%b %d, %I:%M %p')})")
            try:
                idx = input(f"\n  Export which snapshot? (1-{len(snapshots)}): ").strip()
                idx = int(idx) - 1
                if 0 <= idx < len(snapshots):
                    export_csv(snapshots[idx][0])
                else:
                    print(f"{RED}Invalid selection.{NC}")
            except (ValueError, EOFError, KeyboardInterrupt):
                continue
        elif choice == "4":
            list_snapshots_cmd()
        elif choice.lower() == "q":
            break
        else:
            print(f"{RED}Invalid selection.{NC}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Azure Network Auditor v2.0 — Resource Graph edition.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"aznetaudit_rg {VERSION}")

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("snapshot", help="Take a full environment snapshot")

    diff_parser = subparsers.add_parser("diff", help="Compare two snapshots")
    diff_parser.add_argument("--from", dest="from_file", help="Older snapshot file")
    diff_parser.add_argument("--to", dest="to_file", help="Newer snapshot file")
    diff_parser.add_argument("--export", action="store_true", help="Export diff to text file")

    export_parser = subparsers.add_parser("export", help="Export snapshot to CSV files")
    export_parser.add_argument("--csv", dest="csv_file", required=True, help="Snapshot file to export")

    subparsers.add_parser("list", help="List available snapshots")

    return parser.parse_args()


def main():
    try:
        args = parse_args()

        if args.command == "snapshot":
            take_snapshot()
        elif args.command == "diff":
            run_diff(
                from_file=args.from_file,
                to_file=args.to_file,
                interactive=sys.stdin.isatty(),
                export=args.export,
            )
        elif args.command == "export":
            export_csv(args.csv_file)
        elif args.command == "list":
            list_snapshots_cmd()
        else:
            if sys.stdin.isatty():
                interactive_menu()
            else:
                parse_args()
    except KeyboardInterrupt:
        printerr(f"\n{YELLOW}Interrupted.{NC}")
        sys.exit(130)


if __name__ == "__main__":
    main()
