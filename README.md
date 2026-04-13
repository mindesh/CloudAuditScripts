# Azure Network Auditor

Scans all Azure subscriptions in your tenant and produces a JSON snapshot of your network security posture. Detects 13 types of misconfigurations across VNets, subnets, NSGs, route tables, peerings, gateways, app services, storage accounts, and more. Read-only — never modifies any Azure resources.

## Prerequisites

- Python 3.6+
- Azure CLI installed and logged in (`az login`)

## Quick Start

```bash
git clone https://github.com/mindesh/CloudAuditScripts.git
cd CloudAuditScripts
python3 azNetAudit.py
```

The `requests` library is installed automatically on first run if missing.

This launches an interactive menu:

```
Azure Network Auditor v2.0.0 (Resource Graph)
=============================================

[1] Full snapshot - capture entire network environment
[2] Diff snapshots - compare two runs and show changes
[3] Export CSV    - convert a snapshot to CSV files
[4] List snapshots - show available snapshots
[q] Quit

Select option:
```

## Permissions

Requires **Reader** role on target subscriptions. The tool performs 15 Resource Graph queries and a handful of ARM REST GET calls. No write operations.
