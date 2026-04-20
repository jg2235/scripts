# General Purpose Scripts

A collection of useful automation scripts for network, infrastructure, and DevOps tasks — primarily focused on **F5 BIG-IP**, **F5 XC (Distributed Cloud)**, DNS management, and related operations.

## 📁 Repository Structure

## 🛠️ Scripts Overview

### F5 XC (Distributed Cloud)
- **`f5xc-lb-certificate-inventory.py`** — Generates an inventory of certificates attached to load balancers.
- **`f5xc-lb-waf-inventory.py`** — Pulls WAF policy and configuration inventory for load balancers.
- **`f5xc-tenant-map.py`** — Pulls the LB/pool/healthcheck/WAF relationships per namespace, and renders a self-contained interactive HTML map

### F5 BIG-IP
- **`gtm-cleanup.sh`** — Cleanup script for Global Traffic Manager (GTM) objects.
- **`ltm-cleanup.sh`** — Cleanup script for Local Traffic Manager (LTM) objects.
- **`big-ip_mass_fqdn_node_creation/`** — Tools for mass-creating nodes using FQDNs on BIG-IP.

### DNS
- **`create_dns_records_windows/`** — Scripts to automate DNS record creation on Windows DNS servers.

## 🚀 Usage

Each script or directory contains its own usage instructions (or will soon). Most scripts are written in **Python 3** or **Bash** and are designed to be reusable across environments.

**Example (Python scripts):**
```bash
python3 f5xc-lb-certificate-inventory.py

chmod +x gtm-cleanup.sh
./gtm-cleanup.sh

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/jg2235/scripts.git
cd scripts

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
