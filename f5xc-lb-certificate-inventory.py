#!/usr/bin/env python3
"""
F5 Distributed Cloud - HTTP LB Certificate Inventory
Enumerates all namespaces and HTTP load balancers with:
  - LB Name
  - Domains
  - Certificate Type (Auto / Custom / HTTP-only)
  - Certificate Expiration Date
"""

import os
import sys
import json
import requests
from datetime import datetime, timezone

# --- Configuration ---
TENANT    = os.environ.get("F5XC_TENANT", "f5-amer-ent")
API_TOKEN = os.environ.get("F5XC_API_TOKEN", "XXXX")
BASE_URL  = f"https://{TENANT}.console.ves.volterra.io"

# --- Session Setup ---
session = requests.Session()
session.headers.update({
    "Authorization": f"APIToken {API_TOKEN}",
    "Content-Type":  "application/json",
})


def api(method, path):
    """Generic API call with error handling."""
    try:
        r = session.request(method, BASE_URL + path, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError:
        if r.status_code in (403, 404):
            return None
        print(f"  ERROR [{r.status_code}] {path}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"  ERROR {path}: {e}", file=sys.stderr)
        return None


# ── Namespace & LB Listing ────────────────────────────────────────────────────

def list_namespaces():
    data = api("GET", "/api/web/namespaces")
    if not data or "items" not in data:
        sys.exit("Failed to retrieve namespaces. Check tenant name and API token.")
    return [item["name"] for item in data["items"]]


def list_http_lb_names(namespace):
    data = api("GET", f"/api/config/namespaces/{namespace}/http_loadbalancers")
    if not data or "items" not in data:
        return []
    names = []
    for item in data["items"]:
        name = item.get("name")
        if not name:
            meta = item.get("metadata") or {}
            name = meta.get("name")
        if not name:
            get_meta = (item.get("get_spec") or {}).get("metadata") or {}
            name = get_meta.get("name")
        if name:
            names.append(name)
    return names


def get_http_lb(namespace, name):
    return api("GET", f"/api/config/namespaces/{namespace}/http_loadbalancers/{name}")


# ── Certificate Extraction ───────────────────────────────────────────────────

def parse_timestamp(ts):
    """Parse XC timestamp into readable date. Known format: 2026-06-11T11:14:47Z"""
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        if ts > 1e12:
            ts = ts / 1000
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%b %d, %Y")
        except (ValueError, OSError):
            return str(ts)
    if isinstance(ts, str):
        # Strip trailing Z and parse
        clean = ts.replace("Z", "").replace("+00:00", "")
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(clean, fmt).strftime("%b %d, %Y")
            except ValueError:
                continue
        return ts  # Return raw string if unparseable
    return str(ts)


def extract_cert_info(lb_obj):
    """Determine certificate type and expiration from the full LB GET response.

    Confirmed API field paths (from debug output):
      Auto cert expiry:  spec.auto_cert_info.auto_cert_expiry  ("2026-06-11T11:14:47Z")
      Auto cert state:   spec.auto_cert_info.auto_cert_state   ("CertificateValid")
      Auto cert issuer:  spec.auto_cert_info.auto_cert_issuer
      Auto cert subject: spec.auto_cert_info.auto_cert_subject
      Cert state:        spec.cert_state                       ("CertificateValid")
      TLS timestamps:    spec.downstream_tls_certificate_expiration_timestamps[]

    Returns: (cert_type: str, cert_expiry: str)
    """
    spec = lb_obj.get("spec") or lb_obj.get("get_spec") or {}

    # ── 1. HTTPS with Automatic Certificate ──
    auto_cert = spec.get("https_auto_cert")
    if auto_cert and isinstance(auto_cert, dict):
        cert_type = "HTTPS Auto Certificate"
        expiry = None

        # Primary path: spec.auto_cert_info.auto_cert_expiry
        auto_cert_info = spec.get("auto_cert_info")
        if auto_cert_info and isinstance(auto_cert_info, dict):
            val = auto_cert_info.get("auto_cert_expiry")
            if val:
                expiry = parse_timestamp(val)

        # Fallback: spec.downstream_tls_certificate_expiration_timestamps[0]
        if not expiry:
            ts_list = spec.get("downstream_tls_certificate_expiration_timestamps")
            if isinstance(ts_list, list) and ts_list:
                expiry = parse_timestamp(ts_list[0])

        return cert_type, expiry or "N/A (check console)"

    # ── 2. HTTPS with Custom Certificate ──
    https_block = spec.get("https")
    if https_block and isinstance(https_block, dict):
        cert_type = "HTTPS Custom Certificate"
        expiry = None

        # Primary: spec.downstream_tls_certificate_expiration_timestamps[0]
        ts_list = spec.get("downstream_tls_certificate_expiration_timestamps")
        if isinstance(ts_list, list) and ts_list:
            expiry = parse_timestamp(ts_list[0])

        # Fallback: spec.auto_cert_info.auto_cert_expiry (some custom LBs populate this)
        if not expiry:
            auto_cert_info = spec.get("auto_cert_info")
            if auto_cert_info and isinstance(auto_cert_info, dict):
                val = auto_cert_info.get("auto_cert_expiry")
                if val:
                    expiry = parse_timestamp(val)

        # Fallback: resolve certificate_chain ref
        if not expiry:
            tls_params = (https_block.get("tls_cert_params") or
                          https_block.get("tls_parameters") or
                          https_block.get("server_tls_parameters") or
                          https_block)
            if isinstance(tls_params, dict):
                cert_chains = (tls_params.get("certificates") or
                               tls_params.get("tls_certificates") or [])
                if not isinstance(cert_chains, list):
                    cert_chains = [cert_chains] if cert_chains else []
                for cert_ref_block in cert_chains:
                    if not isinstance(cert_ref_block, dict):
                        continue
                    refs = (cert_ref_block.get("ref") or
                            (cert_ref_block.get("certificate") or {}).get("ref") or [])
                    if isinstance(refs, list):
                        for r in refs:
                            if isinstance(r, dict) and r.get("name"):
                                cert_ns = r.get("namespace", "system")
                                cert_name = r["name"]
                                cert_obj = api("GET",
                                    f"/api/config/namespaces/{cert_ns}/certificate_chains/{cert_name}")
                                if cert_obj:
                                    c_spec = cert_obj.get("spec") or cert_obj.get("get_spec") or {}
                                    for ek in ("not_after", "expiry", "expiration_timestamp",
                                               "auto_cert_expiry"):
                                        val = c_spec.get(ek)
                                        if val:
                                            expiry = parse_timestamp(val)
                                            break
                            if expiry:
                                break
                    if expiry:
                        break

        return cert_type, expiry or "N/A (check console)"

    # ── 3. HTTP only (no TLS) ──
    if spec.get("http"):
        return "HTTP (no TLS)", "—"

    # ── 4. Fallback: check for any HTTPS indicator ──
    for k in ("https_auto_cert", "https", "tls_parameters"):
        if spec.get(k):
            return "HTTPS (type unknown)", "N/A"

    return "HTTP (no TLS)", "—"


def extract_domains(spec):
    if not spec:
        return []
    domains = spec.get("domains", [])
    return domains if isinstance(domains, list) else []


# ── Table Rendering ───────────────────────────────────────────────────────────

COLS = [
    ("Load Balancer",       26),
    ("Domains",             38),
    ("Certificate Type",    28),
    ("Cert Expiration",     22),
]


def trunc(text, width):
    if len(text) <= width:
        return text
    return text[:width - 2] + ".."


def table_header():
    hdr = " │ ".join(h.ljust(w) for h, w in COLS)
    sep = "─┼─".join("─" * w for _, w in COLS)
    return hdr, sep


def table_row(vals):
    cells = []
    for i, (_, w) in enumerate(COLS):
        v = vals[i] if i < len(vals) else ""
        cells.append(trunc(v, w).ljust(w))
    return " │ ".join(cells)


def print_namespace_table(ns, lb_records):
    total_width = sum(w for _, w in COLS) + 3 * (len(COLS) - 1)
    hdr, sep = table_header()

    print(f"\n{'═' * total_width}")
    print(f"  NAMESPACE: {ns}  ({len(lb_records)} HTTP LB(s))")
    print(f"{'═' * total_width}")
    print(hdr)
    print(sep)

    for i, rec in enumerate(lb_records):
        lb_name   = rec["lb_name"]
        domains   = ", ".join(rec["domains"]) if rec["domains"] else "—"
        cert_type = rec["cert_type"]
        cert_exp  = rec["cert_expiry"]

        # If multiple domains overflow, show first on main row, rest as continuation
        domain_list = rec["domains"] if rec["domains"] else ["—"]
        first_domain = domain_list[0]
        print(table_row([lb_name, first_domain, cert_type, cert_exp]))

        # Additional domain continuation rows
        for extra_domain in domain_list[1:]:
            print(table_row(["", extra_domain, "", ""]))

        # Separator between LBs
        if i < len(lb_records) - 1:
            print("─┼─".join("─" * w for _, w in COLS))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    total_width = sum(w for _, w in COLS) + 3 * (len(COLS) - 1)

    print(f"\n{'═' * total_width}")
    print(f"  F5 XC Certificate Inventory — Tenant: {TENANT}")
    print(f"{'═' * total_width}")

    namespaces = list_namespaces()
    print(f"  Scanning {len(namespaces)} namespace(s)...\n")

    summary = []
    ns_with_lbs = 0

    for ns in namespaces:
        lb_names = list_http_lb_names(ns)
        if not lb_names:
            continue

        ns_with_lbs += 1
        ns_records = []

        for lb_name in lb_names:
            lb_obj = get_http_lb(ns, lb_name)
            if not lb_obj:
                ns_records.append({
                    "lb_name": lb_name, "domains": [],
                    "cert_type": "ERROR", "cert_expiry": "N/A",
                })
                continue

            spec = lb_obj.get("spec") or lb_obj.get("get_spec") or {}
            domains = extract_domains(spec)
            cert_type, cert_expiry = extract_cert_info(lb_obj)

            rec = {
                "namespace":   ns,
                "lb_name":     lb_name,
                "domains":     domains,
                "cert_type":   cert_type,
                "cert_expiry": cert_expiry,
            }
            ns_records.append(rec)
            summary.append(rec)

        print_namespace_table(ns, ns_records)

    # ── Summary ──
    total_lbs   = len(summary)
    auto_cert   = sum(1 for s in summary if "Auto" in s["cert_type"])
    custom_cert = sum(1 for s in summary if "Custom" in s["cert_type"])
    http_only   = sum(1 for s in summary if "HTTP" in s["cert_type"] and "HTTPS" not in s["cert_type"])

    print(f"\n{'═' * total_width}")
    print(f"  SUMMARY")
    print(f"{'═' * total_width}")
    print(f"  Namespaces scanned         : {len(namespaces)}")
    print(f"  Namespaces with LBs        : {ns_with_lbs}")
    print(f"  Total HTTP LBs             : {total_lbs}")
    print(f"  HTTPS Auto Certificate     : {auto_cert}")
    print(f"  HTTPS Custom Certificate   : {custom_cert}")
    print(f"  HTTP only (no TLS)         : {http_only}")
    print(f"{'═' * total_width}")

    output_file = "f5xc_cert_inventory.json"
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Full inventory written to {output_file}\n")


if __name__ == "__main__":
    main()
