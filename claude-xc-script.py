#!/usr/bin/env python3
"""
F5 Distributed Cloud - HTTP LB & WAF Policy Inventory
Enumerates all namespaces, HTTP load balancers, and attached WAF (app_firewall) policies.
"""

import os
import sys
import json
import requests
from collections import defaultdict

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
    except requests.exceptions.HTTPError as e:
        # 403/404 on a namespace is common (RBAC or no objects) — skip gracefully
        if r.status_code in (403, 404):
            return None
        print(f"  ERROR [{r.status_code}] {path}: {e}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"  ERROR {path}: {e}", file=sys.stderr)
        return None


def list_namespaces():
    """Return list of namespace names."""
    data = api("GET", "/api/web/namespaces")
    if not data or "items" not in data:
        sys.exit("Failed to retrieve namespaces. Check tenant name and API token.")
    return [item["name"] for item in data["items"]]


def list_http_lbs(namespace):
    """Return list of HTTP LB objects in a namespace."""
    data = api("GET", f"/api/config/namespaces/{namespace}/http_loadbalancers")
    if not data or "items" not in data:
        return []
    return data["items"]


def extract_waf_info(lb):
    """Extract WAF / app_firewall reference from an HTTP LB spec."""
    spec = lb.get("spec") or lb.get("get_spec") or {}

    # Primary: direct app_firewall reference
    app_fw = spec.get("app_firewall")
    if app_fw:
        refs = app_fw.get("ref", []) if isinstance(app_fw, dict) else []
        if refs:
            return [{
                "name":      r.get("name", "unknown"),
                "namespace": r.get("namespace", "same-as-lb"),
                "tenant":    r.get("tenant", TENANT),
            } for r in refs]
        # Some responses nest it as a direct name string
        if isinstance(app_fw, str):
            return [{"name": app_fw, "namespace": "unknown", "tenant": TENANT}]

    # Check for WAF type indicator (e.g., single_lb_app_firewall)
    for key in ("single_lb_app_firewall", "shared_lb_app_firewall"):
        waf_block = spec.get(key)
        if waf_block:
            ref = waf_block if isinstance(waf_block, dict) else {}
            refs = ref.get("ref", [])
            if refs:
                return [{"name": r.get("name"), "namespace": r.get("namespace", "same-as-lb"), "tenant": r.get("tenant", TENANT)} for r in refs]

    return []


def main():
    print(f"{'='*80}")
    print(f"F5 XC Inventory — Tenant: {TENANT}")
    print(f"{'='*80}\n")

    namespaces = list_namespaces()
    print(f"Found {len(namespaces)} namespace(s)\n")

    summary = []  # (namespace, lb_name, domains, waf_policies)

    for ns in namespaces:
        lbs = list_http_lbs(ns)
        if not lbs:
            continue

        print(f"Namespace: {ns}  ({len(lbs)} HTTP LB(s))")
        print(f"{'-'*60}")

        for lb in lbs:
            meta = lb.get("metadata") or {}
            spec = lb.get("spec") or lb.get("get_spec") or {}
            lb_name = meta.get("name", "unknown")
            domains = spec.get("domains", [])
            waf_policies = extract_waf_info(lb)

            waf_display = ", ".join(
                f"{w['name']} (ns:{w['namespace']})" for w in waf_policies
            ) if waf_policies else "NONE"

            print(f"  LB: {lb_name}")
            print(f"      Domains: {', '.join(domains) if domains else 'N/A'}")
            print(f"      WAF:     {waf_display}")

            summary.append({
                "namespace":    ns,
                "lb_name":      lb_name,
                "domains":      domains,
                "waf_policies": waf_policies,
            })

        print()

    # --- Summary ---
    total_lbs  = len(summary)
    with_waf   = sum(1 for s in summary if s["waf_policies"])
    no_waf     = total_lbs - with_waf

    print(f"{'='*80}")
    print(f"SUMMARY")
    print(f"  Namespaces scanned : {len(namespaces)}")
    print(f"  Total HTTP LBs     : {total_lbs}")
    print(f"  With WAF policy    : {with_waf}")
    print(f"  WITHOUT WAF policy : {no_waf}  {'⚠️  review recommended' if no_waf else '✓'}")
    print(f"{'='*80}")

    # Optional: dump JSON for programmatic consumption
    output_file = "f5xc_inventory.json"
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nFull inventory written to {output_file}")


if __name__ == "__main__":
    main()
