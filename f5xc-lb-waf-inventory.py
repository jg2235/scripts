#!/usr/bin/env python3
"""
F5 Distributed Cloud - HTTP LB & WAF Policy Inventory
Enumerates all namespaces, HTTP load balancers, and attached WAF (app_firewall) policies.
"""

import os
import sys
import json
import requests

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


def list_namespaces():
    """Return list of namespace names."""
    data = api("GET", "/api/web/namespaces")
    if not data or "items" not in data:
        sys.exit("Failed to retrieve namespaces. Check tenant name and API token.")
    return [item["name"] for item in data["items"]]


def list_http_lb_names(namespace):
    """Return list of HTTP LB names from the abbreviated LIST response."""
    data = api("GET", f"/api/config/namespaces/{namespace}/http_loadbalancers")
    if not data or "items" not in data:
        return []
    names = []
    for item in data["items"]:
        # LIST response: name can be top-level, in metadata, or in get_spec.metadata
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
    """GET a single HTTP LB — returns full spec with domains, WAF refs, etc."""
    return api("GET", f"/api/config/namespaces/{namespace}/http_loadbalancers/{name}")


def extract_waf_info(spec):
    """Extract WAF / app_firewall references from the full HTTP LB spec."""
    if not spec:
        return []

    results = []
    for key in ("app_firewall", "single_lb_app_firewall", "shared_lb_app_firewall",
                "waf", "web_app_firewall"):
        val = spec.get(key)
        if not val or not isinstance(val, dict):
            continue

        # Standard XC object reference: { "ref": [ { "name":..., "namespace":... } ] }
        refs = val.get("ref", [])
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, dict) and r.get("name"):
                    results.append({
                        "name":      r["name"],
                        "namespace": r.get("namespace", "same-as-lb"),
                        "tenant":    r.get("tenant", TENANT),
                    })
        # Fallback: direct name field on the block itself
        if not refs and val.get("name"):
            results.append({
                "name":      val["name"],
                "namespace": val.get("namespace", "same-as-lb"),
                "tenant":    val.get("tenant", TENANT),
            })

    return results


def extract_domains(spec):
    """Extract domains from the full HTTP LB spec."""
    if not spec:
        return []
    domains = spec.get("domains", [])
    return domains if isinstance(domains, list) else []


def main():
    print(f"{'='*80}")
    print(f"F5 XC Inventory — Tenant: {TENANT}")
    print(f"{'='*80}\n")

    namespaces = list_namespaces()
    print(f"Found {len(namespaces)} namespace(s)\n")

    summary = []

    for ns in namespaces:
        lb_names = list_http_lb_names(ns)
        if not lb_names:
            continue

        print(f"Namespace: {ns}  ({len(lb_names)} HTTP LB(s))")
        print(f"{'-'*60}")

        for lb_name in lb_names:
            # Individual GET for full spec
            lb_obj = get_http_lb(ns, lb_name)

            if not lb_obj:
                print(f"  LB: {lb_name}  (could not retrieve details)")
                continue

            spec = lb_obj.get("spec") or lb_obj.get("get_spec") or {}

            domains      = extract_domains(spec)
            waf_policies = extract_waf_info(spec)

            waf_display = ", ".join(
                f"{w['namespace']}/{w['name']}" for w in waf_policies
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
    total_lbs = len(summary)
    with_waf  = sum(1 for s in summary if s["waf_policies"])
    no_waf    = total_lbs - with_waf

    print(f"{'='*80}")
    print(f"SUMMARY")
    print(f"  Namespaces scanned : {len(namespaces)}")
    print(f"  Total HTTP LBs     : {total_lbs}")
    print(f"  With WAF policy    : {with_waf}")
    print(f"  WITHOUT WAF policy : {no_waf}  {'⚠️  review recommended' if no_waf else '✓'}")
    print(f"{'='*80}")

    output_file = "f5xc_inventory.json"
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nFull inventory written to {output_file}")


if __name__ == "__main__":
    main()
