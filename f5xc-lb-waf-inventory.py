#!/usr/bin/env python3
"""
F5 Distributed Cloud - HTTP LB Full Inventory
Enumerates all namespaces, HTTP load balancers with:
  - Domains
  - WAF (app_firewall) policies
  - Origin pools & origin servers
  - API Definition (enabled + name)
  - API Discovery (enabled/disabled)
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

# Cache origin pool lookups to avoid redundant GETs
_origin_pool_cache = {}


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


# ── Namespace & LB listing ────────────────────────────────────────────────────

def list_namespaces():
    """Return list of namespace names."""
    data = api("GET", "/api/web/namespaces")
    if not data or "items" not in data:
        sys.exit("Failed to retrieve namespaces. Check tenant name and API token.")
    return [item["name"] for item in data["items"]]


def list_http_lb_names(namespace):
    """Return LB names from the abbreviated LIST response."""
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
    """GET a single HTTP LB with full spec."""
    return api("GET", f"/api/config/namespaces/{namespace}/http_loadbalancers/{name}")


# ── Extractors ────────────────────────────────────────────────────────────────

def extract_domains(spec):
    """Extract domains list from LB spec."""
    if not spec:
        return []
    domains = spec.get("domains", [])
    return domains if isinstance(domains, list) else []


def extract_waf_info(spec):
    """Extract WAF / app_firewall references."""
    if not spec:
        return []
    results = []
    for key in ("app_firewall", "single_lb_app_firewall", "shared_lb_app_firewall",
                "waf", "web_app_firewall"):
        val = spec.get(key)
        if not val or not isinstance(val, dict):
            continue
        refs = val.get("ref", [])
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, dict) and r.get("name"):
                    results.append({
                        "name":      r["name"],
                        "namespace": r.get("namespace", "same-as-lb"),
                        "tenant":    r.get("tenant", TENANT),
                    })
        if not refs and val.get("name"):
            results.append({
                "name":      val["name"],
                "namespace": val.get("namespace", "same-as-lb"),
                "tenant":    val.get("tenant", TENANT),
            })
    return results


def _resolve_ref(ref_obj):
    """Extract (namespace, name) from a standard XC ref block."""
    if not ref_obj or not isinstance(ref_obj, dict):
        return None, None
    refs = ref_obj.get("ref", [])
    if isinstance(refs, list) and refs:
        r = refs[0]
        return r.get("namespace"), r.get("name")
    # Fallback: direct fields
    return ref_obj.get("namespace"), ref_obj.get("name")


def extract_origin_pool_refs(spec):
    """Extract origin pool references from LB spec.
    Pools live in default_route_pools[].pool, or round_robin/routes variations."""
    if not spec:
        return []
    pool_refs = []

    # default_route_pools is the standard location
    for pool_entry in (spec.get("default_route_pools") or []):
        pool_block = pool_entry.get("pool") or pool_entry.get("origin_pool") or {}
        ns, name = _resolve_ref(pool_block)
        if name:
            pool_refs.append({"namespace": ns, "name": name,
                              "weight": pool_entry.get("weight", 1),
                              "priority": pool_entry.get("priority", 0)})

    # Also check routes[].simple_routes[].origin_pools if present
    for route in (spec.get("routes") or []):
        sr = route.get("simple_route") or {}
        for pool_entry in (sr.get("origin_pools") or []):
            pool_block = pool_entry.get("pool") or pool_entry.get("origin_pool") or {}
            ns, name = _resolve_ref(pool_block)
            if name:
                pool_refs.append({"namespace": ns, "name": name,
                                  "weight": pool_entry.get("weight", 1),
                                  "priority": pool_entry.get("priority", 0)})

    return pool_refs


def get_origin_pool_details(namespace, name):
    """GET origin pool and return origin servers + port. Results are cached."""
    cache_key = f"{namespace}/{name}"
    if cache_key in _origin_pool_cache:
        return _origin_pool_cache[cache_key]

    data = api("GET", f"/api/config/namespaces/{namespace}/origin_pools/{name}")
    if not data:
        _origin_pool_cache[cache_key] = None
        return None

    spec = data.get("spec") or data.get("get_spec") or {}
    port = spec.get("port", "N/A")
    lb_algo = spec.get("loadbalancer_algorithm", "N/A")

    servers = []
    for srv in (spec.get("origin_servers") or []):
        # Determine origin type and address
        if srv.get("public_name"):
            stype = "Public DNS"
            addr  = (srv["public_name"].get("dns_name") or
                     srv["public_name"].get("hostname") or "unknown")
        elif srv.get("public_ip"):
            stype = "Public IP"
            addr  = (srv["public_ip"].get("ip") or
                     srv["public_ip"].get("ipv4") or "unknown")
        elif srv.get("private_name"):
            stype = "Private DNS"
            addr  = (srv["private_name"].get("dns_name") or
                     srv["private_name"].get("hostname") or "unknown")
        elif srv.get("private_ip"):
            stype = "Private IP"
            addr  = (srv["private_ip"].get("ip") or
                     srv["private_ip"].get("ipv4") or "unknown")
        elif srv.get("k8s_service"):
            stype = "K8s Service"
            addr  = (srv["k8s_service"].get("service_name") or "unknown")
        elif srv.get("consul_service"):
            stype = "Consul"
            addr  = (srv["consul_service"].get("service_name") or "unknown")
        elif srv.get("custom_endpoint_object"):
            stype = "Custom Endpoint"
            addr  = str(srv["custom_endpoint_object"])
        elif srv.get("vn_private_name"):
            stype = "VN Private DNS"
            addr  = (srv["vn_private_name"].get("dns_name") or "unknown")
        elif srv.get("vn_private_ip"):
            stype = "VN Private IP"
            addr  = (srv["vn_private_ip"].get("ip") or "unknown")
        else:
            stype = "Unknown"
            addr  = str(srv)

        # Site/vsite label if present
        site = ""
        for site_key in ("site_locator", "site", "virtual_site"):
            sl = srv.get(site_key)
            if sl and isinstance(sl, dict):
                site_ref = sl.get("site") or sl.get("virtual_site") or sl
                if isinstance(site_ref, dict):
                    refs = site_ref.get("ref", [])
                    if refs:
                        site = refs[0].get("name", "")
                        break

        servers.append({"type": stype, "address": addr, "site": site})

    result = {"port": port, "lb_algorithm": lb_algo, "servers": servers}
    _origin_pool_cache[cache_key] = result
    return result


def extract_api_protection(spec):
    """Extract API Definition and API Discovery status from LB spec."""
    if not spec:
        return {"api_definition_enabled": False, "api_definition_name": None,
                "api_discovery_enabled": False}

    api_def_enabled = False
    api_def_name    = None
    api_disc_enabled = False

    # API protection is typically nested under api_protection or api_specification
    api_prot = spec.get("api_protection") or {}

    # --- API Definition ---
    # Can be at spec level or inside api_protection
    for block in (spec, api_prot):
        # Check enable_api_definition / api_definition
        for key in ("api_definition", "api_specification", "enable_api_definition"):
            val = block.get(key)
            if not val:
                continue
            if isinstance(val, dict):
                api_def_enabled = True
                ns, name = _resolve_ref(val)
                if name:
                    api_def_name = f"{ns}/{name}" if ns else name
                # Sometimes nested one more level
                inner = val.get("api_definition") or val.get("definition")
                if inner and isinstance(inner, dict):
                    ns2, name2 = _resolve_ref(inner)
                    if name2:
                        api_def_name = f"{ns2}/{name2}" if ns2 else name2
            elif isinstance(val, str) and val.lower() not in ("", "disable", "disabled"):
                api_def_enabled = True

    # Fallback: check for presence of disable_api_definition
    if not api_def_enabled:
        for block in (spec, api_prot):
            if block.get("disable_api_definition") is not None:
                api_def_enabled = False
            # Empty dict for api_definition means enabled with no ref
            if "api_definition" in block and block["api_definition"] == {}:
                api_def_enabled = False

    # --- API Discovery ---
    for block in (spec, api_prot):
        for key in ("api_discovery", "enable_api_discovery"):
            val = block.get(key)
            if val is None:
                continue
            if isinstance(val, dict):
                # Present as a block = enabled (unless explicitly disabled inside)
                if val.get("disable") or val.get("disabled"):
                    api_disc_enabled = False
                else:
                    api_disc_enabled = True
            elif isinstance(val, str):
                api_disc_enabled = val.lower() not in ("", "disable", "disabled")
            elif isinstance(val, bool):
                api_disc_enabled = val

    # Check for disable_api_discovery as explicit off
    for block in (spec, api_prot):
        if block.get("disable_api_discovery") is not None:
            api_disc_enabled = False

    return {
        "api_definition_enabled": api_def_enabled,
        "api_definition_name":    api_def_name,
        "api_discovery_enabled":  api_disc_enabled,
    }


# ── Table Rendering ───────────────────────────────────────────────────────────

# Column definitions: (header, width)
COLS = [
    ("Load Balancer",  24),
    ("Domains",        32),
    ("WAF Policy",     28),
    ("API Definition", 28),
    ("API Disc.",      10),
    ("Origin Pool",    28),
    ("Origin Servers", 36),
]


def trunc(text, width):
    """Truncate text with ellipsis if too wide."""
    if len(text) <= width:
        return text
    return text[:width - 2] + ".."


def table_header():
    """Return header + separator lines."""
    hdr  = " │ ".join(h.ljust(w) for h, w in COLS)
    sep  = "─┼─".join("─" * w for _, w in COLS)
    return hdr, sep


def table_row(vals):
    """Render one row. vals = list of strings matching COLS order."""
    cells = []
    for i, (_, w) in enumerate(COLS):
        v = vals[i] if i < len(vals) else ""
        cells.append(trunc(v, w).ljust(w))
    return " │ ".join(cells)


def blank_row_with(col_idx, value):
    """Row with only one column filled (for continuation lines)."""
    cells = []
    for i, (_, w) in enumerate(COLS):
        v = value if i == col_idx else ""
        cells.append(trunc(v, w).ljust(w))
    return " │ ".join(cells)


def print_namespace_table(ns, lb_records):
    """Print a full table for one namespace."""
    total_width = sum(w for _, w in COLS) + 3 * (len(COLS) - 1)
    hdr, sep = table_header()

    print(f"\n{'═' * total_width}")
    print(f"  NAMESPACE: {ns}  ({len(lb_records)} HTTP LB(s))")
    print(f"{'═' * total_width}")
    print(hdr)
    print(sep)

    for rec in lb_records:
        lb_name  = rec["lb_name"]
        domains  = ", ".join(rec["domains"]) if rec["domains"] else "—"
        waf      = ", ".join(f"{w['namespace']}/{w['name']}" for w in rec["waf_policies"]) \
                   if rec["waf_policies"] else "NONE"
        api_def  = "Disabled"
        if rec["api_definition"]["api_definition_enabled"]:
            api_def = rec["api_definition"]["api_definition_name"] or "Enabled (unnamed)"
        api_disc = "Enabled" if rec["api_definition"]["api_discovery_enabled"] else "Disabled"

        pools = rec["origin_pools"]
        if not pools:
            print(table_row([lb_name, domains, waf, api_def, api_disc, "NONE", "—"]))
        else:
            first = True
            for pool in pools:
                pool_name = pool["pool"]
                port      = pool.get("port", "N/A")
                servers   = pool.get("servers", [])

                if not servers:
                    srv_str = "— (no origins)"
                    if first:
                        print(table_row([lb_name, domains, waf, api_def, api_disc,
                                         pool_name, srv_str]))
                        first = False
                    else:
                        # Continuation row: only pool + server columns filled
                        print(table_row(["", "", "", "", "", pool_name, srv_str]))
                else:
                    for si, srv in enumerate(servers):
                        site_tag = f" @{srv['site']}" if srv.get("site") else ""
                        srv_str  = f"[{srv['type']}] {srv['address']}:{port}{site_tag}"

                        if first:
                            pool_disp = pool_name if si == 0 else ""
                            print(table_row([lb_name, domains, waf, api_def, api_disc,
                                             pool_disp, srv_str]))
                            first = False
                        else:
                            pool_disp = pool_name if si == 0 else ""
                            print(table_row(["", "", "", "", "", pool_disp, srv_str]))

        # Thin separator between LBs within the same namespace
        if rec != lb_records[-1]:
            print("─┼─".join("─" * w for _, w in COLS))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    total_width = sum(w for _, w in COLS) + 3 * (len(COLS) - 1)
    print(f"\n{'═' * total_width}")
    print(f"  F5 XC Full Inventory — Tenant: {TENANT}")
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
                    "lb_name": lb_name, "domains": [], "waf_policies": [],
                    "api_definition": {"api_definition_enabled": False,
                                       "api_definition_name": None,
                                       "api_discovery_enabled": False},
                    "origin_pools": [],
                })
                continue

            spec = lb_obj.get("spec") or lb_obj.get("get_spec") or {}

            domains      = extract_domains(spec)
            waf_policies = extract_waf_info(spec)
            pool_refs    = extract_origin_pool_refs(spec)
            api_info     = extract_api_protection(spec)

            # Resolve origin pool details
            pool_details = []
            for pr in pool_refs:
                pool_ns   = pr["namespace"] or ns
                pool_name = pr["name"]
                details   = get_origin_pool_details(pool_ns, pool_name)
                if details:
                    pool_details.append({
                        "pool":    f"{pool_ns}/{pool_name}",
                        "port":    details["port"],
                        "servers": details["servers"],
                    })
                else:
                    pool_details.append({
                        "pool": f"{pool_ns}/{pool_name}",
                        "port": "N/A", "servers": [],
                    })

            rec = {
                "namespace":      ns,
                "lb_name":        lb_name,
                "domains":        domains,
                "waf_policies":   waf_policies,
                "api_definition": api_info,
                "origin_pools":   pool_details,
            }
            ns_records.append(rec)
            summary.append(rec)

        print_namespace_table(ns, ns_records)

    # ── Summary ──
    total_lbs   = len(summary)
    with_waf    = sum(1 for s in summary if s["waf_policies"])
    no_waf      = total_lbs - with_waf
    with_apidef = sum(1 for s in summary if s["api_definition"]["api_definition_enabled"])
    with_disc   = sum(1 for s in summary if s["api_definition"]["api_discovery_enabled"])

    print(f"\n{'═' * total_width}")
    print(f"  SUMMARY")
    print(f"{'═' * total_width}")
    print(f"  Namespaces scanned    : {len(namespaces)}")
    print(f"  Namespaces with LBs   : {ns_with_lbs}")
    print(f"  Total HTTP LBs        : {total_lbs}")
    print(f"  With WAF policy       : {with_waf}")
    print(f"  WITHOUT WAF policy    : {no_waf}  {'⚠️  review recommended' if no_waf else '✓'}")
    print(f"  API Definition on     : {with_apidef}")
    print(f"  API Discovery on      : {with_disc}")
    print(f"  Origin pools resolved : {len(_origin_pool_cache)}")
    print(f"{'═' * total_width}")

    output_file = "f5xc_inventory.json"
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Full inventory written to {output_file}\n")


if __name__ == "__main__":
    main()
