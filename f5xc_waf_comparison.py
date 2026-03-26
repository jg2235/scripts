#!/usr/bin/env python3
"""
F5 Distributed Cloud - WAF (App Firewall) Policy Comparison
Enumerates all WAF policies across shared + all namespaces and displays
a side-by-side comparison table of settings grouped by namespace.
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


# ── Data Collection ───────────────────────────────────────────────────────────

def list_namespaces():
    data = api("GET", "/api/web/namespaces")
    if not data or "items" not in data:
        sys.exit("Failed to retrieve namespaces. Check tenant name and API token.")
    return [item["name"] for item in data["items"]]


def list_waf_names(namespace):
    """List WAF policy names in a namespace (from abbreviated LIST)."""
    data = api("GET", f"/api/config/namespaces/{namespace}/app_firewalls")
    if not data or "items" not in data:
        return []
    names = []
    for item in data["items"]:
        name = item.get("name")
        if not name:
            name = (item.get("metadata") or {}).get("name")
        if name:
            names.append(name)
    return names


def get_waf(namespace, name):
    """GET full WAF policy object."""
    return api("GET", f"/api/config/namespaces/{namespace}/app_firewalls/{name}")


# ── Settings Extraction ──────────────────────────────────────────────────────
# WAF spec uses mutually-exclusive keys to indicate chosen option.
# We normalize each setting to a human-readable string.

def extract_settings(spec):
    """Parse WAF spec into a normalized settings dict."""
    s = {}

    # 1. Enforcement Mode: blocking | monitoring
    if "blocking" in spec:
        s["Enforcement Mode"] = "Blocking"
    elif "monitoring" in spec:
        s["Enforcement Mode"] = "Monitoring"
    else:
        s["Enforcement Mode"] = "Default"

    # 2. Detection Settings: default_detection_settings | detection_settings (custom)
    if "detection_settings" in spec:
        ds = spec["detection_settings"] or {}
        s["Detection Settings"] = "Custom"

        # 2a. Signature Accuracy
        sig = ds.get("signature_selection_setting") or {}
        if "high_medium_low_accuracy_signatures" in sig:
            s["Signature Accuracy"] = "High + Medium + Low"
        elif "high_medium_accuracy_signatures" in sig:
            s["Signature Accuracy"] = "High + Medium"
        elif "high_accuracy_signatures" in sig:
            s["Signature Accuracy"] = "High Only"
        elif "only_custom_signatures" in sig:
            s["Signature Accuracy"] = "Custom Only"
        else:
            s["Signature Accuracy"] = "Default"

        # 2b. Attack Type Settings
        if "default_attack_type_settings" in sig:
            s["Attack Type Settings"] = "Default"
        elif "custom_attack_type_settings" in sig:
            s["Attack Type Settings"] = "Custom"
        else:
            s["Attack Type Settings"] = "Default"

        # 2c. Staging
        if "disable_staging" in ds:
            s["Staging"] = "Disabled"
        elif "enable_staging" in ds:
            s["Staging"] = "Enabled"
        else:
            s["Staging"] = "Default"

        # 2d. Suppression
        if "enable_suppression" in ds:
            s["Suppression"] = "Enabled"
        elif "disable_suppression" in ds:
            s["Suppression"] = "Disabled"
        else:
            s["Suppression"] = "Default"

        # 2e. Threat Campaigns
        if "enable_threat_campaigns" in ds:
            s["Threat Campaigns"] = "Enabled"
        elif "disable_threat_campaigns" in ds:
            s["Threat Campaigns"] = "Disabled"
        else:
            s["Threat Campaigns"] = "Default"

        # 2f. Violation Settings
        vs = ds.get("violation_settings") or {}
        if "disabled_violation_types" in vs:
            disabled = vs["disabled_violation_types"]
            s["Disabled Violations"] = str(len(disabled))
        elif "default_violation_settings" in ds:
            s["Disabled Violations"] = "0 (all default)"
        else:
            s["Disabled Violations"] = "0 (all default)"

    elif "default_detection_settings" in spec:
        s["Detection Settings"] = "Default"
        s["Signature Accuracy"] = "Default"
        s["Attack Type Settings"] = "Default"
        s["Staging"] = "Default"
        s["Suppression"] = "Default"
        s["Threat Campaigns"] = "Default"
        s["Disabled Violations"] = "0 (all default)"
    else:
        s["Detection Settings"] = "Default"
        s["Signature Accuracy"] = "Default"
        s["Attack Type Settings"] = "Default"
        s["Staging"] = "Default"
        s["Suppression"] = "Default"
        s["Threat Campaigns"] = "Default"
        s["Disabled Violations"] = "0 (all default)"

    # 3. Bot Protection
    # Can be at spec level or inside detection_settings
    bot = spec.get("bot_protection_setting")
    if not bot:
        ds = spec.get("detection_settings") or {}
        bot = ds.get("bot_protection_setting")

    if bot and isinstance(bot, dict):
        s["Bot Protection"] = "Custom"
        s["  Good Bot"] = bot.get("good_bot_action", "DEFAULT")
        s["  Malicious Bot"] = bot.get("malicious_bot_action", "DEFAULT")
        s["  Suspicious Bot"] = bot.get("suspicious_bot_action", "DEFAULT")
    elif "default_bot_setting" in spec:
        s["Bot Protection"] = "Default"
        s["  Good Bot"] = "DEFAULT"
        s["  Malicious Bot"] = "DEFAULT"
        s["  Suspicious Bot"] = "DEFAULT"
    else:
        s["Bot Protection"] = "Default"
        s["  Good Bot"] = "DEFAULT"
        s["  Malicious Bot"] = "DEFAULT"
        s["  Suspicious Bot"] = "DEFAULT"

    # 4. Blocking Page
    if "use_default_blocking_page" in spec:
        s["Blocking Page"] = "Default"
    elif "blocking_page" in spec:
        bp = spec["blocking_page"] or {}
        code = bp.get("response_code", "N/A")
        s["Blocking Page"] = f"Custom (HTTP {code})"
    else:
        s["Blocking Page"] = "Default"

    # 5. Response Codes
    if "allow_all_response_codes" in spec:
        s["Response Codes"] = "Allow All"
    elif "allowed_response_codes" in spec:
        codes = spec["allowed_response_codes"]
        if isinstance(codes, dict):
            code_list = codes.get("response_codes", [])
            s["Response Codes"] = ", ".join(str(c) for c in code_list) if code_list else "Custom"
        else:
            s["Response Codes"] = "Custom"
    else:
        s["Response Codes"] = "Default"

    # 6. Anonymization
    if "default_anonymization" in spec:
        s["Anonymization"] = "Default"
    elif "custom_anonymization" in spec:
        s["Anonymization"] = "Custom"
    elif "disable_anonymization" in spec:
        s["Anonymization"] = "Disabled"
    else:
        s["Anonymization"] = "Default"

    # 7. AI Enhancements
    ai = spec.get("enable_ai_enhancements")
    if ai and isinstance(ai, dict):
        if "mitigate_high_medium_risk_action" in ai:
            s["AI Enhancements"] = "High + Medium Risk"
        elif "mitigate_high_risk_action" in ai:
            s["AI Enhancements"] = "High Risk Only"
        else:
            s["AI Enhancements"] = "Enabled"
    elif "disable_ai_enhancements" in spec:
        s["AI Enhancements"] = "Disabled"
    else:
        s["AI Enhancements"] = "Disabled"

    return s


# ── Table Rendering ──────────────────────────────────────────────────────────

# Ordered list of setting keys for display
SETTING_ORDER = [
    "Enforcement Mode",
    "Detection Settings",
    "Signature Accuracy",
    "Attack Type Settings",
    "Staging",
    "Suppression",
    "Threat Campaigns",
    "Disabled Violations",
    "Bot Protection",
    "  Good Bot",
    "  Malicious Bot",
    "  Suspicious Bot",
    "Blocking Page",
    "Response Codes",
    "Anonymization",
    "AI Enhancements",
]

SETTING_COL_W = 24
POLICY_COL_W  = 22


def trunc(text, width):
    if len(text) <= width:
        return text
    return text[:width - 2] + ".."


def render_comparison(ns, policies):
    """Render a side-by-side comparison table for policies in a namespace.
    policies = list of (name, settings_dict)
    """
    n = len(policies)
    total_w = SETTING_COL_W + 3 + (POLICY_COL_W + 3) * n - 3

    print(f"\n{'═' * max(total_w, 60)}")
    print(f"  NAMESPACE: {ns}  ({n} WAF polic{'y' if n == 1 else 'ies'})")
    print(f"{'═' * max(total_w, 60)}")

    # Header row: Setting | Policy1 | Policy2 | ...
    hdr_cells = ["Setting".ljust(SETTING_COL_W)]
    for name, _ in policies:
        hdr_cells.append(trunc(name, POLICY_COL_W).ljust(POLICY_COL_W))
    print(" │ ".join(hdr_cells))

    sep_cells = ["─" * SETTING_COL_W]
    for _ in policies:
        sep_cells.append("─" * POLICY_COL_W)
    print("─┼─".join(sep_cells))

    # Data rows
    for setting_key in SETTING_ORDER:
        cells = [trunc(setting_key, SETTING_COL_W).ljust(SETTING_COL_W)]
        values = []
        for _, settings in policies:
            val = settings.get(setting_key, "—")
            values.append(val)
            cells.append(trunc(val, POLICY_COL_W).ljust(POLICY_COL_W))

        # Highlight differences: mark row if values differ
        unique = set(values)
        marker = " ◀ DIFF" if len(unique) > 1 else ""

        print(" │ ".join(cells) + marker)

    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'═' * 70}")
    print(f"  F5 XC WAF Policy Comparison — Tenant: {TENANT}")
    print(f"{'═' * 70}")

    namespaces = list_namespaces()
    print(f"  Scanning {len(namespaces)} namespace(s)...\n")

    all_policies = []   # (ns, name, settings) for JSON output
    ns_count = 0
    total_policies = 0

    # Always process shared first
    ordered_ns = ["shared"] + [ns for ns in namespaces if ns != "shared"]

    for ns in ordered_ns:
        waf_names = list_waf_names(ns)
        if not waf_names:
            continue

        ns_count += 1
        ns_policies = []

        for name in waf_names:
            obj = get_waf(ns, name)
            if not obj:
                continue
            spec = obj.get("spec") or obj.get("get_spec") or {}
            settings = extract_settings(spec)
            ns_policies.append((name, settings))
            all_policies.append({"namespace": ns, "name": name, "settings": settings})
            total_policies += 1

        if ns_policies:
            render_comparison(ns, ns_policies)

    # ── Summary ──
    print(f"{'═' * 70}")
    print(f"  SUMMARY")
    print(f"{'═' * 70}")
    print(f"  Namespaces scanned      : {len(namespaces)}")
    print(f"  Namespaces with WAF     : {ns_count}")
    print(f"  Total WAF policies      : {total_policies}")

    # Quick stats
    modes = {}
    for p in all_policies:
        mode = p["settings"].get("Enforcement Mode", "Unknown")
        modes[mode] = modes.get(mode, 0) + 1
    for mode, count in sorted(modes.items()):
        print(f"  {mode:25s}: {count}")

    print(f"{'═' * 70}")

    output_file = "f5xc_waf_comparison.json"
    with open(output_file, "w") as f:
        json.dump(all_policies, f, indent=2)
    print(f"\n  Full comparison written to {output_file}\n")


if __name__ == "__main__":
    main()
