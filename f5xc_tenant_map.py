#!/usr/bin/env python3
"""
f5xc_inventory_map.py — F5 Distributed Cloud tenant visual topology map.

For every accessible namespace, walks:
    HTTP LB  ──► Origin Pool(s)  ──► Health Check(s)
             └─► App Firewall (WAF)

Captures per-LB:
    • domain(s)
    • TLS mode (http / https-auto / https-custom / no-advertise)
    • certificate expiration (auto-cert state OR custom cert_chain lookup)
    • API Discovery enabled / disabled
    • attached WAF (or disable_waf flag)

Renders a single self-contained HTML file: Mermaid topology + detail table
per namespace. Optional JSON dump.

ENV
    F5XC_TENANT      e.g. "f5-amer-ent"
    F5XC_API_TOKEN   token with read access

USAGE
    python f5xc_inventory_map.py                         # -> f5xc_map.html
    python f5xc_inventory_map.py -o tenant.html --json tenant.json
    python f5xc_inventory_map.py --namespaces j-granieri,shared --workers 24
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

# Optional: only used as a last-resort fallback for custom cert expiry
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False


# ───────────────────────────── API client ──────────────────────────────────

class XC:
    def __init__(self, tenant: str, token: str, timeout: int = 30):
        self.base = f"https://{tenant}.console.ves.volterra.io"
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"APIToken {token}",
            "Content-Type":  "application/json",
        })

    def get(self, path: str) -> dict:
        r = self.s.get(self.base + path, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def try_get(self, path: str):
        try:
            r = self.s.get(self.base + path, timeout=self.timeout)
        except requests.RequestException as e:
            return {"__error__": str(e)}
        if r.status_code in (401, 403, 404):
            return None
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            return {"__error__": f"{r.status_code} {e}"}
        return r.json()


# ───────────────────────────── extractors ──────────────────────────────────

def _spec_of(obj: dict) -> dict:
    if not obj:
        return {}
    return obj.get("spec") or (obj.get("replace_form") or {}).get("spec") or {}


def _find_key_like(obj, needles: tuple, depth: int = 0, max_depth: int = 6):
    """Recursively search obj for a key whose name contains any needle (case-insensitive).
    Returns the first non-empty scalar value found."""
    if depth > max_depth or obj is None:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                lk = k.lower()
                if any(n in lk for n in needles) and isinstance(v, (int, float, str)) and v:
                    return v
            found = _find_key_like(v, needles, depth + 1, max_depth)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_key_like(v, needles, depth + 1, max_depth)
            if found:
                return found
    return None


def _ts_to_iso(v):
    """Normalize epoch-seconds/ms int/float or ISO string to ISO8601 UTC."""
    if not v:
        return None
    try:
        if isinstance(v, (int, float)):
            if v > 1e12:      # millis
                v = v / 1000.0
            return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
        s = str(v).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def _api_discovery(spec: dict) -> str:
    """'on' / 'off' based on HTTP LB spec oneof."""
    if "enable_api_discovery" in spec:
        return "on"
    if "disable_api_discovery" in spec:
        return "off"
    if "api_discovery" in spec:
        return "on" if spec["api_discovery"] else "off"
    return "off"


def _tls_info(spec: dict):
    """Return (mode, cert_refs). mode ∈ {http, https-auto, https-custom, no-advertise, unknown}."""
    if "http" in spec:
        return "http", []
    if "https_auto_cert" in spec:
        return "https-auto", []
    if "do_not_advertise" in spec:
        return "no-advertise", []
    if "https" in spec:
        https = spec["https"] or {}
        certs = []
        tcp = https.get("tls_cert_params") or {}
        for c in tcp.get("certificates", []) or []:
            if c.get("name"):
                certs.append({"name": c["name"], "namespace": c.get("namespace") or ""})
        dlb = https.get("default_loadbalancer") or {}
        tlsp = dlb.get("tls_parameters") or {}
        for c in (tlsp.get("tls_certificates") or tlsp.get("certificates") or []):
            if c.get("name"):
                certs.append({"name": c["name"], "namespace": c.get("namespace") or ""})
        return "https-custom", certs
    return "unknown", []


def _extract_lb(full_obj: dict) -> dict:
    spec = _spec_of(full_obj)

    pools = []
    for p in spec.get("default_route_pools", []) or []:
        pool = p.get("pool") or {}
        if pool.get("name"):
            pools.append({"name": pool["name"], "namespace": pool.get("namespace") or ""})
    for route in spec.get("routes", []) or []:
        sr = ((route.get("simple_route") or {}).get("origin_pools")) or []
        for p in sr:
            pool = p.get("pool") or {}
            if pool.get("name"):
                pools.append({"name": pool["name"], "namespace": pool.get("namespace") or ""})

    wafs = []
    fw = spec.get("app_firewall")
    if isinstance(fw, dict) and fw.get("name"):
        wafs.append({"name": fw["name"], "namespace": fw.get("namespace") or ""})

    tls_mode, cert_refs = _tls_info(spec)

    # Auto-cert: scan the whole LB response for an expiration-like field
    auto_cert_expiry = None
    if tls_mode == "https-auto":
        auto_cert_expiry = _ts_to_iso(_find_key_like(full_obj, ("expir", "not_after", "valid_until")))

    return {
        "domains":          spec.get("domains") or [],
        "pools":            _dedupe(pools),
        "wafs":             wafs,
        "waf_disabled":     "disable_waf" in spec,
        "tls_mode":         tls_mode,
        "cert_refs":        cert_refs,
        "auto_cert_expiry": auto_cert_expiry,
        "api_discovery":    _api_discovery(spec),
    }


def _extract_pool(spec: dict) -> dict:
    origins = []
    for o in spec.get("origin_servers", []) or []:
        for kind, v in o.items():
            if kind == "labels" or not isinstance(v, dict):
                continue
            tgt = (v.get("dns_name") or v.get("ip") or v.get("service_name")
                   or v.get("vhost_name") or v.get("fqdn") or kind)
            origins.append({"type": kind, "target": str(tgt)})
            break
    hcs = []
    for h in spec.get("healthcheck", []) or []:
        if h.get("name"):
            hcs.append({"name": h["name"], "namespace": h.get("namespace") or ""})
    return {"origins": origins, "healthchecks": hcs, "port": spec.get("port")}


def _dedupe(items):
    seen, out = set(), []
    for i in items:
        k = (i.get("name"), i.get("namespace"))
        if k not in seen:
            seen.add(k); out.append(i)
    return out


# ─────────────────────── cert chain resolution ─────────────────────────────

def resolve_cert(xc: XC, ns: str, name: str, cache: dict) -> dict:
    """Fetch cert_chain + extract expiry. Cached by (ns, name)."""
    key = (ns, name)
    if key in cache:
        return cache[key]
    out = {"expiry": None, "error": None}
    obj = xc.try_get(f"/api/config/namespaces/{ns}/certificate_chains/{name}?response_format=2")
    if obj is None:
        out["error"] = "not accessible"; cache[key] = out; return out
    if "__error__" in obj:
        out["error"] = obj["__error__"]; cache[key] = out; return out

    iso = _ts_to_iso(_find_key_like(obj, ("expir", "not_after", "valid_until")))
    if iso:
        out["expiry"] = iso; cache[key] = out; return out

    if _HAVE_CRYPTO:
        spec = _spec_of(obj)
        for c in spec.get("certificates", []) or []:
            pem = c.get("certificate") or c.get("cert") or c.get("certificate_url")
            if isinstance(pem, str) and "BEGIN CERTIFICATE" in pem:
                try:
                    cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
                    na = getattr(cert, "not_valid_after_utc", None) or \
                         cert.not_valid_after.replace(tzinfo=timezone.utc)
                    out["expiry"] = na.isoformat()
                    cache[key] = out; return out
                except Exception as e:
                    out["error"] = f"pem parse: {e}"

    if not out["error"]:
        out["error"] = "no expiration field found"
    cache[key] = out
    return out


def days_until(iso):
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return None


# ───────────────────────── per-namespace collection ────────────────────────

def collect_namespace(xc: XC, ns: str, cert_cache: dict) -> dict:
    out = {"namespace": ns, "lbs": [], "pools": {}, "hcs": {}, "wafs": {}, "error": None}

    lb_list = xc.try_get(f"/api/config/namespaces/{ns}/http_loadbalancers")
    if lb_list is None:
        out["error"] = "no read access"; return out
    if "__error__" in lb_list:
        out["error"] = lb_list["__error__"]; return out

    for item in lb_list.get("items", []):
        name = item["name"]
        obj = xc.try_get(f"/api/config/namespaces/{ns}/http_loadbalancers/{name}?response_format=2")
        if not obj or "__error__" in (obj or {}):
            continue
        lb = {"name": name, **_extract_lb(obj)}

        lb["cert_expiry"] = None
        lb["cert_expiry_error"] = None
        if lb["tls_mode"] == "https-custom" and lb["cert_refs"]:
            earliest = None
            errors = []
            for ref in lb["cert_refs"]:
                c_ns = ref["namespace"] or ns
                ci = resolve_cert(xc, c_ns, ref["name"], cert_cache)
                if ci["expiry"] and (earliest is None or ci["expiry"] < earliest):
                    earliest = ci["expiry"]
                if ci["error"]:
                    errors.append(f'{c_ns}/{ref["name"]}: {ci["error"]}')
            lb["cert_expiry"] = earliest
            lb["cert_expiry_error"] = "; ".join(errors) if errors else None
        elif lb["tls_mode"] == "https-auto":
            lb["cert_expiry"] = lb["auto_cert_expiry"]

        out["lbs"].append(lb)

    pool_list = xc.try_get(f"/api/config/namespaces/{ns}/origin_pools") or {}
    for item in pool_list.get("items", []):
        pname = item["name"]
        obj = xc.try_get(f"/api/config/namespaces/{ns}/origin_pools/{pname}?response_format=2")
        out["pools"][pname] = _extract_pool(_spec_of(obj)) if obj and "__error__" not in obj else {
            "origins": [], "healthchecks": [], "port": None}

    hc_list = xc.try_get(f"/api/config/namespaces/{ns}/healthchecks") or {}
    for item in hc_list.get("items", []):
        out["hcs"][item["name"]] = {"description": item.get("description", "")}

    waf_list = xc.try_get(f"/api/config/namespaces/{ns}/app_firewalls") or {}
    for item in waf_list.get("items", []):
        out["wafs"][item["name"]] = {"description": item.get("description", "")}

    return out


# ──────────────────────────── rendering ────────────────────────────────────

TLS_BADGE = {
    "http":          ('HTTP',       '#8b949e'),
    "https-auto":    ('HTTPS auto', '#2ea043'),
    "https-custom":  ('HTTPS cert', '#1f6feb'),
    "no-advertise":  ('no-advert',  '#6e7681'),
    "unknown":       ('unknown',    '#6e7681'),
}


def _mm_id(kind, ns, name):
    raw = f"{kind}__{ns}__{name}"
    return "".join(c if c.isalnum() else "_" for c in raw)


def _mm_txt(s, n=60):
    return (s or "").replace('"', "'").replace("\n", " ").replace("|", "/")[:n]


def namespace_mermaid(nd: dict) -> str:
    ns = nd["namespace"]
    L = ["graph LR",
         "  classDef lb   fill:#1f6feb,color:#fff,stroke:#0a3a8c,stroke-width:1px;",
         "  classDef pool fill:#2ea043,color:#fff,stroke:#1a6e2b;",
         "  classDef hc   fill:#f2cc60,color:#000,stroke:#9a7500;",
         "  classDef waf  fill:#db4b7b,color:#fff,stroke:#8a1e4a;",
         "  classDef ext  fill:#21262d,color:#c9d1d9,stroke:#6e7681,stroke-dasharray:3 3;"]
    declared = set()

    def dec(nid, line):
        if nid not in declared:
            L.append(line); declared.add(nid)

    for lb in nd["lbs"]:
        lb_id = _mm_id("lb", ns, lb["name"])
        dom = lb["domains"][0] if lb["domains"] else ""
        extra = " +%d" % (len(lb["domains"]) - 1) if len(lb["domains"]) > 1 else ""
        tls = {"http": "🔓", "https-auto": "🔒", "https-custom": "🔒",
               "no-advertise": "⊘"}.get(lb["tls_mode"], "?")
        apid = "📡" if lb["api_discovery"] == "on" else ""
        subtitle = f'{tls} {_mm_txt(dom, 40)}{extra} {apid}'.strip()
        dec(lb_id, f'  {lb_id}["🌐 {_mm_txt(lb["name"])}<br/><small>{subtitle}</small>"]:::lb')

        for pref in lb["pools"]:
            pns = pref["namespace"] or ns
            pid = _mm_id("pool", pns, pref["name"])
            if pns == ns and pref["name"] in nd["pools"]:
                pd = nd["pools"][pref["name"]]
                port = pd.get("port")
                origins = "; ".join(o["target"] for o in pd["origins"][:3])
                if len(pd["origins"]) > 3:
                    origins += f" (+{len(pd['origins']) - 3})"
                lbl = _mm_txt(pref["name"])
                if port:
                    lbl += f'<br/><small>:{port}</small>'
                if origins:
                    lbl += f'<br/><small>{_mm_txt(origins, 50)}</small>'
                dec(pid, f'  {pid}("🎯 {lbl}"):::pool')
                for href in pd["healthchecks"]:
                    hns = href["namespace"] or ns
                    hid = _mm_id("hc", hns, href["name"])
                    hlbl = _mm_txt(href["name"]) + (f" [{hns}]" if hns != ns else "")
                    dec(hid, f'  {hid}{{"❤ {hlbl}"}}:::hc')
                    L.append(f'  {pid} -.hc.-> {hid}')
            else:
                dec(pid, f'  {pid}("🎯 {_mm_txt(pref["name"])}<br/><small>[{pns}]</small>"):::ext')
            L.append(f'  {lb_id} --> {pid}')

        for wref in lb["wafs"]:
            wns = wref["namespace"] or ns
            wid = _mm_id("waf", wns, wref["name"])
            cls = "waf" if wns == ns else "ext"
            wlbl = _mm_txt(wref["name"]) + (f" [{wns}]" if wns != ns else "")
            dec(wid, f'  {wid}[["🛡 {wlbl}"]]:::{cls}')
            L.append(f'  {lb_id} -.waf.-> {wid}')
        if lb["waf_disabled"]:
            wid = _mm_id("wafoff", ns, lb["name"])
            dec(wid, f'  {wid}[["⚠ WAF disabled"]]:::ext')
            L.append(f'  {lb_id} -.-> {wid}')

    return "\n".join(L)


def _fmt_expiry(iso, err=None):
    if not iso:
        return f'<span class="exp-unk">{html.escape(err) if err else "—"}</span>'
    d = days_until(iso)
    date = iso.split("T")[0]
    if d is None:
        return html.escape(date)
    if d < 0:
        return f'<span class="exp-expired">{date} ({abs(d)}d ago)</span>'
    if d <= 30:
        return f'<span class="exp-warn">{date} ({d}d)</span>'
    return f'{date} <small>({d}d)</small>'


def namespace_table(nd: dict) -> str:
    if not nd["lbs"]:
        return ""
    rows = []
    for lb in nd["lbs"]:
        domain = ", ".join(lb["domains"]) or "—"
        tls_label, tls_color = TLS_BADGE.get(lb["tls_mode"], TLS_BADGE["unknown"])
        tls_cell = f'<span class="badge" style="background:{tls_color}">{tls_label}</span>'
        exp_cell = "—" if lb["tls_mode"] == "http" \
            else _fmt_expiry(lb.get("cert_expiry"), lb.get("cert_expiry_error"))
        apid = ('<span class="badge on">ON</span>' if lb["api_discovery"] == "on"
                else '<span class="badge off">off</span>')
        waf_list = [html.escape(w["name"]) + (f" [{w['namespace']}]" if w["namespace"] else "")
                    for w in lb["wafs"]]
        waf_cell = (", ".join(waf_list) if waf_list
                    else ('<span class="badge off">disabled</span>' if lb["waf_disabled"]
                          else '<span class="badge off">none</span>'))
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(lb['name'])}</code></td>"
            f"<td>{html.escape(domain)}</td>"
            f"<td>{tls_cell}</td>"
            f"<td>{exp_cell}</td>"
            f"<td>{apid}</td>"
            f"<td>{waf_cell}</td>"
            "</tr>"
        )
    return (
        '<table class="lbtbl"><thead><tr>'
        '<th>LB</th><th>Domain(s)</th><th>TLS</th>'
        '<th>Cert expiry</th><th>API Disc.</th><th>WAF</th>'
        '</tr></thead><tbody>' + "".join(rows) + "</tbody></table>"
    )


HTML_TPL = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>F5 XC Tenant Map — {tenant}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;margin:0;background:#0d1117;color:#e6edf3}}
header{{padding:18px 28px;background:#161b22;border-bottom:1px solid #30363d;position:sticky;top:0;z-index:10}}
header h1{{margin:0 0 4px;font-size:20px}}
header .meta{{color:#8b949e;font-size:12px}}
.stats{{display:flex;gap:14px;margin-top:12px;flex-wrap:wrap}}
.stat{{background:#0d1117;padding:8px 12px;border-radius:6px;border:1px solid #30363d;min-width:90px}}
.stat b{{display:block;font-size:18px;color:#58a6ff}}
.stat span{{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}}
.legend{{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;font-size:11px}}
.legend span{{padding:2px 7px;border-radius:3px;color:#fff}}
.tag-lb{{background:#1f6feb}}.tag-pool{{background:#2ea043}}
.tag-hc{{background:#f2cc60;color:#000}}.tag-waf{{background:#db4b7b}}
main{{padding:18px 28px;max-width:1500px;margin:0 auto}}
details{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:14px}}
summary{{padding:12px 18px;cursor:pointer;font-weight:600;font-size:14px;
  display:flex;justify-content:space-between;align-items:center;gap:12px;list-style:none}}
summary::-webkit-details-marker{{display:none}}
summary::before{{content:"▸";margin-right:6px;color:#8b949e}}
details[open] summary::before{{content:"▾"}}
summary:hover{{background:#1c2128}}
summary .counts{{color:#8b949e;font-weight:400;font-size:11px;font-family:ui-monospace,monospace}}
.diagram{{padding:12px;background:#fff;border-radius:6px;margin:0 18px 12px;overflow:auto}}
.empty{{padding:10px 18px 14px;color:#8b949e;font-style:italic;font-size:12px}}
.err{{color:#f85149}}
footer{{padding:16px;color:#8b949e;font-size:11px;text-align:center;border-top:1px solid #30363d}}
code{{background:#21262d;padding:1px 5px;border-radius:3px;font-size:12px}}
table.lbtbl{{width:calc(100% - 36px);margin:0 18px 16px;border-collapse:collapse;font-size:12px}}
table.lbtbl th,table.lbtbl td{{padding:7px 10px;border-bottom:1px solid #30363d;text-align:left;vertical-align:top}}
table.lbtbl th{{background:#0d1117;color:#8b949e;font-weight:500;text-transform:uppercase;font-size:10px;letter-spacing:.5px}}
table.lbtbl tr:hover td{{background:#1c2128}}
.badge{{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;color:#fff;font-weight:500}}
.badge.on{{background:#2ea043}}
.badge.off{{background:#6e7681}}
.exp-warn{{color:#f2cc60;font-weight:600}}
.exp-expired{{color:#f85149;font-weight:700}}
.exp-unk{{color:#8b949e;font-style:italic}}
</style></head><body>
<header>
  <h1>🌐 F5 XC Tenant Map — <code>{tenant}</code></h1>
  <div class="meta">Generated {ts} • {ns_count} namespaces scanned</div>
  <div class="stats">
    <div class="stat"><b>{t_lbs}</b><span>HTTP LBs</span></div>
    <div class="stat"><b>{t_pools}</b><span>Origin pools</span></div>
    <div class="stat"><b>{t_hcs}</b><span>Health checks</span></div>
    <div class="stat"><b>{t_wafs}</b><span>App firewalls</span></div>
    <div class="stat"><b>{t_apid}</b><span>API discovery on</span></div>
    <div class="stat"><b>{t_expsoon}</b><span>Certs &lt;30d</span></div>
  </div>
  <div class="legend">
    <span class="tag-lb">🌐 HTTP LB</span>
    <span class="tag-pool">🎯 Origin Pool</span>
    <span class="tag-hc">❤ Health Check</span>
    <span class="tag-waf">🛡 App Firewall</span>
  </div>
</header>
<main>{sections}</main>
<footer>f5xc_inventory_map.py • {tenant}.console.ves.io</footer>
<script>mermaid.initialize({{startOnLoad:true,theme:'default',flowchart:{{useMaxWidth:true,htmlLabels:true}}}});</script>
</body></html>
"""


def render_html(tenant, inventory):
    sections = []
    t_lbs = t_pools = t_hcs = t_wafs = t_apid = t_expsoon = 0
    for nd in inventory:
        ns = nd["namespace"]
        nl, np_, nh, nw = len(nd["lbs"]), len(nd["pools"]), len(nd["hcs"]), len(nd["wafs"])
        t_lbs += nl; t_pools += np_; t_hcs += nh; t_wafs += nw
        for lb in nd["lbs"]:
            if lb["api_discovery"] == "on":
                t_apid += 1
            d = days_until(lb.get("cert_expiry"))
            if d is not None and d < 30:
                t_expsoon += 1

        if nl == 0 and np_ == 0 and nh == 0 and nw == 0 and not nd.get("error"):
            continue
        head = (f'<summary>📂 {html.escape(ns)}'
                f'<span class="counts">{nl} LB · {np_} pool · {nh} HC · {nw} WAF</span>'
                '</summary>')
        if nd.get("error"):
            body = f'<div class="empty err">⚠ {html.escape(nd["error"])}</div>'
        elif nl == 0:
            body = (f'<div class="empty">No HTTP LBs. '
                    f'Pools: {np_} · Health checks: {nh} · App firewalls: {nw}</div>')
        else:
            body = (f'<div class="diagram"><pre class="mermaid">{namespace_mermaid(nd)}</pre></div>'
                    f'{namespace_table(nd)}')
        sections.append(f'<details {"open" if nl > 0 else ""}>{head}{body}</details>')

    return HTML_TPL.format(
        tenant=html.escape(tenant),
        ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        ns_count=len(inventory),
        t_lbs=t_lbs, t_pools=t_pools, t_hcs=t_hcs, t_wafs=t_wafs,
        t_apid=t_apid, t_expsoon=t_expsoon,
        sections="\n".join(sections) or '<div class="empty">No visible objects.</div>',
    )


# ─────────────────────────────── main ──────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="F5 XC tenant visual inventory map")
    ap.add_argument("-o", "--output", default="f5xc_map.html")
    ap.add_argument("--json", default=None)
    ap.add_argument("--namespaces", default=None)
    ap.add_argument("--skip", default="system,ves-io-shared",
                    help="Comma-separated namespaces to skip (default: system,ves-io-shared)")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    tenant = os.environ.get("F5XC_TENANT")
    token = os.environ.get("F5XC_API_TOKEN")
    if not tenant or not token:
        sys.exit("ERROR: set F5XC_TENANT and F5XC_API_TOKEN env vars")

    xc = XC(tenant, token)

    print(f"→ tenant {tenant}: listing namespaces…", file=sys.stderr)
    try:
        namespaces = sorted(i["name"] for i in xc.get("/api/web/namespaces").get("items", []))
    except requests.RequestException as e:
        sys.exit(f"ERROR listing namespaces: {e}")

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    namespaces = [n for n in namespaces if n not in skip]
    if args.namespaces:
        wanted = {n.strip() for n in args.namespaces.split(",")}
        namespaces = [n for n in namespaces if n in wanted]
    print(f"  {len(namespaces)} namespaces to scan", file=sys.stderr)
    if not _HAVE_CRYPTO:
        print("  (note: 'cryptography' not installed — PEM cert expiry fallback disabled)",
              file=sys.stderr)

    cert_cache = {}
    inventory = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        fut = {ex.submit(collect_namespace, xc, n, cert_cache): n for n in namespaces}
        for f in as_completed(fut):
            n = fut[f]
            try:
                r = f.result()
            except Exception as e:
                r = {"namespace": n, "lbs": [], "pools": {}, "hcs": {}, "wafs": {}, "error": str(e)}
            inventory.append(r)
            tag = "ERR" if r.get("error") else "OK "
            apid_on = sum(1 for lb in r["lbs"] if lb.get("api_discovery") == "on")
            print(f"  [{tag}] {n:40s}  LB={len(r['lbs']):>2}  pool={len(r['pools']):>2}"
                  f"  HC={len(r['hcs']):>2}  WAF={len(r['wafs']):>2}  apiD={apid_on}",
                  file=sys.stderr)

    inventory.sort(key=lambda x: x["namespace"])

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"tenant": tenant, "generated": datetime.now(timezone.utc).isoformat(),
                       "namespaces": inventory}, f, indent=2)
        print(f"→ wrote {args.json}", file=sys.stderr)

    with open(args.output, "w") as f:
        f.write(render_html(tenant, inventory))
    print(f"→ wrote {args.output}  ({time.time() - t0:.1f}s)", file=sys.stderr)


if __name__ == "__main__":
    main()
