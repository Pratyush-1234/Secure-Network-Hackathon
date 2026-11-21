#!/usr/bin/env python3
"""
Shield Wall: alert summary by attack type (PS6 core task 4 + stretch dashboard)

Reads the centralized, normalized event stream that Vector writes
(logs/central/events.ndjson: proxy access, proxy rate-limit, ModSecurity
audit and fail2ban events) and produces:

  reports/alert_summary.md    human-readable summary (for the report / demo)
  reports/alert_summary.csv   one row per attack type
  reports/alert_summary.json  machine-readable totals
  reports/dashboard.html      self-contained dashboard (no external assets)

Standard library only.
  python3 scripts/alert_summary.py [--events PATH] [--out DIR] [--benign-ip IP ...]
"""
import argparse
import csv
import html
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

# attack type -> (ATT&CK technique, CWE, CAPEC)
TAXONOMY = {
    "SQL Injection":                          ("T1190", "CWE-89", "CAPEC-66"),
    "Cross-Site Scripting":                   ("T1190", "CWE-79", "CAPEC-63"),
    "Command Injection":                      ("T1190", "CWE-78", "CAPEC-88"),
    "Path Traversal / File Inclusion":        ("T1190", "CWE-22", "CAPEC-126"),
    "PHP Injection":                          ("T1190", "CWE-94", "CAPEC-242"),
    "Scanner / Recon":                        ("T1595.002", "-", "CAPEC-541"),
    "Brute Force / Rate Limit":               ("T1110.001", "CWE-307", "CAPEC-49"),
    "Automated attack (repeated WAF blocks)": ("T1595.002 / T1190", "-", "-"),
    "Data Leakage (response)":                ("T1190", "CWE-200", "CAPEC-118"),
    "Flood / Rate Limit":                     ("T1499", "CWE-770", "CAPEC-125"),
    "Other / Protocol":                       ("T1190", "-", "-"),
}
ORDER = list(TAXONOMY)


def load(path):
    events, bad = [], 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    return events, bad


def minute(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%H:%M")
    except Exception:
        return "?"


def summarize(events, benign_ips):
    access = [e for e in events if e.get("event_type") == "http_access"]
    waf = [e for e in events if e.get("event_type") == "waf_alert"]
    rl = [e for e in events if e.get("event_type") == "rate_limit"]
    bans = [e for e in events if e.get("event_type") == "ban"]

    totals = {
        "events_total": len(events),
        "proxy_requests": len(access),
        "allowed": sum(1 for e in access if e.get("action") == "allowed"),
        "blocked_waf_403": sum(1 for e in access if e.get("status") == 403),
        "rate_limited_429": sum(1 for e in access if e.get("status") == 429),
        "blocked_edge_404": sum(1 for e in access if e.get("action") == "blocked_edge"),
        "waf_alerts": len(waf),
        "waf_blocked_transactions": sum(1 for e in waf if e.get("action") == "blocked_waf"),
        "waf_outbound_detections": sum(1 for e in waf if e.get("action") == "outbound_detected"),
        "fail2ban_bans": len(bans),
        "banned_ips": sorted({e.get("client_ip") for e in bans if e.get("client_ip")}),
    }
    totals["blocked_total"] = totals["blocked_waf_403"] + totals["rate_limited_429"] + totals["blocked_edge_404"]

    by_type = defaultdict(lambda: {"blocked": 0, "detected": 0, "bans": 0, "ips": set(), "rules": Counter(),
                                    "first": None, "last": None, "samples": []})

    def touch(row, e):
        ts = e.get("ts")
        if ts:
            row["first"] = min(row["first"] or ts, ts)
            row["last"] = max(row["last"] or ts, ts)
        if e.get("client_ip"):
            row["ips"].add(e["client_ip"])

    for e in waf:
        t = e.get("attack_type") or "Other / Protocol"
        row = by_type[t]
        if e.get("action") == "blocked_waf":
            row["blocked"] += 1
        else:
            row["detected"] += 1
        for r in e.get("rules") or []:
            rid = str(r.get("id") or "")
            if rid and rid not in ("949110", "959100", "980170"):   # skip anomaly-evaluation bookkeeping
                row["rules"][(rid, r.get("msg") or "")] += 1
        touch(row, e)
        if len(row["samples"]) < 5 and e.get("action") == "blocked_waf":
            row["samples"].append(e)
    for e in rl:
        t = e.get("attack_type") or "Brute Force / Rate Limit"
        row = by_type[t]
        row["blocked"] += 1
        row["rules"][("nginx:limit_req", (e.get("detail") or "").split(" ")[0])] += 1
        touch(row, e)
        if len(row["samples"]) < 5:
            row["samples"].append(e)
    for e in bans:
        t = e.get("attack_type") or "Automated attack (repeated WAF blocks)"
        row = by_type[t]
        row["bans"] += 1
        row["rules"][("fail2ban:ban", e.get("detail") or "")] += 1
        touch(row, e)

    rule_counter = Counter()
    for e in waf:
        for r in e.get("rules") or []:
            rid = str(r.get("id") or "")
            if rid and rid not in ("949110", "959100", "980170"):
                rule_counter[(rid, r.get("msg") or "")] += 1

    ip_rows = defaultdict(lambda: {"requests": 0, "allowed": 0, "blocked_403": 0, "rate_limited_429": 0, "banned": False})
    for e in access:
        ip = e.get("client_ip") or "?"
        ip_rows[ip]["requests"] += 1
        if e.get("action") == "allowed":
            ip_rows[ip]["allowed"] += 1
        if e.get("status") == 403:
            ip_rows[ip]["blocked_403"] += 1
        if e.get("status") == 429:
            ip_rows[ip]["rate_limited_429"] += 1
    for ip in totals["banned_ips"]:
        ip_rows[ip]["banned"] = True

    timeline = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in access:
        m = minute(e.get("ts", ""))
        timeline[m]["allowed" if e.get("action") == "allowed" else "blocked"] += 1

    fps = [e for e in waf if e.get("client_ip") in benign_ips and e.get("action") == "blocked_waf"]

    return totals, by_type, rule_counter, ip_rows, dict(sorted(timeline.items())), fps


def type_rows(by_type):
    rows = []
    for t in sorted(by_type, key=lambda k: (-by_type[k]["blocked"], ORDER.index(k) if k in ORDER else 99)):
        d = by_type[t]
        tech, cwe, capec = TAXONOMY.get(t, ("T1190", "-", "-"))
        top = ", ".join(f"{rid}" for (rid, _m), _c in d["rules"].most_common(4))
        rows.append({
            "attack_type": t, "blocked": d["blocked"], "detected_only": d["detected"], "ip_bans": d["bans"],
            "unique_sources": len(d["ips"]), "sources": " ".join(sorted(d["ips"])),
            "mitre_attack": tech, "cwe": cwe, "capec": capec, "top_rules": top,
            "first_seen": d["first"] or "", "last_seen": d["last"] or "",
        })
    return rows


def write_md(path, src, totals, rows, rule_counter, ip_rows, timeline, fps, by_type, bad):
    L = []
    L.append("# Shield Wall: WAF & proxy alert summary\n")
    L.append(f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC from `{src}` "
             f"({totals['events_total']} centralized events: nginx access + error, ModSecurity audit, fail2ban"
             + (f"; {bad} unparsable lines skipped" if bad else "") + ")._\n")
    L.append("## Totals\n")
    L.append("| Metric | Value |\n|---|---:|")
    for k, label in [("proxy_requests", "Requests reaching the edge proxy"),
                     ("allowed", "Allowed to the application"),
                     ("blocked_waf_403", "Blocked by ModSecurity / CRS (HTTP 403)"),
                     ("rate_limited_429", "Rejected by login rate limit (HTTP 429)"),
                     ("blocked_edge_404", "Sensitive paths hidden at the edge (HTTP 404)"),
                     ("waf_blocked_transactions", "WAF audit-log blocked transactions"),
                     ("waf_outbound_detections", "Response-leakage detections (detect-only)"),
                     ("fail2ban_bans", "Automatic IP bans (fail2ban)")]:
        L.append(f"| {label} | {totals[k]} |")
    L.append(f"| Banned source IPs | {', '.join(totals['banned_ips']) or '-'} |\n")

    L.append("## Alerts by attack type\n")
    L.append("| Attack type | Blocked | Detect-only | IP bans | Sources | ATT&CK | CWE | CAPEC | Top rules | First seen | Last seen |")
    L.append("|---|---:|---:|---:|---:|---|---|---|---|---|---|")
    for r in rows:
        L.append(f"| {r['attack_type']} | {r['blocked']} | {r['detected_only']} | {r['ip_bans']} | {r['unique_sources']} | {r['mitre_attack']} | "
                 f"{r['cwe']} | {r['capec']} | {r['top_rules']} | {r['first_seen'][11:19]} | {r['last_seen'][11:19]} |")
    L.append("\n_Brute Force counts are nginx `limit_req` rejections plus fail2ban bans. All other rows are ModSecurity "
             "transactions (one per blocked request). Each one is classified by the attack family with the most matching "
             "CRS / Shield Wall rules, and scanner user agents always win. A payload can match several families, "
             "e.g. `?page=/etc/passwd` trips CRS LFI rule 930120 and RCE rules 932160/932236. Every matched family is kept "
             "in the event's `attack_families` field in the central log._\n")

    L.append("## Top triggered rules\n")
    L.append("| Rule ID | Description | Hits |\n|---|---|---:|")
    for (rid, msg), c in rule_counter.most_common(15):
        L.append(f"| {rid} | {msg.replace('|', '/')} | {c} |")

    L.append("\n## Sources\n")
    L.append("| Client IP | Requests | Allowed | Blocked 403 | Rate-limited 429 | Banned |\n|---|---:|---:|---:|---:|---|")
    for ip, d in sorted(ip_rows.items(), key=lambda kv: -(kv[1]["blocked_403"] + kv[1]["rate_limited_429"])):
        L.append(f"| {ip} | {d['requests']} | {d['allowed']} | {d['blocked_403']} | {d['rate_limited_429']} | {'yes' if d['banned'] else 'no'} |")

    L.append("\n## Sample blocked requests\n")
    L.append("| Time (UTC) | Source | Attack type | Request | Rules |\n|---|---|---|---|---|")
    for t in [r["attack_type"] for r in rows]:
        for e in by_type[t]["samples"][:2]:
            uri = (e.get("uri") or "").replace("|", "%7C")
            if len(uri) > 70:
                uri = uri[:67] + "..."
            ids = " ".join(i for i in (e.get("rule_ids") or []) if i not in ("949110",)) or e.get("detail", "")
            L.append(f"| {(e.get('ts') or '')[11:19]} | {e.get('client_ip')} | {t} | `{e.get('method','')} {uri}` | {ids} |")

    L.append("\n## False positives against benign traffic\n")
    if fps:
        L.append(f"**{len(fps)} benign request(s) were blocked:**\n")
        for e in fps:
            L.append(f"- {e.get('ts')} {e.get('client_ip')} `{e.get('uri')}` rules {e.get('rule_ids')}")
    else:
        L.append("None. No request from the benign client was blocked by the WAF.")

    L.append("\n## Timeline (requests per minute)\n")
    L.append("| Minute (UTC) | Allowed | Blocked / rejected |\n|---|---:|---:|")
    for m, d in timeline.items():
        L.append(f"| {m} | {d['allowed']} | {d['blocked']} |")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def write_csv(path, rows):
    cols = ["attack_type", "blocked", "detected_only", "ip_bans", "unique_sources", "sources", "mitre_attack", "cwe", "capec",
            "top_rules", "first_seen", "last_seen"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------- dashboard
def nice_max(v):
    """Round the axis maximum up so the 4 gridline steps are whole numbers."""
    step = 1
    for s in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000):
        if v <= s * 4:
            step = s
            break
    else:
        step = -(-v // 4)
    return step * 4

def bar_svg(items, width=520, bar_h=22, gap=10, label_w=200):
    """Horizontal single-series bar chart. items = [(label, value, tooltip)]"""
    if not items:
        return "<p class='muted'>No data</p>"
    vmax = nice_max(max(v for _, v, _ in items) or 1)
    plot_w = width - label_w - 60
    h = len(items) * (bar_h + gap) + 24
    out = [f"<svg viewBox='0 0 {width} {h}' role='img' aria-label='Blocked events by attack type' class='chart'>"]
    # recessive vertical gridlines at quarter steps
    for q in range(5):
        x = label_w + plot_w * q / 4
        out.append(f"<line x1='{x:.1f}' y1='0' x2='{x:.1f}' y2='{h-20}' class='grid'/>")
        out.append(f"<text x='{x:.1f}' y='{h-6}' class='axis' text-anchor='middle'>{round(vmax*q/4)}</text>")
    for i, (label, v, tip) in enumerate(items):
        y = i * (bar_h + gap) + 4
        w = max(plot_w * v / vmax, 2)
        out.append(f"<g class='mark' data-tip='{html.escape(tip, quote=True)}'>")
        out.append(f"<rect x='0' y='{y-4}' width='{width}' height='{bar_h+gap}' class='hit'/>")
        out.append(f"<text x='{label_w-10}' y='{y+bar_h*0.7:.1f}' class='lbl' text-anchor='end'>{html.escape(label)}</text>")
        out.append(f"<path d='M{label_w},{y} h{w-4:.1f} a4,4 0 0 1 4,4 v{bar_h-8} a4,4 0 0 1 -4,4 h-{w-4:.1f} z' class='bar'/>")
        out.append(f"<text x='{label_w+w+6:.1f}' y='{y+bar_h*0.7:.1f}' class='val'>{v}</text></g>")
    out.append("</svg>")
    return "".join(out)


def col_svg(timeline, width=520, height=200):
    """Per-minute column chart of blocked/rejected requests (single series)."""
    if not timeline:
        return "<p class='muted'>No data</p>"
    keys = list(timeline)
    vals = [timeline[k]["blocked"] for k in keys]
    vmax = nice_max(max(vals) or 1)
    left, bottom, top = 36, 22, 10
    pw, ph = width - left - 8, height - bottom - top
    step = pw / len(keys)
    bw = max(min(step - 2, 28), 2)
    out = [f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='Blocked requests per minute' class='chart'>"]
    for q in range(5):
        y = top + ph - ph * q / 4
        out.append(f"<line x1='{left}' y1='{y:.1f}' x2='{width-8}' y2='{y:.1f}' class='grid'/>")
        out.append(f"<text x='{left-6}' y='{y+4:.1f}' class='axis' text-anchor='end'>{round(vmax*q/4)}</text>")
    every = max(1, len(keys) // 8)
    for i, k in enumerate(keys):
        v = vals[i]
        x = left + i * step + (step - bw) / 2
        hgt = ph * v / vmax
        y = top + ph - hgt
        tip = f"{k} UTC: {v} blocked / rejected, {timeline[k]['allowed']} allowed"
        out.append(f"<g class='mark' data-tip='{html.escape(tip, quote=True)}'>")
        out.append(f"<rect x='{left + i*step:.1f}' y='{top}' width='{step:.1f}' height='{ph}' class='hit'/>")
        if v:
            r = min(4, bw / 2, hgt)
            out.append(f"<path d='M{x:.1f},{top+ph} v-{hgt-r:.1f} a{r},{r} 0 0 1 {r},-{r} h{bw-2*r:.1f} a{r},{r} 0 0 1 {r},{r} v{hgt-r:.1f} z' class='bar'/>")
        out.append("</g>")
        if i % every == 0:
            out.append(f"<text x='{x+bw/2:.1f}' y='{height-6}' class='axis' text-anchor='middle'>{k}</text>")
    out.append("</svg>")
    return "".join(out)


def write_dashboard(path, totals, rows, rule_counter, ip_rows, timeline, fps):
    def esc(s):
        return html.escape(str(s))
    items = [(r["attack_type"], r["blocked"],
              f"{r['attack_type']}: {r['blocked']} blocked · {r['mitre_attack']} · {r['cwe']} · rules {r['top_rules']}")
             for r in rows if r["blocked"] > 0]
    tiles = [("Requests at edge", totals["proxy_requests"]), ("Allowed", totals["allowed"]),
             ("Blocked by WAF (403)", totals["blocked_waf_403"]), ("Rate-limited (429)", totals["rate_limited_429"]),
             ("IP bans", totals["fail2ban_bans"]), ("Benign false positives", len(fps))]
    type_table = "".join(
        f"<tr><td>{esc(r['attack_type'])}</td><td class='n'>{r['blocked']}</td><td class='n'>{r['detected_only']}</td><td class='n'>{r['ip_bans']}</td>"
        f"<td>{esc(r['mitre_attack'])}</td><td>{esc(r['cwe'])}</td><td>{esc(r['capec'])}</td><td>{esc(r['top_rules'])}</td></tr>"
        for r in rows)
    rule_table = "".join(f"<tr><td>{esc(rid)}</td><td>{esc(msg)}</td><td class='n'>{c}</td></tr>"
                         for (rid, msg), c in rule_counter.most_common(12))
    ip_table = "".join(
        f"<tr><td>{esc(ip)}</td><td class='n'>{d['requests']}</td><td class='n'>{d['allowed']}</td><td class='n'>{d['blocked_403']}</td>"
        f"<td class='n'>{d['rate_limited_429']}</td><td>{'yes' if d['banned'] else 'no'}</td></tr>"
        for ip, d in sorted(ip_rows.items(), key=lambda kv: -(kv[1]['blocked_403'] + kv[1]['rate_limited_429'])))
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shield Wall Alerts</title>
<style>
:root {{ color-scheme: light; --surface:#fcfcfb; --card:#ffffff; --border:#e4e3df; --text:#0b0b0b; --text2:#52514e;
  --muted:#7a7974; --grid:#ebeae6; --series1:#2a78d6; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ color-scheme: dark; --surface:#1a1a19; --card:#222220;
  --border:#3a3a37; --text:#f0efec; --text2:#c3c2b7; --muted:#8f8e86; --grid:#2f2f2c; --series1:#3987e5; }} }}
:root[data-theme="dark"] {{ color-scheme: dark; --surface:#1a1a19; --card:#222220; --border:#3a3a37; --text:#f0efec;
  --text2:#c3c2b7; --muted:#8f8e86; --grid:#2f2f2c; --series1:#3987e5; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--surface); color:var(--text); font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:24px 16px 48px; }}
h1 {{ font-size:22px; margin:0 0 4px; }} h2 {{ font-size:16px; margin:0 0 12px; }}
.muted {{ color:var(--muted); }} .sub {{ color:var(--text2); margin:0 0 20px; }}
.tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:16px; }}
.tile, .card {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }}
.tile .k {{ color:var(--text2); font-size:12px; }} .tile .v {{ font-size:28px; font-weight:600; font-variant-numeric:tabular-nums; }}
.grid2 {{ display:grid; grid-template-columns:1fr; gap:16px; }}
@media (min-width:900px) {{ .grid2 {{ grid-template-columns:1fr 1fr; }} }}
.card {{ margin-bottom:16px; overflow-x:auto; }}
svg.chart {{ width:100%; height:auto; display:block; }}
.grid {{ stroke:var(--grid); stroke-width:1; }} .axis {{ fill:var(--muted); font-size:12px; }}
.lbl {{ fill:var(--text2); font-size:13px; }} .val {{ fill:var(--text); font-size:13px; font-variant-numeric:tabular-nums; }}
.bar {{ fill:var(--series1); }} .hit {{ fill:transparent; }} .mark:hover .bar {{ opacity:.8; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--border); vertical-align:top; }}
th {{ color:var(--text2); font-weight:600; }} td.n, th.n {{ text-align:right; font-variant-numeric:tabular-nums; }}
#tip {{ position:fixed; pointer-events:none; background:var(--card); color:var(--text); border:1px solid var(--border);
  border-radius:6px; padding:6px 9px; font-size:12px; box-shadow:0 2px 8px rgba(0,0,0,.15); display:none; max-width:320px; }}
</style></head>
<body><main>
<h1>Shield Wall: WAF alert dashboard</h1>
<p class="sub">nginx + ModSecurity v3 + OWASP CRS 4.30 in front of DVWA · generated {gen} from the centralized log stream</p>
<div class="tiles">{''.join(f"<div class='tile'><div class='k'>{esc(k)}</div><div class='v'>{v}</div></div>" for k, v in tiles)}</div>
<div class="grid2">
  <div class="card"><h2>Blocked events by attack type</h2>{bar_svg(items)}</div>
  <div class="card"><h2>Blocked or rejected requests per minute</h2>{col_svg(timeline)}</div>
</div>
<div class="card"><h2>Alerts by attack type</h2><table><thead><tr><th>Attack type</th><th class="n">Blocked</th><th class="n">Detect-only</th><th class="n">IP bans</th>
<th>ATT&amp;CK</th><th>CWE</th><th>CAPEC</th><th>Top rules</th></tr></thead><tbody>{type_table}</tbody></table></div>
<div class="grid2">
  <div class="card"><h2>Top triggered rules</h2><table><thead><tr><th>Rule</th><th>Description</th><th class="n">Hits</th></tr></thead><tbody>{rule_table}</tbody></table></div>
  <div class="card"><h2>Sources</h2><table><thead><tr><th>Client IP</th><th class="n">Req</th><th class="n">Allowed</th><th class="n">403</th><th class="n">429</th><th>Banned</th></tr></thead><tbody>{ip_table}</tbody></table></div>
</div>
</main><div id="tip" role="tooltip"></div>
<script>
const tip=document.getElementById('tip');
document.querySelectorAll('.mark').forEach(m=>{{
  m.addEventListener('mousemove',e=>{{tip.textContent=m.dataset.tip;tip.style.display='block';
    const x=Math.min(e.clientX+14,window.innerWidth-tip.offsetWidth-8);tip.style.left=x+'px';tip.style.top=(e.clientY+14)+'px';}});
  m.addEventListener('mouseleave',()=>{{tip.style.display='none';}});
}});
</script></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", default=os.path.join(root, "logs", "central", "events.ndjson"))
    ap.add_argument("--out", default=os.path.join(root, "reports"))
    ap.add_argument("--benign-ip", action="append", default=["10.66.10.20"])
    a = ap.parse_args()
    if not os.path.exists(a.events):
        sys.exit(f"events file not found: {a.events}")
    events, bad = load(a.events)
    totals, by_type, rules, ips, timeline, fps = summarize(events, set(a.benign_ip))
    rows = type_rows(by_type)
    os.makedirs(a.out, exist_ok=True)
    write_md(os.path.join(a.out, "alert_summary.md"), a.events, totals, rows, rules, ips, timeline, fps, by_type, bad)
    write_csv(os.path.join(a.out, "alert_summary.csv"), rows)
    with open(os.path.join(a.out, "alert_summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"totals": totals, "by_attack_type": rows, "benign_false_positives": len(fps),
                   "top_rules": [{"id": r, "msg": m, "hits": c} for (r, m), c in rules.most_common(20)]}, fh, indent=2)
    write_dashboard(os.path.join(a.out, "dashboard.html"), totals, rows, rules, ips, timeline, fps)
    print(f"[summary] {totals['events_total']} events | {totals['proxy_requests']} requests | "
          f"{totals['blocked_waf_403']} WAF-blocked | {totals['rate_limited_429']} rate-limited | "
          f"{totals['fail2ban_bans']} bans | {len(fps)} benign FPs")
    for r in rows:
        print(f"  {r['attack_type']:<40} blocked={r['blocked']:<4} bans={r['ip_bans']:<2} {r['mitre_attack']:<18} {r['cwe']:<8} rules: {r['top_rules']}")
    print(f"[summary] wrote {a.out}/alert_summary.md|.csv|.json and dashboard.html")


if __name__ == "__main__":
    main()
