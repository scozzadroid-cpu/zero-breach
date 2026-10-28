"""Data for the module's web page (KernelSU WebUI) and a standalone copy of it.

The scheduler calls refresh() after every scan. It turns the saved scan reports
(upstream's JSON documents plus the readable text) into webroot/data.js, which
the static page in webroot/ renders, and writes a single-file copy of the page
to the shared storage folder so it can also be opened in a normal browser.

Everything that comes from scanned data is escaped for a <script> context and
shown by the page as text only, never as markup: the WebUI can run root
commands, so scanned content must never be able to become code.
"""

import io
import json
import os
import re

STEM_RE = re.compile(r"^\d{4}-\d\d-\d\d_\d{4}$")  # one scan: YYYY-MM-DD_HHMM
KEEP_SCANS = 30      # scans listed on the page
FULL_TEXT = 10       # newest scans that also carry the full readable report
MAX_HITS = 200       # findings listed per scan (the count is always exact)
MAX_CHECKS = 60      # checks listed per module


def defang(text, indicators=()):
    """example.com -> example[.]com, http -> hxxp, so a page or a forwarded
    report never turns an indicator into a clickable or fetchable link."""
    text = str(text)
    for ind in sorted({i for i in indicators if i}, key=len, reverse=True):
        text = re.sub(re.escape(ind), ind.replace(".", "[.]"), text, flags=re.I)
    return re.sub(r"(?i)\bhttp(s?)://", lambda m: "hxxp" + m.group(1) + "://", text)


def _summarize(doc, stem, text):
    hits, serious = [], 0
    total = 0
    for name, mod in doc["modules"].items():
        for h in mod["hits"]:
            total += 1
            if h["evidence"] != "referenced":
                serious += 1
            if len(hits) < MAX_HITS:
                ind = h["indicator"]
                hits.append({
                    "module": name,
                    "indicator": defang(ind, [ind]),
                    "evidence": h["evidence"],
                    "where": defang(h["location"], [ind]),
                    "detail": defang(h["detail"], [ind]),
                    "who": h.get("profile", ""),
                    "seen": h.get("observed", ""),
                    "confidence": h.get("confidence", ""),
                    "source": h.get("source", ""),
                })
    modules = []
    for name, mod in doc["modules"].items():
        modules.append({
            "name": name, "status": mod["status"], "checked": mod["checked"],
            "skipped": mod["skipped"], "seconds": mod["duration_s"],
            "checks": [{"name": c["name"], "ran": c["ran"], "reason": c["reason"]}
                       for c in mod["checks"]][:MAX_CHECKS],
            "checks_total": len(mod["checks"]),
            "notes": mod["notes"][:20],
        })
    return {
        "id": stem,
        "when": doc["timestamp"],
        "status": doc["verdict"]["status"],
        "hits_total": total,
        "serious": serious,
        "hits": hits,
        "gaps": doc["verdict"]["gaps"][:60],
        "gaps_total": len(doc["verdict"]["gaps"]),
        "seconds": round(sum(m["duration_s"] for m in doc["modules"].values())),
        "ioc_count": doc["ioc_set"]["count"],
        "ioc_age_days": doc["ioc_set"]["age_days"],
        "version": doc["tool"]["version"],
        "modules": modules,
        "text": text,
    }


def collect(reports_dir):
    stems = sorted((f[:-5] for f in os.listdir(reports_dir)
                    if f.endswith(".json") and STEM_RE.match(f[:-5])), reverse=True)
    scans = []
    for stem in stems:
        if len(scans) >= KEEP_SCANS:
            break
        try:
            with io.open(os.path.join(reports_dir, stem + ".json"), encoding="utf-8") as fh:
                doc = json.load(fh)
            text = ""
            if len(scans) < FULL_TEXT:
                with io.open(os.path.join(reports_dir, stem + ".txt"), encoding="utf-8",
                             errors="replace") as fh:
                    text = fh.read()
            scans.append(_summarize(doc, stem, text))
        except (OSError, ValueError, KeyError):
            continue  # a half-written or foreign file never breaks the page
    return scans


def _script_json(obj):
    # "</" would let scanned text close the <script> element
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")


def write_data(webroot, reports_dir, meta):
    data = {"meta": meta, "scans": collect(reports_dir)}
    tmp = os.path.join(webroot, "data.js.tmp")
    with io.open(tmp, "w", encoding="utf-8") as fh:
        fh.write("window.ZB = " + _script_json(data) + ";\n")
    os.replace(tmp, os.path.join(webroot, "data.js"))


def write_standalone(webroot, share_dir):
    """One self-contained HTML file: same page, style, script and data inlined."""
    def read(name):
        with io.open(os.path.join(webroot, name), encoding="utf-8") as fh:
            return fh.read()

    html = read("index.html")
    html = re.sub(r"<meta http-equiv=\"Content-Security-Policy\"[^>]*>\n?", "", html)
    html = html.replace('<link rel="stylesheet" href="style.css">',
                        "<style>\n" + read("style.css") + "</style>")
    html = html.replace('<script src="data.js"></script>',
                        "<script>\n" + read("data.js").replace("</", "<\\/") + "</script>")
    html = html.replace('<script src="app.js"></script>',
                        "<script>\n" + read("app.js").replace("</script", "<\\/script") + "</script>")
    os.makedirs(share_dir, exist_ok=True)
    with io.open(os.path.join(share_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(html)


def refresh(webroot, reports_dir, share_dir, meta):
    write_data(webroot, reports_dir, meta)
    if share_dir:
        write_standalone(webroot, share_dir)
