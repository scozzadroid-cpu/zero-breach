/* Zero Breach Nightly - report page.
 * Everything that comes from scanned data is put on the page with createTextNode /
 * textContent only. Never use innerHTML here: this page can run root commands
 * through the WebUI bridge, so scanned content must never be able to become markup. */
(function () {
  "use strict";

  var Z = window.ZB || { meta: {}, scans: [] };
  var meta = Z.meta || {};
  var scans = Z.scans || [];
  var app = document.getElementById("app");
  var selected = scans.length ? scans[0].id : null;

  var DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  var BADGE = {
    "on-disk": "file found", "file-pattern": "pattern", "persistence": "auto-start", "contacted": "contact",
    "dns-record": "dns", "attempted": "blocked lookup", "configured": "config", "referenced": "mention"
  };
  var WHY = {
    "on-disk": "A file that matches a known sample is present on the device. Take this seriously.",
    "file-pattern": "A file matches a research rule. It needs a closer look before it means anything.",
    "persistence": "The name is registered to start automatically. Take this seriously.",
    "contacted": "The browser or an app fetched something from this host. This is the kind of finding to take seriously.",
    "dns-record": "The name shows up in local DNS data. A lookup does not prove a connection.",
    "attempted": "A lookup happened but a filter blocked it, so nothing was contacted.",
    "configured": "The name is set up locally to point at a real address.",
    "referenced": "The name appears inside text saved by an app or website (for example a list of advertising vendors). " +
      "That is a mention, not contact: it does not mean this phone connected to it."
  };

  // --- helpers -------------------------------------------------------------------
  function add(el, c) {
    if (c == null || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(el, x); }); return; }
    el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (k === "class") el.className = v;
        else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
        else if (v !== false && v != null) el.setAttribute(k, v);
      });
    }
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  var NS = "http://www.w3.org/2000/svg";
  function svgEl(tag, attrs) {
    var el = document.createElementNS(NS, tag);
    Object.keys(attrs).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    return el;
  }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
  function parts(iso) { return /^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)/.exec(iso || ""); }
  function fmt(iso) {
    var m = parts(iso);
    if (!m) return iso || "?";
    var d = new Date(+m[1], +m[2] - 1, +m[3]);
    return DAYS[d.getDay()] + " " + (+m[3]) + " " + MONTHS[+m[2] - 1] + " " + m[4] + ":" + m[5];
  }
  function fmtDay(iso) {
    var m = parts(iso);
    return m ? (+m[3]) + " " + MONTHS[+m[2] - 1] : (iso || "?");
  }
  function hoursSince(iso) {
    var m = parts(iso);
    return m ? (Date.now() - new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]).getTime()) / 3600000 : null;
  }
  function ago(iso) {
    var hrs = hoursSince(iso);
    if (hrs == null) return "";
    if (hrs < 1) return "just now";
    if (hrs < 48) return Math.round(hrs) + " h ago";
    return Math.round(hrs / 24) + " days ago";
  }
  function mins(s) { return s >= 90 ? Math.round(s / 60) + " min" : s + " s"; }
  function total(s) { return s.modules.reduce(function (n, m) { return n + m.checked; }, 0); }
  function level(s) { return s.serious > 0 ? "alert" : "clear"; }

  function lastError() {
    var e = meta.last_error;
    if (!e) return null;
    if (scans.length && String(scans[0].when) >= String(e.when)) return null;
    return e;
  }
  function lastSkip() {
    var k = meta.last_skip;
    if (!k) return null;
    if (scans.length && String(scans[0].when) >= String(k.when)) return null;
    return k;
  }

  function run(cmd, done) {
    if (!window.ksu || typeof window.ksu.exec !== "function") return false;
    var cb = "zbcb" + Date.now();
    window[cb] = function (code, out, err) { delete window[cb]; done(code, out, err); };
    window.ksu.exec(cmd, "{}", cb);
    return true;
  }

  // --- the verdict ---------------------------------------------------------------
  // alert     : at least one serious finding
  // attention : nothing dangerous found, but the check is not up to date or did not complete
  // clear     : no known threat found (mentions in saved content do not change that)
  // none      : no scan yet
  function assess() {
    var s = scans[0];
    if (!s) {
      return { level: "none", state: "No data", head: "No scan yet",
        lede: meta.next ? "The first scan is scheduled for " + meta.next + "." : "Waiting for the first scan.", reasons: [], notes: [], todo: null };
    }
    if (s.serious > 0) {
      return { level: "alert", state: "Alert", head: "Possible threat found",
        lede: plural(s.serious, "serious finding", "serious findings") + " in the scan of " + fmt(s.when) + ".",
        reasons: [], notes: [],
        todo: ["Do not delete anything: the traces are the evidence.",
          "Read the findings below and note which app or site is named.",
          "If you have a concrete reason to think you are a target, contact the Access Now Digital Security Helpline (accessnow.org/help) or the Amnesty International Security Lab (securitylab.amnesty.org)."] };
    }
    var reasons = [];
    var limit = (meta.max_gap_h || 72) + 12;
    var hrs = hoursSince(s.when);
    if (hrs != null && hrs > limit) reasons.push("The last scan is " + ago(s.when).replace(" ago", "") + " old; it should run at least every " + Math.round((meta.max_gap_h || 72) / 24) + " days.");
    var e = lastError();
    if (e) reasons.push("The last scan attempt failed (" + fmt(e.when) + "): " + e.reason + ".");
    var k = lastSkip();
    if (k) reasons.push("The scan of " + fmtDay(k.when) + " was skipped: " + k.reason + ".");
    if (s.ioc_age_days != null && s.ioc_age_days > 30) reasons.push("The list of known indicators is " + s.ioc_age_days + " days old.");
    var notes = [];
    if (s.hits_total > 0) notes.push(plural(s.hits_total, "harmless mention", "harmless mentions") + " of a name from the indicator list in saved web data. Details under Findings; no sign the phone contacted it.");
    if (meta.waiting_for_charger) notes.push("Tonight's scan is waiting for a charger.");
    if (reasons.length) {
      return { level: "attention", state: "Attention", head: "Needs attention",
        lede: "Nothing dangerous was found, but the check is not fully up to date.", reasons: reasons, notes: notes,
        todo: ["Fix the point" + (reasons.length > 1 ? "s" : "") + " above, then press Scan now."] };
    }
    return { level: "clear", state: "Clear", head: "No known threat found",
      lede: "Scanned " + total(s).toLocaleString("en-US") + " items in Chrome, app web views and app caches · " + fmt(s.when) + " (" + ago(s.when) + ").",
      reasons: [], notes: notes, todo: null };
  }

  var ICON = {
    clear: "M8 12.2l2.8 2.8 5.4-6",
    attention: "M12 7.4v5.6M12 16.1v.4",
    alert: "M9 9l6 6M15 9l-6 6",
    none: "M9.6 10a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1.1.9-1.1 1.7M12 17v.3"
  };
  function shield(lv) {
    var s = svgEl("svg", { "class": "shield", viewBox: "0 0 24 24", "aria-hidden": "true" });
    s.appendChild(svgEl("path", { "class": "shield-body", d: "M12 2.2 20 5v6.2c0 5-3.3 9.2-8 10.6-4.7-1.4-8-5.6-8-10.6V5z" }));
    s.appendChild(svgEl("path", { "class": "shield-icon", d: ICON[lv] }));
    return s;
  }

  function heroCard() {
    var a = assess();
    var card = h("section", { "class": "hero " + a.level });
    add(card, h("div", { "class": "hero-top" }, shield(a.level),
      h("div", null, h("div", { "class": "state" }, a.state), h("div", { "class": "headline" }, a.head), h("p", { "class": "lede" }, a.lede))));
    if (a.reasons.length) { var ul = h("ul", { "class": "reasons" }); a.reasons.forEach(function (r) { add(ul, h("li", null, r)); }); add(card, ul); }
    if (a.notes.length) { var un = h("ul", { "class": "reasons" }); a.notes.forEach(function (r) { add(un, h("li", null, r)); }); add(card, un); }
    if (a.todo) {
      var t = h("div", { "class": "todo" }, h("b", null, "What to do"));
      a.todo.forEach(function (x) { add(t, h("div", null, x)); });
      add(card, t);
    }
    var strip = h("div", { "class": "strip" });
    [["clear", "Clear"], ["attention", "Attention"], ["alert", "Alert"]].forEach(function (p) {
      add(strip, h("span", { "class": a.level === p[0] ? "on" : "" }, p[1]));
    });
    add(card, strip);

    var msg = h("span", { "class": "msg" });
    var btn = h("button", { "class": "primary", type: "button" }, meta.running ? "Scanning…" : "Scan now");
    if (meta.running || !(window.ksu && window.ksu.exec)) btn.disabled = true;
    btn.addEventListener("click", function () {
      btn.disabled = true;
      var ok = run("kill -USR1 $(cat /data/adb/zero-breach/scheduler.pid)", function (code) {
        msg.textContent = code === 0 ? "Started in the background. Reload this page in 10-20 minutes." : "Could not start it (is the scheduler running?).";
      });
      if (!ok) msg.textContent = "Only available from the root manager.";
    });
    add(card, h("div", { "class": "actions" }, btn, msg));
    add(card, h("p", { "class": "fine" },
      "Clear means no known trace was found in the places checked. It is not a guarantee: the scan cannot see the traffic of native apps, " +
      "nor spyware that leaves none of these traces."));
    return card;
  }

  function tile(kind, key, value, sub) {
    return h("div", { "class": "tile " + kind }, h("div", { "class": "k" }, key), h("div", { "class": "v" }, value), sub ? h("div", { "class": "s" }, sub) : null);
  }

  function tiles() {
    var s = scans[0], out = h("div", { "class": "tiles" });
    add(out, tile("ok", "Next scan", meta.running ? "Running now" : (meta.next || "—"), meta.schedule));
    var old = s && s.ioc_age_days != null && s.ioc_age_days > 30;
    add(out, tile(s ? (old ? "warn" : "ok") : "", "Indicators", s ? s.ioc_count + " known" : "—",
      s && s.ioc_age_days != null ? "list is " + plural(s.ioc_age_days, "day", "days") + " old" : null));
    var zb = meta.newer ? tile("warn", "Zero Breach", meta.pinned || "?", "new version " + meta.latest + " is out")
      : tile(meta.latest ? "ok" : "", "Zero Breach", meta.pinned || "?", meta.latest ? "up to date" : "version check pending");
    add(out, zb);
    var t = meta.notify_test;
    var al;
    if (meta.shell_blocked) al = tile("bad", "Alerts", "Blocked", "allow notifications for the Shell app");
    else if (meta.notify_failed || (t && !t.ok)) al = tile("bad", "Alerts", "Not delivered", "see Settings → test");
    else if (t && t.ok) al = tile("ok", "Alerts", "Working", "tested " + fmtDay(t.when));
    else al = tile("", "Alerts", "Not tested", "use Send test in Settings");
    add(out, al);
    return out;
  }

  // --- findings ------------------------------------------------------------------
  // One card per file and grade: the same file usually matches several names.
  function groupHits(list) {
    var order = [], by = {};
    list.forEach(function (x) {
      var k = x.where + "|" + x.evidence;
      if (!by[k]) { by[k] = { first: x, indicators: [], sources: [] }; order.push(k); }
      if (by[k].indicators.indexOf(x.indicator) < 0) by[k].indicators.push(x.indicator);
      if (x.source && by[k].sources.indexOf(x.source) < 0) by[k].sources.push(x.source);
    });
    return order.map(function (k) { return by[k]; });
  }

  function hitCard(g) {
    var x = g.first;
    var kind = x.evidence === "referenced" ? "mention" : (x.evidence === "contacted" || x.evidence === "on-disk" || x.evidence === "persistence" ? "contact" : "");
    var badge = kind === "mention" ? "" : (kind === "contact" ? "bad" : "warn");
    var c = h("div", { "class": "card hit " + kind });
    add(c, [
      h("div", null, h("span", { "class": "ind" }, g.indicators.join("  ")), " ", h("span", { "class": "badge " + badge }, BADGE[x.evidence] || x.evidence)),
      h("p", { "class": "why" }, WHY[x.evidence] || "Unclassified kind of evidence: treat it as serious."),
      x.who ? h("p", null, "App / profile: " + x.who) : null,
      x.seen ? h("p", null, "Observed: " + x.seen) : null,
      h("p", { "class": "where" }, x.where),
      g.sources.length ? h("p", { "class": "muted" }, "Source: " + g.sources.join(", ")) : null
    ]);
    return c;
  }

  function findings(s) {
    var box = h("div");
    add(box, h("h2", { "class": "sec" }, "Findings · scan of " + fmt(s.when)));
    if (!s.hits.length) { add(box, h("div", { "class": "card muted" }, "Nothing from the indicator list was found.")); return box; }
    var groups = groupHits(s.hits);
    groups.slice(0, 5).forEach(function (g) { add(box, hitCard(g)); });
    if (groups.length > 5) {
      var more = h("details", null, h("summary", null, "Show " + (groups.length - 5) + " more"));
      groups.slice(5).forEach(function (g) { add(more, hitCard(g)); });
      add(box, more);
    }
    if (s.hits_total > s.hits.length) add(box, h("p", { "class": "muted" }, "Showing " + s.hits.length + " of " + s.hits_total + " findings; the full list is in the report."));
    return box;
  }

  function details(s) {
    var box = h("div");
    add(box, h("h2", { "class": "sec" }, "What this scan could not check (" + s.gaps_total + ")"));
    if (s.gaps.length) {
      var ul = h("ul", { "class": "plain" });
      s.gaps.forEach(function (g) { add(ul, h("li", null, g)); });
      add(box, h("div", { "class": "card" }, ul));
      if (s.gaps_total > s.gaps.length) add(box, h("p", { "class": "muted" }, "…and " + (s.gaps_total - s.gaps.length) + " more."));
    } else {
      add(box, h("div", { "class": "card muted" }, "No gap declared."));
    }

    var mods = h("details");
    add(mods, h("summary", null, "Checks performed"));
    s.modules.forEach(function (m) {
      var d = h("div", { "class": "card check" });
      add(d, h("strong", null, m.name + " · " + m.status.toLowerCase()), " ",
        h("span", { "class": "muted" }, m.checked.toLocaleString("en-US") + " items read, " + m.skipped + " skipped, " + mins(Math.round(m.seconds))));
      var ul2 = h("ul", { "class": "plain" });
      m.checks.forEach(function (c) {
        add(ul2, h("li", null, h("span", { "class": c.ran ? "ran" : "skip" }, c.ran ? "ran" : "did not run"), " ", c.name, c.ran ? "" : " — " + c.reason));
      });
      if (m.checks_total > m.checks.length) add(ul2, h("li", { "class": "muted" }, "…and " + (m.checks_total - m.checks.length) + " more checks"));
      add(d, ul2);
      add(mods, d);
    });
    add(box, mods);
    if (s.text) add(box, h("details", null, h("summary", null, "Full report"), h("pre", null, s.text)));
    return box;
  }

  // --- history -------------------------------------------------------------------
  function history() {
    var box = h("div");
    add(box, h("h2", { "class": "sec" }, "History (" + scans.length + ")"));
    var trail = h("div", { "class": "trail", "aria-hidden": "true" });
    scans.slice().reverse().forEach(function (s) { add(trail, h("i", { "class": level(s), title: fmt(s.when) })); });
    add(box, trail);
    var ul = h("ul", { "class": "history" });
    scans.forEach(function (s) {
      var b = h("button", { type: "button", "aria-current": s.id === selected ? "true" : "false" },
        h("span", { "class": "dot " + level(s) }), h("span", null, fmt(s.when)),
        h("span", { "class": "meta" }, s.serious ? plural(s.serious, "serious finding", "serious findings") : (s.hits_total ? plural(s.hits_total, "mention", "mentions") : "clean")));
      b.addEventListener("click", function () { selected = s.id; render(); });
      add(ul, h("li", null, b));
    });
    add(box, ul);
    return box;
  }

  // --- settings ------------------------------------------------------------------
  // Values are checked here and again by set_config.py, which accepts only these
  // keys and shapes; the command line is built from checked tokens, never raw text.
  var DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

  function settingsCard() {
    var c = meta.config;
    var box = h("div");
    add(box, h("h2", { "class": "sec" }, "Settings"));
    var card = h("section", { "class": "card" });
    add(box, card);
    if (!c || !meta.set_cmd) {
      add(card, h("span", { "class": "muted" }, "Available after the scheduler has started."));
      return box;
    }
    var editable = !!(window.ksu && typeof window.ksu.exec === "function");
    function dis() { return editable ? false : ""; }

    var time = h("input", { type: "time", value: c.TIME.slice(0, 2) + ":" + c.TIME.slice(2), disabled: dis() });
    var active = c.DAYS.split(" ");
    var dayBoxes = DAY_LABELS.map(function (name, i) {
      var cb = h("input", { type: "checkbox", value: String(i + 1), disabled: dis() });
      cb.checked = active.indexOf(String(i + 1)) >= 0;
      return cb;
    });
    var days = h("div", { "class": "days" });
    dayBoxes.forEach(function (cb, i) { add(days, h("label", null, cb, " " + DAY_LABELS[i])); });

    function toggle(key, text) {
      var cb = h("input", { type: "checkbox", disabled: dis() });
      cb.checked = c[key] === "1";
      return { key: key, el: cb, row: h("label", { "class": "opt" }, cb, " " + text) };
    }
    var toggles = [
      toggle("ONLY_CHARGING", "Run only while the phone is charging (otherwise wait for a charger until the late window closes)"),
      toggle("NOTIFY", "Notify on new findings, failed scans and new versions"),
      toggle("UPDATE_IOCS", "Refresh the indicator list before each scan"),
      toggle("CHECK_UPSTREAM", "Look for new Zero Breach releases")
    ];
    var late = h("input", { type: "number", min: "0", max: "12", value: c.LATE_H, disabled: dis() });
    var limit = h("input", { type: "number", min: "1", max: "180", value: c.TIMEOUT_MIN, disabled: dis() });

    var form = h("div", { "class": "opts" });
    add(form, [
      h("label", { "class": "opt" }, "Start time ", time),
      h("div", null, h("span", { "class": "muted" }, "Days"), days)
    ]);
    toggles.forEach(function (t) { add(form, t.row); });
    add(form, [
      h("label", { "class": "opt" }, "If the phone was asleep, still run up to (hours) ", late),
      h("label", { "class": "opt" }, "Maximum scan time (minutes) ", limit)
    ]);
    add(card, form);

    var msg = h("span", { "class": "msg" });
    var save = h("button", { "class": "primary", type: "button", disabled: dis() }, "Save");
    save.addEventListener("click", function () {
      var t = time.value.replace(":", "");
      var d = dayBoxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
      var l = String(late.value), m = String(limit.value);
      if (!/^([01]\d|2[0-3])[0-5]\d$/.test(t)) { msg.textContent = "Invalid time."; return; }
      if (!d.length) { msg.textContent = "Pick at least one day."; return; }
      if (!/^(\d|1[0-2])$/.test(l)) { msg.textContent = "Late window: 0 to 12 hours."; return; }
      if (!/^([1-9]\d?|1[0-7]\d|180)$/.test(m)) { msg.textContent = "Time limit: 1 to 180 minutes."; return; }
      var args = ["TIME=" + t, "DAYS='" + d.join(" ") + "'", "LATE_H=" + l, "TIMEOUT_MIN=" + m];
      toggles.forEach(function (x) { args.push(x.key + "=" + (x.el.checked ? "1" : "0")); });
      save.disabled = true;
      msg.textContent = "Saving…";
      run(meta.set_cmd + " " + args.join(" "), function (code, out, err) {
        if (code === 0) {
          msg.textContent = "Saved.";
          setTimeout(function () { window.location.reload(); }, 1500);
        } else {
          save.disabled = false;
          msg.textContent = "Not saved: " + String(err || out || "error").slice(0, 120);
        }
      });
    });
    var test = h("button", { type: "button", disabled: dis() }, "Send test notification");
    test.addEventListener("click", function () {
      test.disabled = true;
      run("kill -USR2 $(cat /data/adb/zero-breach/scheduler.pid)", function (code) {
        msg.textContent = code === 0 ? "Test sent. Reload in a few seconds to see the result." : "Could not reach the scheduler.";
        test.disabled = false;
      });
    });
    add(card, h("div", { "class": "actions" }, save, test, msg));
    if (!editable) add(card, h("p", { "class": "fine" }, "Read-only here: change settings from the page opened in the root manager (or in config.sh)."));
    return box;
  }

  // --- page ------------------------------------------------------------------------
  function render() {
    while (app.firstChild) app.removeChild(app.firstChild);
    add(app, [
      h("div", { "class": "brand" }, "Zero", h("span", { "class": "sl" }, "//"), "Breach"),
      h("p", { "class": "tag" }, "Nightly check · AdFection / Candiru indicators"),
      heroCard(),
      tiles()
    ]);
    if (scans.length) {
      var s = scans.filter(function (x) { return x.id === selected; })[0] || scans[0];
      add(app, [findings(s), details(s), history()]);
    }
    add(app, settingsCard());
    if (meta.generated) add(app, h("p", { "class": "foot" }, "Page updated " + fmt(meta.generated) + " · bundled Zero Breach " + (meta.pinned || "?")));
  }

  render();
})();
