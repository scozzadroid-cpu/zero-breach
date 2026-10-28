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
  var GLOSS = {
    "on-disk": "a known file is present on the device",
    "file-pattern": "matches a research rule, needs checking",
    "persistence": "registered to start automatically",
    "contacted": "the device contacted this host",
    "dns-record": "appears in local DNS data, contact not verified",
    "attempted": "a lookup was made but blocked by a filter",
    "configured": "configured locally to point at a real address",
    "referenced": "mentioned in saved content, does not show any contact"
  };

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
  function mins(s) { return s >= 90 ? Math.round(s / 60) + " min" : s + " s"; }

  function verdict(s) {
    if (s.serious > 0) return { cls: "bad", title: plural(s.serious, "finding to review", "findings to review") };
    if (s.hits_total > 0) return { cls: "warn", title: plural(s.hits_total, "mention in saved content", "mentions in saved content") };
    return { cls: "ok", title: "No known indicator found" };
  }

  function lastError() {
    var e = meta.last_error;
    if (!e) return null;
    if (scans.length && String(scans[0].when) >= String(e.when)) return null;
    return e;
  }

  function run(cmd, done) {
    if (!window.ksu || typeof window.ksu.exec !== "function") return false;
    var cb = "zbcb" + Date.now();
    window[cb] = function (code, out, err) { delete window[cb]; done(code, out, err); };
    window.ksu.exec(cmd, "{}", cb);
    return true;
  }

  function summaryCard() {
    var err = lastError();
    var card = h("section", { "class": "card" });
    if (!scans.length) {
      add(card, h("div", { "class": "verdict" }, h("span", { "class": "dot" }),
        h("div", null, h("strong", null, "No scan has run yet"),
          h("span", { "class": "when" }, meta.next ? "The first one is scheduled for " + meta.next : "Waiting for the first start"))));
    } else {
      var s = scans[0], v = verdict(s);
      add(card, h("div", { "class": "verdict" }, h("span", { "class": "dot " + v.cls }),
        h("div", null, h("strong", null, v.title),
          h("span", { "class": "when" }, "Last scan " + fmt(s.when) + " · took " + mins(s.seconds)))));
      if (s.serious > 0) {
        add(card, h("p", { "class": "note bad" },
          "Do not delete anything: the traces are the evidence. If you have a concrete reason to think you are a target, " +
          "contact the Access Now Digital Security Helpline (accessnow.org/help) or the Amnesty International Security Lab " +
          "(securitylab.amnesty.org)."));
      } else if (s.hits_total > 0) {
        add(card, h("p", { "class": "note warn" },
          "Only mentions in saved content (for example an article about the campaign): they do not show that the device contacted anything."));
      }
    }
    if (err) {
      add(card, h("p", { "class": "note warn" }, "Last attempt failed (" + fmt(err.when) + "): " + err.reason));
    }
    var skip = meta.last_skip;
    if (skip && (!scans.length || String(scans[0].when) < String(skip.when))) {
      add(card, h("p", { "class": "note warn" }, "Scan of " + fmtDay(skip.when) + " skipped: " + skip.reason + "."));
    }
    if (meta.notifications_blocked) {
      add(card, h("p", { "class": "note warn" },
        "Notifications are blocked on this phone: Android has them turned off for the Shell app, which is what posts them. " +
        "Turn them on in Settings > Apps > (show system apps) > Shell > Notifications. Until then, alerts only show here and in the module description."));
    }
    if (meta.waiting_for_charger) {
      add(card, h("p", { "class": "note warn" }, "Tonight's scan is waiting for a charger (the \"only while charging\" setting)."));
    }
    add(card, h("p", { "class": "note" },
      "A clean result is not an all-clear. The scan only looks for known traces (published indicators) in Chrome, in app WebViews " +
      "and in app caches: it cannot see the traffic of native apps, nor spyware that leaves none of these traces."));
    var actions = h("div", { "class": "actions" });
    var msg = h("span", { "class": "muted" });
    var btn = h("button", { "class": "primary", type: "button" }, meta.running ? "Scan in progress…" : "Scan now");
    if (meta.running || !(window.ksu && window.ksu.exec)) btn.disabled = true;
    btn.addEventListener("click", function () {
      btn.disabled = true;
      var ok = run("kill -USR1 $(cat /data/adb/zero-breach/scheduler.pid)", function (code) {
        msg.textContent = code === 0 ? "Started in the background: reload this page in 10-15 minutes." : "Could not start it (is the scheduler running?).";
      });
      if (!ok) msg.textContent = "Only available from the root manager.";
    });
    add(actions, [btn, msg]);
    add(card, actions);
    return card;
  }

  function statusCard() {
    var rows = [];
    if (meta.running) rows.push(["Status", "scan in progress since " + fmt(meta.running).split(" ").pop()]);
    rows.push(["Next scan", meta.next || "—"]);
    if (meta.schedule) rows.push(["Schedule", meta.schedule]);
    if (scans.length) {
      var s = scans[0];
      rows.push(["Indicators", s.ioc_count + (s.ioc_age_days == null ? "" : " · list is " + plural(s.ioc_age_days, "day", "days") + " old")]);
      rows.push(["Scanner", "Zero Breach " + s.version]);
    }
    var upd = h("span", null, "bundled " + (meta.pinned || "?"));
    if (meta.newer) {
      add(upd, [" · ", h("span", { "class": "badge warn" }, "new version " + meta.latest), " (", meta.update_url || "", ")"]);
    } else if (meta.latest) {
      add(upd, " · latest release " + meta.latest);
    } else {
      add(upd, " · version check not run yet");
    }
    rows.push(["Zero Breach", upd]);
    var dl = h("dl");
    rows.forEach(function (r) { add(dl, [h("dt", null, r[0]), h("dd", null, r[1])]); });
    return h("section", { "class": "card" }, dl);
  }

  // --- settings ---------------------------------------------------------------
  // Values are checked here and again by set_config.py, which accepts only these
  // keys and shapes; the command line is built from checked tokens, never raw text.
  var DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

  function settingsCard() {
    var c = meta.config;
    var card = h("section", { "class": "card" }, h("strong", null, "Settings"));
    if (!c || !meta.set_cmd) {
      add(card, h("p", { "class": "muted" }, "Available after the scheduler has started."));
      return card;
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

    var msg = h("span", { "class": "muted" });
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
    add(card, h("div", { "class": "actions" }, save, msg));
    if (!editable) add(card, h("p", { "class": "muted" }, "Read-only here: change settings from the page opened in the root manager (or in config.sh)."));
    return card;
  }

  function historyList() {
    var ul = h("ul", { "class": "history" });
    scans.forEach(function (s) {
      var v = verdict(s);
      var b = h("button", { type: "button", "aria-current": s.id === selected ? "true" : "false" },
        h("span", { "class": "dot " + v.cls }),
        h("span", null, fmt(s.when)),
        h("span", { "class": "meta" }, s.hits_total ? plural(s.hits_total, "finding", "findings") : "clean", " · ", plural(s.gaps_total, "gap", "gaps")));
      b.addEventListener("click", function () { selected = s.id; render(); });
      add(ul, h("li", null, b));
    });
    return ul;
  }

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
    var x = g.first, serious = x.evidence !== "referenced";
    var c = h("div", { "class": "card hit" + (serious ? " serious" : "") });
    add(c, [
      h("div", null, h("span", { "class": "ind" }, g.indicators.join("  ")), " ",
        h("span", { "class": "badge " + (serious ? "bad" : "warn") }, x.evidence)),
      h("p", null, GLOSS[x.evidence] || "unclassified kind of evidence: treat it as serious"),
      x.who ? h("p", null, "App / profile: " + x.who) : null,
      x.seen ? h("p", null, "Observed: " + x.seen) : null,
      h("p", null, x.detail),
      h("p", { "class": "where" }, x.where),
      g.sources.length ? h("p", { "class": "muted" }, "Source: " + g.sources.join(", ")) : null
    ]);
    return c;
  }

  function detail(s) {
    var box = h("div");
    add(box, h("h2", null, "Scan of " + fmt(s.when)));
    if (s.hits.length) {
      add(box, groupHits(s.hits).map(hitCard));
      if (s.hits_total > s.hits.length) add(box, h("p", { "class": "muted" }, "Showing " + s.hits.length + " of " + s.hits_total + " findings; the full list is in the report."));
    } else {
      add(box, h("p", { "class": "muted" }, "No findings."));
    }

    add(box, h("h2", null, "What could not be checked (" + s.gaps_total + ")"));
    if (s.gaps.length) {
      var ul = h("ul", { "class": "plain" });
      s.gaps.forEach(function (g) { add(ul, h("li", null, g)); });
      add(box, h("div", { "class": "card" }, ul));
      if (s.gaps_total > s.gaps.length) add(box, h("p", { "class": "muted" }, "…and " + (s.gaps_total - s.gaps.length) + " more."));
    } else {
      add(box, h("p", { "class": "muted" }, "No gap declared."));
    }

    var mods = h("details");
    add(mods, h("summary", null, "Checks performed"));
    s.modules.forEach(function (m) {
      var d = h("div", { "class": "card check" });
      add(d, h("strong", null, m.name + " · " + m.status.toLowerCase()), " ",
        h("span", { "class": "muted" }, m.checked + " items read, " + m.skipped + " skipped, " + mins(Math.round(m.seconds))));
      var ul2 = h("ul", { "class": "plain" });
      m.checks.forEach(function (c) {
        add(ul2, h("li", null, h("span", { "class": c.ran ? "ran" : "skip" }, c.ran ? "ran" : "did not run"), " ", c.name, c.ran ? "" : " — " + c.reason));
      });
      if (m.checks_total > m.checks.length) add(ul2, h("li", { "class": "muted" }, "…and " + (m.checks_total - m.checks.length) + " more checks"));
      add(d, ul2);
      add(mods, d);
    });
    add(box, mods);

    if (s.text) {
      add(box, h("details", null, h("summary", null, "Full report"), h("pre", null, s.text)));
    }
    return box;
  }

  function render() {
    while (app.firstChild) app.removeChild(app.firstChild);
    add(app, [
      h("h1", null, "Zero Breach"),
      h("p", { "class": "sub" }, "Nightly check for the AdFection / Candiru indicators on this device"),
      summaryCard(),
      statusCard(),
      settingsCard()
    ]);
    if (scans.length) {
      add(app, [h("h2", null, "History (" + scans.length + ")"), historyList()]);
      var s = scans.filter(function (x) { return x.id === selected; })[0] || scans[0];
      add(app, detail(s));
    }
    if (meta.generated) add(app, h("p", { "class": "muted" }, "Page updated " + fmt(meta.generated)));
  }

  render();
})();
