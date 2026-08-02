"use strict";
// DHCPig web UI (V2.0) — vanilla JS, no build step. Token comes from the ?token= URL param.

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const $ = (id) => document.getElementById(id);
const authHdr = { Authorization: "Bearer " + TOKEN };

async function api(path, method = "GET", body) {
  const opts = { method, headers: { ...authHdr } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  let data = {};
  try { data = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(data.error || "HTTP " + r.status);
  return data;
}

let running = false;
// Four independent per-second series, all counting frames this tool actually transmits (never
// replies received) -- discover/release/arp are self-explanatory; "renew" is the REQUEST this
// tool sends after every OFFER, which the control transaction's own docstring treats as a
// renewal probe (see _control_transaction() in engine.py) even though it's never a true
// unicast RFC 2131 renewal. pps (the dashboard tile) is just their sum.
const rate = {
  discoverLast: 0, discoverSeries: [],
  releaseLast: 0, releaseSeries: [],
  arpLast: 0, arpSeries: [],
  renewLast: 0, renewSeries: [],
};
function pushSeries(series, v) {
  series.push(v);
  if (series.length > 120) series.shift();
}
const servers = new Map();
const neighbors = new Map();
const leases = [];
const ifaceCidr = {};       // iface name -> network cidr (for scope auto-fill)

// What pressing Start will actually do, per mode. Written for someone who isn't a DHCP
// specialist: the sequence in plain words, then one line on who gets hurt. `harm` drives the
// colour, so a read-only mode never looks like a destructive one.
const MODE_NOTES = {
  exhaust: {
    harm: true,
    text: "Releases every neighbour's address and requests it back from the server for a " +
      "random MAC, then keeps requesting addresses until the pool is empty. Connected devices " +
      "should lose their address, and no device should be able to get a new one.",
  },
  release: {
    harm: true,
    text: "Releases every neighbour's address and requests it back from the server for a " +
      "random MAC, then contests the neighbour's IP with forged ARP. Connected devices should " +
      "lose their address and have to request a new one from the pool.",
  },
  "release-previous": {
    harm: false,
    text: "Recovery. Hands back every address this tool took on this network. " +
      "Sends nothing if the pool isn't exhausted.",
  },
  "active-scan": {
    harm: false,
    text: "Read-only. ARP-sweeps the scope and fingerprints the DHCP servers.",
  },
  scan: {
    harm: false,
    text: "Read-only. Watches DHCP and ARP traffic without sending anything.",
  },
};
let lastAutoScope = "";     // remember what we auto-filled so we don't clobber user edits

// ---- config <-> payload ---------------------------------------------------
function currentConfig() {
  const scope = $("scope").value.split(",").map((s) => s.trim()).filter(Boolean);
  return {
    interface: $("iface").value,
    mode: $("mode").value,
    rate: +$("rate").value,
    dry_run: $("dryrun").checked,
    scope_cidrs: scope.length ? scope : null,
    spoof_eth_src: $("spoofeth").checked,
    verbosity: currentVerbosity(),
  };
}

function applyConfig(c) {
  if (!c) return;
  if (c.interface) $("iface").value = c.interface;
  if (c.mode) $("mode").value = c.mode;
  if (c.rate != null) $("rate").value = c.rate;
  if (c.dry_run != null) $("dryrun").checked = c.dry_run;
  if (c.spoof_eth_src != null) $("spoofeth").checked = c.spoof_eth_src;
  if (Array.isArray(c.scope_cidrs)) $("scope").value = c.scope_cidrs.join(", ");
  onModeChange();
}

// ---- UI state -------------------------------------------------------------
function setRunning(on) {
  running = on;
  $("start").disabled = on;
  $("stop").disabled = !on;
  ["iface", "mode", "rate", "dryrun", "scope", "spoofeth"]
    .forEach((id) => ($(id).disabled = on));
}

function onModeChange() {
  const mode = $("mode").value;
  // Scope applies to every mode -- it bounds the ARP sweep and the _send() scope guard in all
  // of them, and for exhaust it's also what makes the pool-size estimate deterministic rather
  // than inferred from the first OFFER's subnet. The panel used to appear only for
  // release/active-scan/release-previous, which made the form jump around on mode change and
  // hid a control that was doing real work in exhaust too. Always shown now.
  const note = MODE_NOTES[mode];
  $("modenote").textContent = note ? note.text : "";
  $("modenote").classList.toggle("harm", !!(note && note.harm));
  // exhaust and release have no --rate of their own; release's re-acquisition leg shares
  // exhaust's windowed handshake pipeline, which paces it and backs off on NAKs the same way.
  const selfPaced = mode === "exhaust" || mode === "release";
  $("ratecfg").classList.toggle("hidden", selfPaced);
  $("ratehint").classList.toggle("hidden", !selfPaced);
  // release-previous defaults to 50pps, not the 7pps every other mode uses -- it runs during
  // an outage the operator is trying to end, and its frames are unicast to one server rather
  // than sprayed at the segment. Only nudge the field if it's still sitting at a default.
  if (mode === "release-previous" && +$("rate").value === 7) $("rate").value = 50;
  else if (mode !== "release-previous" && +$("rate").value === 50) $("rate").value = 7;
  autofillScope();
  const labels = {
    exhaust: ["leases", "servers", "pps"],
    scan: ["hosts", "servers", "resolved"],
    "active-scan": ["hosts", "servers", "resolved"],
    release: ["released", "neighbors", "pps"],
    "release-previous": ["released", "servers", "pps"],
  }[mode];
  $("l-a").textContent = labels[0];
  $("l-b").textContent = labels[1];
  $("l-c").textContent = labels[2];
  // headroom means something for exhaust (free addresses left) and release-previous (addresses
  // this run is handing back) -- both are CIDR-derived pool numbers; every other mode leaves it
  // dimmed since there's no pool concept to report
  if (mode !== "exhaust" && mode !== "release-previous") {
    $("c-e").textContent = "—";
    $("l-e").textContent = "headroom";
    $("headroomcell").classList.add("dim");
  }
}

function autofillScope() {
  // fill the scope with the selected interface's network, unless the user typed their own
  const cidr = ifaceCidr[$("iface").value];
  const cur = $("scope").value.trim();
  if (cidr && (cur === "" || cur === lastAutoScope)) {
    $("scope").value = cidr;
    lastAutoScope = cidr;
  }
}

// ---- log + tables ---------------------------------------------------------
// level: 0 errors (always) · 1 notice/summary · 2 normal traffic · 3 debug
function currentVerbosity() {
  return +$("verbosity").value;
}

function logLine(cls, text, level = 2) {
  const el = $("log");
  const span = document.createElement("span");
  span.className = cls;
  span.dataset.level = level;
  span.textContent = text + "\n";
  span.style.display = level <= currentVerbosity() ? "" : "none";
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
  // Anything styled "alert" (a [!!] line -- pool exhaustion, a defensive control firing, a
  // denied host, ... -- or any other line the caller judged alert-worthy, like a failed CONTROL
  // transaction or an [XX] error) is the log's highest-severity tag -- flag the center tables
  // panel too, since the neighbors/hosts roll-call is what an operator is looking at, not the
  // scrolling log underneath it. Also surface it in the dashboard panel, where the graph/
  // counters already are.
  if (cls === "alert") { flagAlert(); addDashboardAlert(text); }
}

function addDashboardAlert(text) {
  const el = $("alerts");
  const div = document.createElement("div");
  div.textContent = text;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function flagAlert() {
  $("tables").classList.add("alert-flag");
}

function applyVerbosityFilter() {
  const v = currentVerbosity();
  for (const span of $("log").children) {
    span.style.display = +span.dataset.level <= v ? "" : "none";
  }
  $("log").scrollTop = $("log").scrollHeight;
}

function renderServers() {
  const tb = document.querySelector("#t-servers tbody");
  tb.innerHTML = "";
  for (const s of servers.values()) {
    const fp = s.fingerprint || {};
    tb.insertAdjacentHTML("beforeend",
      `<tr><td>${s.server_id}</td><td>${s.offers_seen}</td>` +
      `<td>${fp.os || fp.device || fp.vendor || ""}</td><td>${fp.confidence ?? ""}</td></tr>`);
  }
}
// Result column classes mirror the OUTCOME roll-call's own severity groupings (see the `cls()`
// helper in the NeighborSummary case below) so a host's row in this table and its line in the
// log/OUTCOME block always agree on how bad its outcome is.
const RESULT_CLASS = {
  offline: "res-bad", lease_taken: "res-bad",
  released_unconfirmed: "res-warn",
  reacted: "res-in", unaffected: "res-notice",
};
function renderNeighbors() {
  const tb = document.querySelector("#t-neighbors tbody");
  tb.innerHTML = "";
  for (const n of neighbors.values()) {
    const fp = n.fp || {};
    const resultCls = RESULT_CLASS[n.category] || "";
    tb.insertAdjacentHTML("beforeend",
      `<tr><td>${n.ip}</td><td>${n.mac}</td>` +
      `<td>${fp.os || fp.device || fp.vendor || ""}</td>` +
      `<td class="${resultCls}">${esc(n.outcome || "")}</td></tr>`);
  }
}
function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

// A finding's summary lines (its numbers, list evidence one item per line, then the first
// sentence of its recommendation) come from the server now -- `f.summary`, computed by
// core/findings.py's finding_summary_lines() and attached to every FindingRaised event by
// events.to_dict(). This used to be reimplemented here in JS and had already drifted from the
// Python version (list evidence dumped as `key=len(...)` instead of one line per item) before
// that happened; rendering the server's own list instead of re-deriving one makes that
// impossible instead of merely documented against. The full evidence and full multi-sentence
// recommendation still go to report["findings"] and so to the JSON/HTML export, which is where
// someone writing up the engagement reads them -- this is a summary surface, not the record.

// Findings whose content already has a dedicated log block. NEIGHBORS_OBSERVED is the same
// rows as the OUTCOME roll-call, printed immediately below it -- keep it in report["findings"]
// for the export, but printing it twice in the log is just noise.
const FINDINGS_NOT_LOGGED = new Set(["NEIGHBORS_OBSERVED"]);

function renderLeases() {
  const tb = document.querySelector("#t-leases tbody");
  tb.innerHTML = "";
  for (const l of leases) {
    tb.insertAdjacentHTML("beforeend",
      `<tr><td>${l.ip}</td><td>${l.mac}</td><td>${l.server_ip}</td></tr>`);
  }
}

// ---- canvas sparkline -----------------------------------------------------
// Four lines share one scale -- ARP, DHCP discover, DHCP release, DHCP renew (the REQUEST that
// follows an OFFER) -- so the full transmit-side traffic mix is visible at once instead of one
// rate hiding another.
function drawLine(ctx, s, w, h, max, color) {
  if (s.length < 2) return;
  ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
  s.forEach((v, i) => {
    const x = (i / (s.length - 1)) * (w - 4) + 2;
    const y = h - 4 - (v / max) * (h - 8);
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
}
function drawSpark() {
  const c = $("spark"), ctx = c.getContext("2d");
  const w = c.width, h = c.height;
  const { arpSeries: as, discoverSeries: ds, releaseSeries: rs, renewSeries: ns } = rate;
  ctx.clearRect(0, 0, w, h);
  if (as.length < 2 && ds.length < 2 && rs.length < 2 && ns.length < 2) return;
  const max = Math.max(1, ...as, ...ds, ...rs, ...ns);
  drawLine(ctx, as, w, h, max, "#6ab0ff");
  drawLine(ctx, ds, w, h, max, "#4ec9b0");
  drawLine(ctx, rs, w, h, max, "#e0679a");
  drawLine(ctx, ns, w, h, max, "#e8b04b");
}

// ---- SSE ------------------------------------------------------------------
function connectStream() {
  const es = new EventSource("/events?token=" + encodeURIComponent(TOKEN));
  es.onopen = () => { $("conn").textContent = "SSE: connected"; $("conn").className = "pill on"; };
  es.onerror = () => { $("conn").textContent = "SSE: off"; $("conn").className = "pill off"; };
  es.onmessage = (ev) => { try { handleEvent(JSON.parse(ev.data)); } catch (_) {} };
}

function handleEvent(e) {
  switch (e.type) {
    case "DiscoverSent": {
      let tail = `  chaddr=${e.mac}`;
      if (e.option50) tail += `  option50=${e.option50}`;
      if (e.hostname) tail += `  hostname=${e.hostname}`;
      logLine("out", `[->] DHCP_Discover${tail}`, 2); break;
    }
    case "OfferReceived":
      logLine("in", `[<-] DHCP_Offer    ${e.lease.ip}   from ${e.server.server_id}  chaddr=${e.lease.mac}`, 2); break;
    case "RequestSent": {
      let tail = `  chaddr=${e.lease.mac}`;
      if (e.option50) tail += `  option50=${e.option50}`;
      if (e.hostname) tail += `  hostname=${e.hostname}`;
      logLine("out", `[->] DHCP_Request  ${e.lease.ip}${tail}`, 2); break;
    }
    case "AckReceived":
      leases.push(e.lease); renderLeases();
      logLine("in", `[<-] DHCP_ACK      ${e.lease.ip}   chaddr=${e.lease.mac}`, 2); break;
    case "ServerDiscovered":
      servers.set(e.server.server_id, e.server); renderServers();
      logLine("note", `[--] DHCP server ${e.server.server_id}`, 1); break;
    case "NeighborFound": {
      // keyed by MAC so an ARP sighting and a later/earlier DHCP fingerprint for the same
      // host merge into one row instead of showing up as two
      const prev = neighbors.get(e.neighbor.mac) || {};
      neighbors.set(e.neighbor.mac, { ip: e.neighbor.ip, mac: e.neighbor.mac,
        fp: e.neighbor.fingerprint || prev.fp });
      renderNeighbors();
      logLine("in", `[<-] ARP ${e.neighbor.ip} : ${e.neighbor.mac}`, 2); break;
    }
    case "HostFingerprinted": {
      const fp = e.fp;
      // only client-role fingerprints belong on the Neighbors tab (servers have their own tab)
      if (fp.role === "client" && fp.mac) {
        const prev = neighbors.get(fp.mac) || { ip: "", mac: fp.mac };
        neighbors.set(fp.mac, { ...prev, mac: fp.mac, fp });
        renderNeighbors();
      }
      logLine("note",
        `[--] ${fp.role || "host"} ${fp.mac}  ${fp.os || fp.device || "?"}  conf ${fp.confidence}%`, 2);
      break;
    }
    case "LeaseReleased":
      logLine("out", `[->] DHCPRELEASE  ${e.lease.ip}   chaddr=${e.lease.mac}`, 2); break;
    case "ArpConflictSent": logLine("out", `[->] ARP_conflict contest ownership of ${e.ip}`, 2); break;
    case "ForeignDiscover": {
      const who = e.hostname ? `  hostname=${e.hostname}` : "";
      logLine("note", `[<-] foreign DHCP_Discover  ${e.mac}${who}  (not ours)`, 2);
      break;
    }
    case "ClientEvicted": {
      const bad = ["declined", "discover_unanswered", "apipa"].includes(e.outcome);
      logLine(bad ? "alert" : "in",
        `[${bad ? "!!" : "<-"}] evict outcome  ${e.ip} / ${e.mac}  -> ${e.outcome}`, 2);
      break;
    }
    case "NeighborSummary": {
      // One [==] OUTCOME header covers per-host detail and the tally beneath it (2.7.2) --
      // mirrors cli/render.py's Renderer._neighbor_summary(), which is the source of truth for
      // this layout; keep the two in sync if either changes.
      const cls = (c) => c === "offline" || c === "lease_taken" ? "alert"
        : c === "released_unconfirmed" ? "warnline"
        : c === "unaffected" ? "notice" : "in";
      logLine("finding", `[==] OUTCOME  ${e.total} host(s) seen before this run`, 0);
      if (e.pool_exhausted) {
        logLine("alert",
          `[!!]   POOL EXHAUSTED -- ${e.leases_acquired} lease(s) acquired; neighbors ` +
          `relying on this pool cannot renew`, 0);
      }
      // Feed each row's outcome/category into the neighbors table's Result column too -- this
      // is the same per-host classification, just also shown where the run's live discovery
      // rows already are instead of only at the end of the log.
      for (const [, mac, , outcome, category] of e.rows || []) {
        const prev = neighbors.get(mac);
        if (prev) neighbors.set(mac, { ...prev, outcome, category });
      }
      renderNeighbors();
      // hostname column only when we have one for somebody -- DHCP option 12 is the only
      // source, so an ARP-only segment has none and an always-on column would sit blank
      const namew = Math.max(0, ...(e.rows || []).map((r) => (r[2] || "").length));
      for (const [ip, mac, host, outcome, category, device] of e.rows || []) {
        const name = namew ? (host || "").padEnd(namew) + "  " : "";
        // [device/OS] tag sits before the outcome text, same "" when unknown treatment as the
        // hostname column above -- most ARP-only neighbours have neither
        const tag = device ? `[${device}]  ` : "";
        logLine(cls(category), `       ${ip.padEnd(15)} ${mac}  ${name}${tag}${outcome}`, 0);
      }
      // Blank line between the per-host detail and the tally beneath it -- mirrors
      // cli/render.py's Renderer._neighbor_summary(): one [==] OUTCOME header still covers
      // both, but a hard break separates who from how many.
      logLine("note", "", 0);
      // the concluding "N host(s) did X" roll-up -- same data, aggregated. Counts and what
      // happened, never a verdict: the findings own pass/fail.
      const tally = new Map();
      for (const [, , , outcome, category] of e.rows || []) {
        const [n] = tally.get(outcome) || [0, category];
        tally.set(outcome, [n + 1, category]);
      }
      for (const [outcome, [n, category]] of tally) {
        logLine(cls(category), `       ${String(n).padStart(3)} host(s)  ${outcome}`, 0);
      }
      break;
    }
    case "Skipped": logLine("alert", `[!!] SKIPPED ${e.ip}  ${e.reason}`, 1); break;
    case "StatusTick": {
      const s = e.stats, w = Math.round(s.window || 0);
      const bits = [`t=${Math.round(s.elapsed || 0)}s`, s.state];
      const col = (label, key, rateKey) => {
        const total = s[key] || 0, d = s["d_" + key] || 0;
        if (!total && !d) return;
        const rate = rateKey && s[rateKey] != null ? `, ${s[rateKey]}/s` : "";
        bits.push(`${label} ${total} (+${d} in ${w}s${rate})`);
      };
      col("leases", "leases", "lease_pps");
      col("discovers", "discovers", "discover_pps");
      col("offers", "offers"); col("naks", "naks");
      col("releases", "releases"); col("arp_conflicts", "arp_conflicts");
      col("foreign_discovers", "foreign_discovers");
      col("foreign_unanswered", "foreign_discovers_unanswered");
      col("races", "races");
      if (s.servers) bits.push(`servers ${s.servers}`);
      if (s.neighbors) bits.push(`neighbors ${s.neighbors}`);
      if (s.send_window != null) bits.push(`window ${s.send_window} (inflight ${s.inflight || 0})`);
      if (s.timeouts) bits.push(`timeouts ${s.timeouts}`);
      if (s.headroom != null) {
        const tag = s.pool_source === "scope" ? "" : " est.";
        bits.push(`headroom ${s.headroom} / ~${s.pool_size}${tag}`);
      }
      if (s.since_last_offer != null) bits.push(`last offer ${Math.round(s.since_last_offer)}s ago`);
      if (s.halt_signal) bits.push(`HALTED[${s.halt_signal}]`);
      // level 3 (debug): the dashboard already shows these numbers live, so in the log the
      // 5-second pulse only drowns out the packet lines around it
      logLine("stat", "[##] " + bits.join("  "), 3);
      break;
    }
    case "ControlDetected":
      logLine("alert",
        `[!!] CONTROL DETECTED [${e.signal}]  ${e.detail}  — sending stopped, ` +
        `${e.leases_held} lease(s) held for the report`, 0);
      $("state").textContent = "HALTED"; break;
    case "OffersCeased":
      logLine("note",
        `[--] offers quiet ${e.quiet_for.toFixed(0)}s after ${e.leases} lease(s) — ` +
        `declaring exhaustion at ${e.deadline.toFixed(0)}s`, 1);
      $("state").textContent = "DRAINING?"; break;
    case "PoolExhausted":
      logLine("alert",
        `[!!] POOL EXHAUSTED leases=${e.leases} ` +
        `[${e.confirmed ? "CONFIRMED by post-run control" : "provisional — offers stopped"}]`, 1);
      $("state").textContent = "EXHAUSTED"; break;
    case "ControlStarted":
      logLine("ctl", `[CTL] CONTROL[${e.phase}] legitimate DHCP cycle from real NIC MAC`, 1);
      break;
    case "ControlFinished": {
      const o = e.outcome;
      const who = o.client === "self" ? "own MAC/renewal" : "NEW client";
      const msg = !o.attempted
        ? o.reason
        : o.success
          ? `OK — obtained ${o.offered_ip} from ${o.server_id} in ${o.elapsed}s (released)`
          : `FAILED — ${o.reason}`;
      logLine(o.attempted && !o.success ? "alert" : "ctl",
        `[CTL] CONTROL[${o.phase}/${who}] ${msg}`, 1);
      break;
    }
    case "FindingRaised": {
      // The log is the only results surface now -- no findings tab, no client-side finding
      // store. `verdict`/`severity` still ride along on the object and still reach
      // report["findings"], so the JSON/HTML export is unchanged; this is a view being
      // removed, not data. High/medium sit at level 0 so verbosity 0 == "results only";
      // info drops to level 1 so it doesn't crowd them out.
      const f = e.finding;
      if (FINDINGS_NOT_LOGGED.has(f.id)) break;
      const sev = { high: "HIGH", medium: "MED " }[f.severity] || (f.verdict === "PASS" ? "PASS" : "INFO");
      const cls = f.severity === "high" ? "alert"
        : f.severity === "medium" ? "warnline"
          : f.verdict === "PASS" ? "in" : "notice";
      logLine(cls, `[==] ${sev}  ${f.title}`, f.severity === "info" ? 1 : 0);
      for (const line of f.summary || []) logLine("notice", `        ${line}`, 1);
      break;
    }
    case "SessionEnded": $("state").textContent = "DONE"; setRunning(false); break;
    case "ErrorEvent": logLine("alert", "[XX] " + e.message, 0); break;
    case "Debug": logLine("dbg", "[DBG] " + e.message, 3); break;
  }
}

// ---- status polling -------------------------------------------------------
async function pollStatus() {
  if (!running) return;
  try {
    const { status } = await api("/api/session/status");
    const mode = $("mode").value;
    const scanlike = mode === "scan" || mode === "active-scan";
    const primary = { exhaust: status.leases, scan: neighbors.size,
      "active-scan": neighbors.size, release: status.releases,
      "release-previous": status.releases }[mode] ?? 0;
    // Every rate is transmit-side (frames this tool actually sent), never a reply received --
    // see the `rate` object's own comment. "pps" is their sum: total wire activity, not just
    // whichever single counter happens to be the current mode's primary metric.
    const discoverPps = Math.max(0, (status.discovers ?? 0) - rate.discoverLast);
    rate.discoverLast = status.discovers ?? 0;
    const releasePps = Math.max(0, (status.releases ?? 0) - rate.releaseLast);
    rate.releaseLast = status.releases ?? 0;
    const arpPps = Math.max(0, (status.arp_sent ?? 0) - rate.arpLast);
    rate.arpLast = status.arp_sent ?? 0;
    const renewPps = Math.max(0, (status.requests_sent ?? 0) - rate.renewLast);
    rate.renewLast = status.requests_sent ?? 0;
    const pps = discoverPps + releasePps + arpPps + renewPps;
    $("c-a").textContent = primary;
    $("c-b").textContent = status.servers ?? 0;
    $("c-c").textContent = scanlike ? neighbors.size : pps;
    $("c-d").textContent = (status.elapsed ?? 0) + "s";
    $("state").textContent = status.state ?? "";
    if (mode === "exhaust" && status.pool_size != null) {
      const tag = status.pool_source === "scope" ? "" : " est.";
      const n = status.headroom != null ? status.headroom : "—";
      $("c-e").textContent = `${n} / ${status.pool_size}${tag}`;
      $("l-e").textContent = "headroom";
      $("headroomcell").classList.remove("dim");
      $("headroomcell").title = status.pool_detail || "";
    } else if (mode === "exhaust") {
      $("c-e").textContent = "—";
      $("l-e").textContent = "headroom (unknown)";
      $("headroomcell").classList.add("dim");
    } else if (mode === "release-previous" && status.pool_size != null) {
      const tag = status.pool_source === "scope" ? "" : " est.";
      const n = status.headroom != null ? status.headroom : "—";
      $("c-e").textContent = `${n} / ${status.pool_size}${tag}`;
      $("l-e").textContent = "resetting";
      $("headroomcell").classList.remove("dim");
    } else if (mode === "release-previous") {
      $("c-e").textContent = "—";
      $("l-e").textContent = "headroom (unknown)";
      $("headroomcell").classList.add("dim");
    }
    pushSeries(rate.discoverSeries, discoverPps);
    pushSeries(rate.releaseSeries, releasePps);
    pushSeries(rate.arpSeries, arpPps);
    pushSeries(rate.renewSeries, renewPps);
    drawSpark();
  } catch (_) {}
}
setInterval(pollStatus, 1000);

// ---- start ----------------------------------------------------------------
async function doStart() {
  const cfg = currentConfig();
  try {
    await api("/api/session/start", "POST", cfg);
    rate.discoverLast = 0; rate.discoverSeries = [];
    rate.releaseLast = 0; rate.releaseSeries = [];
    rate.arpLast = 0; rate.arpSeries = [];
    rate.renewLast = 0; rate.renewSeries = [];
    leases.length = 0;
    servers.clear(); neighbors.clear();
    renderServers(); renderNeighbors(); renderLeases();
    $("tables").classList.remove("alert-flag");
    $("alerts").innerHTML = "";
    setRunning(true);
  } catch (err) { logLine("alert", "[XX] " + err.message); }
}

$("start").addEventListener("click", () => {
  const cfg = currentConfig();
  if (cfg.mode === "active-scan" && !cfg.scope_cidrs) {
    logLine("alert", "[XX] active-scan needs a scope CIDR (auto-filled from the interface)", 0);
    return;
  }
  doStart();
});

$("stop").addEventListener("click", async () => {
  try { await api("/api/session/stop", "POST", {}); } catch (_) {}
  setRunning(false);
});

// ---- export / copy-cli / profiles ----------------------------------------
document.querySelectorAll(".exportgrp button").forEach((b) =>
  b.addEventListener("click", async () => {
    const fmt = b.dataset.fmt;
    const r = await fetch("/api/report", {
      method: "POST", headers: { ...authHdr, "Content-Type": "application/json" },
      body: JSON.stringify({ format: fmt }),
    });
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "dhcpig-report." + fmt; a.click();
  }));

$("copycli").addEventListener("click", async () => {
  let cmd = cliFromConfig();
  try { const { command } = await api("/api/session/as-cli"); if (command) cmd = command; }
  catch (_) {}
  try { await navigator.clipboard.writeText(cmd); } catch (_) {}
  logLine("note", "[--] " + cmd);
});
function cliFromConfig() {
  const c = currentConfig();
  let s = `dhcpig ${c.mode} ${c.interface}`;
  if (c.mode !== "exhaust" && c.mode !== "release") s += ` --rate ${c.rate}`;
  (c.scope_cidrs || []).forEach((x) => (s += ` --scope ${x}`));
  if (c.dry_run) s += " --dry-run";
  return s;
}

$("saveprofile").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(currentConfig(), null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = "dhcpig-profile.json"; a.click();
});
$("loadprofile").addEventListener("change", (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => { try { applyConfig(JSON.parse(reader.result)); } catch (_) {} };
  reader.readAsText(f);
});

// ---- tabs -----------------------------------------------------------------
const TAB_NAMES = ["neighbors", "servers", "leases"];
function activateTab(name) {
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.tab === name));
  for (const n of TAB_NAMES) $("t-" + n).classList.toggle("hidden", n !== name);
}
document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => activateTab(t.dataset.tab)));

$("mode").addEventListener("change", onModeChange);
$("iface").addEventListener("change", autofillScope);
$("dryrun").addEventListener("change", () =>
  $("drybanner").classList.toggle("show", $("dryrun").checked));
$("verbosity").addEventListener("change", applyVerbosityFilter);

// ---- boot -----------------------------------------------------------------
(async function init() {
  $("drybanner").classList.toggle("show", $("dryrun").checked);
  try {
    const { interfaces } = await api("/api/ifaces");
    // interfaces: [{name, cidr}]; back-compat if a plain string list is returned
    $("iface").innerHTML = interfaces
      .map((i) => (typeof i === "string" ? i : i.name))
      .map((n) => `<option>${n}</option>`)
      .join("");
    for (const i of interfaces) {
      if (typeof i === "object" && i.cidr) ifaceCidr[i.name] = i.cidr;
    }
  } catch (err) { logLine("alert", "[XX] " + err.message + " (bad token?)", 0); }
  onModeChange();  // after ifaceCidr is populated so scope can auto-fill
  connectStream();
})();
