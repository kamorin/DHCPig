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
const rate = { last: 0, series: [] };
const servers = new Map();
const neighbors = new Map();
const leases = [];
const ifaceCidr = {};       // iface name -> network cidr (for scope auto-fill)
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
  // exhaust has no --rate of its own; the windowed handshake pipeline paces it instead
  const isExhaust = mode === "exhaust";
  $("ratecfg").classList.toggle("hidden", isExhaust);
  $("ratehint").classList.toggle("hidden", !isExhaust);
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
  // headroom only means something for exhaust (it's a DHCP pool concept)
  if (mode !== "exhaust") {
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
function renderNeighbors() {
  const tb = document.querySelector("#t-neighbors tbody");
  tb.innerHTML = "";
  for (const n of neighbors.values()) {
    const fp = n.fp || {};
    tb.insertAdjacentHTML("beforeend",
      `<tr><td>${n.ip}</td><td>${n.mac}</td>` +
      `<td>${fp.os || fp.device || fp.vendor || ""}</td><td>${fp.confidence ?? ""}</td></tr>`);
  }
}
const findings = [];
const controls = [];

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

// List-valued evidence gets its own bulleted block; a narrative like RUN_SUMMARY's `steps` is
// unreadable flattened into one JSON blob, and existing list keys read better this way too.
function evidenceHtml(ev) {
  if (!ev) return "";
  const scalars = {};
  let out = "", lists = "";
  for (const [k, v] of Object.entries(ev)) {
    if (Array.isArray(v) && v.length) {
      // {did, got} pairs (RUN_SUMMARY's steps) render as two columns; the left column is
      // scannable on its own, which is the point of that finding.
      const pairs = v.every((i) => i && typeof i === "object" && "did" in i && "got" in i);
      lists += pairs
        ? `<div class="ev evsteps"><b>${esc(k)}</b><table>` +
          v.map((i) => `<tr><td>${esc(i.did)}</td><td>${esc(i.got)}</td></tr>`).join("") +
          "</table></div>"
        : `<div class="ev evlist"><b>${esc(k)}</b><ul>` +
          v.map((i) => `<li>${esc(typeof i === "string" ? i : JSON.stringify(i))}</li>`).join("") +
          "</ul></div>";
    } else {
      scalars[k] = v;
    }
  }
  if (Object.keys(scalars).length) out += `<div class="ev">${esc(JSON.stringify(scalars))}</div>`;
  return out + lists;
}

function renderFindings() {
  const el = $("t-findings");
  if (!findings.length && !controls.length) return;
  let html = "";
  if (controls.length) {
    html += '<div class="ctlbox"><b>Control transactions</b> (real NIC MAC)<ul>';
    for (const c of controls) {
      const status = !c.attempted
        ? "skipped — " + esc(c.reason)
        : c.success
          ? "OK — lease " + esc(c.offered_ip) + " from " + esc(c.server_id)
          : "FAILED — " + esc(c.reason);
      const cls = !c.attempted ? "skip" : c.success ? "ok" : "bad";
      const who = c.client === "self" ? "own MAC (renewal)" : "new client";
      html += `<li class="${cls}"><b>${esc(c.phase)} / ${esc(who)}</b>: ${status} ` +
        `<i>(${esc(c.elapsed)}s)</i></li>`;
    }
    html += "</ul></div>";
  }
  for (const f of findings) {
    html +=
      `<div class="finding ${esc(f.verdict)}">` +
      `<span class="v">${esc(f.verdict)}</span> <b>${esc(f.title)}</b> ` +
      `<code>${esc(f.id)}</code>` +
      evidenceHtml(f.evidence) +
      (f.recommendation ? `<div class="rec">${esc(f.recommendation)}</div>` : "") +
      "</div>";
  }
  el.innerHTML = html;
}

function renderLeases() {
  const tb = document.querySelector("#t-leases tbody");
  tb.innerHTML = "";
  for (const l of leases) {
    tb.insertAdjacentHTML("beforeend",
      `<tr><td>${l.ip}</td><td>${l.mac}</td><td>${l.server_ip}</td></tr>`);
  }
}

// ---- canvas sparkline -----------------------------------------------------
function drawSpark() {
  const c = $("spark"), ctx = c.getContext("2d");
  const w = c.width, h = c.height, s = rate.series;
  ctx.clearRect(0, 0, w, h);
  if (s.length < 2) return;
  const max = Math.max(1, ...s);
  ctx.strokeStyle = "#4ec9b0"; ctx.lineWidth = 2; ctx.beginPath();
  s.forEach((v, i) => {
    const x = (i / (s.length - 1)) * (w - 4) + 2;
    const y = h - 4 - (v / max) * (h - 8);
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
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
      const counts = {};
      for (const r of e.rows || []) counts[r[3]] = (counts[r[3]] || 0) + 1;
      const tally = Object.entries(counts).map(([c, n]) => `${n} ${c}`).join("  ");
      logLine("finding",
        `[==] NEIGHBOR SUMMARY  ${e.total} host(s) seen before this run  (${tally})`, 0);
      for (const [ip, mac, outcome, category] of e.rows || []) {
        const cls = category === "offline" || category === "lease_taken" ? "alert"
          : category === "unaffected" ? "notice" : "in";
        logLine(cls, `       ${ip.padEnd(15)} ${mac}  ${outcome}`, 0);
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
      controls.push(o); renderFindings();
      logLine(o.attempted && !o.success ? "alert" : "ctl",
        `[CTL] CONTROL[${o.phase}/${who}] ${msg}`, 1);
      break;
    }
    case "FindingRaised":
      findings.push(e.finding); renderFindings();
      // the Findings tab stays out of the way until there's actually a verdict to show,
      // then it's the one thing worth interrupting the operator's current view for
      if (findings.length === 1) activateTab("findings");
      logLine("finding",
        `[==] ${e.finding.verdict} — ${e.finding.title} (${e.finding.id})`, 0);
      break;
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
    const pps = Math.max(0, (status.discovers ?? 0) - rate.last);
    rate.last = status.discovers ?? 0;
    $("c-a").textContent = primary;
    $("c-b").textContent = status.servers ?? 0;
    $("c-c").textContent = scanlike ? neighbors.size : pps;
    $("c-d").textContent = (status.elapsed ?? 0) + "s";
    $("state").textContent = status.state ?? "";
    if (mode === "exhaust" && status.pool_size != null) {
      const tag = status.pool_source === "scope" ? "" : " est.";
      $("c-e").textContent = status.headroom != null ? status.headroom : "—";
      $("l-e").textContent = `headroom / ~${status.pool_size}${tag}`;
      $("headroomcell").classList.remove("dim");
      $("headroomcell").title = status.pool_detail || "";
    } else if (mode === "exhaust") {
      $("c-e").textContent = "—";
      $("l-e").textContent = "headroom (unknown)";
      $("headroomcell").classList.add("dim");
    }
    rate.series.push(pps); if (rate.series.length > 120) rate.series.shift();
    drawSpark();
  } catch (_) {}
}
setInterval(pollStatus, 1000);

// ---- start ----------------------------------------------------------------
async function doStart() {
  const cfg = currentConfig();
  try {
    await api("/api/session/start", "POST", cfg);
    rate.last = 0; rate.series = []; leases.length = 0;
    servers.clear(); neighbors.clear();
    findings.length = 0; controls.length = 0;
    $("t-findings").innerHTML =
      '<p class="hint">Run in progress — verdicts appear here when it ends.</p>';
    renderServers(); renderNeighbors(); renderLeases();
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
  if (c.mode !== "exhaust") s += ` --rate ${c.rate}`;
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
const TAB_NAMES = ["neighbors", "servers", "leases", "findings"];
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
