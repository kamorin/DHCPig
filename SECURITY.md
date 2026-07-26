# Security & Responsible Use

DHCPig is a whitehat validation tool. It must only be used on networks you own or are
explicitly authorized to test.

## Built-in guardrails
- `exhaust` paces itself with a windowed, adaptive handshake pipeline (starts small, grows very
  slowly on a clean ACK — 100 clean ACKs per +1 slot — halves instantly on a NAK/timeout/
  duplicate offer) instead of a flat rate cap — see the README's EXHAUST PIPELINE section.
  `release` and `active-scan` still take a rate cap (`--rate`, default 7 pps) bounding how fast
  they emit RELEASE/ARP/INFORM traffic; `release`'s eviction sub-phase paces itself separately
  via `evict_rounds`/`timeouts.evict_interval`, not `--rate`. `release-previous` also takes
  `--rate` but defaults to 50 pps — its frames are unicast to a single server, not sprayed at the
  segment, and it runs during an outage the operator is actively trying to end.
- `exhaust` also **halts sending immediately** if a defensive control fires mid-run (a NAK
  burst, the link going down, a timeout storm, or a duplicate-offer pattern) — it doesn't try to
  push through a control that's already working. Leases already acquired are kept (not
  released) so the post-run report is still meaningful; see "Leaving the network as you found
  it" below.
- `exhaust` and `release` both run a release phase before consuming/contesting addresses,
  sending DHCPRELEASE for ARP-discovered neighbors (`--no-release` on `exhaust`; there's no
  equivalent flag on `release`, since skipping it defeats the mode). This is itself a probe of
  whether the server honours unauthenticated RELEASE from a third party — see
  `NEIGHBOR_LEASES_RELEASED` in the findings output.
- `exhaust` and `release` both run **RFC 5227 ARP-conflict eviction** against every address they
  just re-acquired, contesting the real owner's claim to force a DECLINE/restart/APIPA fallback
  — `--no-evict` skips this on either mode. See "Eviction is the biggest change in blast radius"
  below.
- `--scope CIDR` bounds which addresses a run may target; out-of-scope targets are dropped.
- `--dry-run` is a genuine reconnaissance pass (the ARP sweep and control transactions run for
  real — they self-clean and cost the target nothing) that builds and logs every *mutating* frame
  (release, re-acquisition, the exhaust sender, eviction) without sending it. It defaults to
  **off** — a run is live unless you pass `--dry-run` explicitly. **Run with `--dry-run` first**
  on any network you haven't tested against before; it's the cheapest way to see a run's target
  list and finding shape before it can touch anything.
- `exhaust` tracks every lease it acquires and can release exactly those, and only those.
  **Leases are always kept after the run** so the exhausted state can be verified; release them
  explicitly with `dhcpig restore <iface>` (or the Restore button) when the same process is
  still around, or `dhcpig release-previous <iface>` once it isn't — see RECOVERY below. There
  is no auto-restore-on-exit anymore: cleanup is always a deliberate, caller-initiated step.
- Out-of-scope targets are dropped by the ScopeGuard and logged.

## `exhaust` is no longer purely passive by default
Because `exhaust` now releases ARP-discovered neighbors' leases before consuming the pool, it can
affect real hosts' current DHCP bindings even though the mode itself is documented as
non-destructive (it only ever *sends* the RELEASE most servers legitimately honour only from the
lease holder). Whether this actually disrupts anyone depends on whether the server accepts an
unauthenticated RELEASE from a third party — that is itself reported as a finding
(`NEIGHBOR_LEASES_RELEASED`). Use `--no-release` if you want the older, strictly pool-only
behavior. **This same release phase now also feeds eviction (below)** — a released, re-acquired
address is exactly what eviction contests, so `--no-release` also has the effect of removing
eviction's targets for that run.

## Eviction is the biggest change in blast radius since the release phase
Both `exhaust` and `release` now run RFC 5227 ARP-conflict eviction against every address they
re-acquire: forged broadcast ARP claiming the *real owner's* address at a bogus MAC, repeated
across several rounds, specifically to move a still-connected host out of its "defend once"
phase and force it to give up an address it currently believes is its own — a DHCPDECLINE,
a restart at INIT, or (worst case) an APIPA fallback after DHCP repeatedly fails it. On
`release` in particular, this means the mode can knock a **currently active client** off its
address at the link layer, not just release a binding server-side — a materially bigger claim
than the mode's name suggests on its own. `--no-evict` turns this off on either mode.

**Statically addressed hosts are collateral, and they have no way back.** RFC 5227 address
conflict detection is a property of the IP stack, not of DHCP — a host with a static IP
configuration reacts to a forged conflict exactly like a DHCP client does, but it has no lease to
fall back on and no DHCP path to recover automatically. It needs manual intervention. DHCPig
cannot distinguish a statically addressed host from a DHCP client by ARP alone, so **eviction
targets are chosen without knowing which they are.**

**Recovery after a live eviction/`release` run is not optional.** `dhcpig release-previous`
frees the addresses this tool took, including everything re-acquired for eviction (re-acquired
addresses are journaled like any other lease — see RECOVERY) — evicted hosts then recover on
their own next DISCOVER retry. Run it as a deliberate cleanup step, the same as `restore`.

## No authorization gate
`release` is **not** gated behind an authorization attestation or a confirmation prompt, and
`--scope` is optional — with none given it targets the interface's own network. `dhcpig release
eth0` will therefore attempt to release, re-acquire, and ARP-conflict-evict every host on that
segment, with no further prompt — see "Eviction is the biggest change in blast radius" above for
what that actually does to a currently connected client. Treat mode selection itself as the
point of no return, and prefer `--dry-run` first and an explicit `--scope` in production.
`Mode.GARP_DOS` (a standalone, non-DHCP-aware ARP flood) was retired — this section used to also
cover it; there is now exactly one destructive mode, and its blast radius grew rather than
shrank when eviction was added, so don't read the retirement as a reduction in what needs care
here.

## Leaving the network as you found it
Because leases are now retained by default, **an exhaust run leaves the pool consumed until you
restore it.** That is deliberate — it is what lets you confirm the impact — but it means the
operator owns the cleanup step. `dhcpig restore <iface>` releases exactly the leases that run
acquired. `dhcpig release-previous <iface>` covers the case `restore` can't: the process was
killed, the box rebooted, or you're recovering from a different machine entirely — see below.

## The lease journal is data about a customer's network, on your disk
Every lease `exhaust` acquires is recorded to an append-only journal the moment the ACK lands —
that's what lets `release-previous` recover a drained pool after this process is long gone. It
is **on by default** (`--no-journal` to opt out, though the tool's ability to clean up after
itself depends on it existing).

The journal is engagement data: which addresses were taken on which network, when, via which
server. It lives at `$XDG_STATE_HOME/dhcpig/leases-<iface>.jsonl`, falling back to
`~/.local/state/dhcpig/` — deliberately **not** under `/var/lib` or any other system-owned path,
so it stays out of anything a package manager might also claim and is obviously yours to manage.
It has a `--max-age` (default 7 days) that makes `release-previous` *ignore* old entries, but the
tool never deletes the file itself — that's on the operator, same as any other engagement
artifact. Delete it when you're done with a customer's network:

    rm -rf ~/.local/state/dhcpig/

`release-previous` releases only what the journal proves this tool acquired — it adds no
capability beyond what `exhaust`/`release` already used. It is not gated behind the
destructive-mode handling `release` gets, because it can't expand a run's blast radius: worst
case, it re-sends a RELEASE for an address that's already free, which is a no-op.

## Reporting a vulnerability
Please open a GitHub issue for non-sensitive bugs. For sensitive reports, contact the
maintainer privately before public disclosure.
