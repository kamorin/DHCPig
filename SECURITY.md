# Security & Responsible Use

DHCPig is a whitehat validation tool. It must only be used on networks you own or are
explicitly authorized to test.

## Built-in guardrails
- `exhaust` paces itself with a windowed, adaptive handshake pipeline (starts small, grows on a
  clean ACK, halves on a NAK/timeout/duplicate offer) instead of a flat rate cap — see the
  README's EXHAUST PIPELINE section. `release`, `garp`, and `active-scan` still take a rate cap
  (`--rate`, default 7 pps) bounding how fast they emit RELEASE/ARP/INFORM traffic.
  `release-previous` also takes `--rate` but defaults to 50 pps — its frames are unicast to a
  single server, not sprayed at the segment, and it runs during an outage the operator is
  actively trying to end.
- `exhaust` also **halts sending immediately** if a defensive control fires mid-run (a NAK
  burst, the link going down, a timeout storm, or a duplicate-offer pattern) — it doesn't try to
  push through a control that's already working. Leases already acquired are kept (not
  released) so the post-run report is still meaningful; see "Leaving the network as you found
  it" below.
- `exhaust` also runs a release phase before consuming addresses, sending DHCPRELEASE for
  ARP-discovered neighbors (`--no-release` to skip). This is itself a probe of whether the
  server honours unauthenticated RELEASE from a third party — see `NEIGHBOR_LEASES_RELEASED` in
  the findings output.
- `--scope CIDR` bounds which addresses a run may target; out-of-scope targets are dropped.
- `--dry-run` builds and logs packets without sending anything.
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
behavior.

## No authorization gate
`release` and `garp` are **not** gated behind an authorization attestation or a confirmation
prompt, and `--scope` is optional — with none given they target the interface's own network.
`dhcpig garp eth0` will therefore attempt to knock every host on that segment offline, with no
further prompt. Treat mode selection itself as the point of no return, and prefer `--dry-run`
first and an explicit `--scope` in production.

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
capability beyond what `exhaust` already used. It is not gated behind the destructive-mode
handling `release`/`garp` get, because it can't expand a run's blast radius: worst case, it
re-sends a RELEASE for an address that's already free, which is a no-op.

## Reporting a vulnerability
Please open a GitHub issue for non-sensitive bugs. For sensitive reports, contact the
maintainer privately before public disclosure.
