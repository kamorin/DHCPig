# Security & Responsible Use

DHCPig is a whitehat validation tool. It must only be used on networks you own or are
explicitly authorized to test.

## Built-in guardrails
- A rate cap (`--rate`, default 10 pps) bounds how fast any run can consume a pool or emit ARP.
- `--scope CIDR` bounds which addresses a run may target; out-of-scope targets are dropped.
- `--dry-run` builds and logs packets without sending anything.
- `exhaust` tracks every lease it acquires and can release exactly those, and only those.
  **Leases are kept by default** so the exhausted state can be verified; release them with
  `dhcpig restore <iface>` (or the Restore button), or run with `--restore-on-exit` to have
  the run clean up after itself automatically.
- Out-of-scope targets are dropped by the ScopeGuard and logged.

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
acquired.

## Reporting a vulnerability
Please open a GitHub issue for non-sensitive bugs. For sensitive reports, contact the
maintainer privately before public disclosure.
