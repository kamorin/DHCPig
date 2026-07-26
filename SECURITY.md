# Security & Responsible Use

DHCPig is a whitehat validation tool. It must only be used on networks you own or are
explicitly authorized to test.

## Built-in guardrails
- Destructive modes (`release`, `garp`) require `--i-am-authorized` **and** `--scope`.
- A rate cap (`--rate`) bounds how fast any run can consume a pool.
- `--dry-run` builds and logs packets without sending anything.
- `exhaust` tracks every lease it acquires and can release exactly those, and only those.
  **Leases are kept by default** so the exhausted state can be verified; release them with
  `dhcpig restore <iface>` (or the Restore button), or run with `--restore-on-exit` to have
  the run clean up after itself automatically.
- Out-of-scope targets are dropped by the ScopeGuard and logged.

## Leaving the network as you found it
Because leases are now retained by default, **an exhaust run leaves the pool consumed until you
restore it.** That is deliberate — it is what lets you confirm the impact — but it means the
operator owns the cleanup step. `dhcpig restore <iface>` releases exactly the leases that run
acquired.

## Reporting a vulnerability
Please open a GitHub issue for non-sensitive bugs. For sensitive reports, contact the
maintainer privately before public disclosure.
