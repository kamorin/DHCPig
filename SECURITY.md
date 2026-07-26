# Security & Responsible Use

DHCPig is a whitehat validation tool. It must only be used on networks you own or are
explicitly authorized to test.

## Built-in guardrails
- Destructive modes (`release`, `garp`) require `--i-am-authorized` **and** `--scope`.
- A rate cap (`--rate`) and `--max-leases` bound the impact of any run.
- `--dry-run` builds and logs packets without sending anything.
- `exhaust` auto-releases the leases it acquired on exit (`restore`), unless `--no-restore`.
- Out-of-scope targets are dropped by the ScopeGuard and logged.

## Reporting a vulnerability
Please open a GitHub issue for non-sensitive bugs. For sensitive reports, contact the
maintainer privately before public disclosure.
