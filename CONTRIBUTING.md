# Contributing

Thanks for looking at this. The rules below are mostly one rule wearing
different hats: **this toolkit reads devices and never changes them**, and a
change that erodes that is the one kind of change that cannot be accepted.

## The line that does not move

There is no configuration commit path. `Driver.apply_config` raises
`WriteDisabled` and no driver overrides it. A pull request that adds one — a way
to push arbitrary config — however well guarded, is out of scope.

netauto does have exactly one device write: firmware upgrade, added deliberately
for driving real upgrades. It is the model for how any future write, if one is
ever justified, must look — never routed through the command guard, and gated
independently by `allow_writes` (off by default), a driver capability, and
confirmation by device name (`Driver.upgrade_firmware`). A write that cannot
clear that bar does not belong here. The read guard itself — `assert_read_only`
— is not negotiable: a "write" that widens it so a command slips through is the
one change that will always be refused.

Everything else is open, including the parts below that are deliberately hard
to change. Hard to change means "argue for it in the commit message", not "no".

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests/ -q
```

The suite needs no network devices and no credentials. If it needs either to
pass, that is the bug.

There is no linter, formatter or type checker configured, and no CI. Match the
surrounding code and run the tests yourself before committing; nothing else
will run them for you.

## Four boundaries a change has to respect

Each of these is a place where a well-meant edit quietly widens what the
toolkit can do. Changing one is fine. Changing one *without noticing* is what
the tests are there to prevent.

**The command guard** — `READ_ALLOW` and `DENY` in `netauto/drivers/base.py`.
Every command sent to a device passes `assert_read_only` first, keyed on the
platform family. Widening `READ_ALLOW` is a deliberate edit: say why in the
commit message, and add cases to `tests/test_guard.py` in both directions — one
that must be permitted, one that must be refused. Default deny is the point;
an unrecognised command is refused rather than forwarded.

**The write-route allowlist** — `ALLOWED_POST_ROUTES` in `tests/conftest.py`.
The GUI may expose a POST only if it changes something on the server, never on
a device. A new POST route fails the guard until it is listed there with a
reason. Adding the entry is the deliberate act; the guard is what makes it
deliberate.

**The ad-hoc target gate** — `netauto/adhoc.py`. Connecting to a host that is
not in the inventory makes the server offer its stored credentials to whatever
answers. A target must be an address this process found in a sweep within the
hour, and must not be routable on the internet. If you are tempted to relax
either half for convenience, that is the moment to open an issue instead.

**Credentials** — resolved from the environment at connect time via a prefix
named in the inventory. They never enter the inventory file, the activity log,
a rendered page, a URL or a tool's return value. `tests/test_web.py` and
`tests/test_mcp.py` both assert a password never appears in output; keep that
true for anything you add.

## Adding things

**A platform driver.** Register it in `netauto/drivers/__init__.py` (`REGISTRY`
maps a platform string to a lazy loader) and implement the `Driver` contract in
`netauto/drivers/base.py`. Import the vendor SDK *inside* the driver module so
a missing optional dependency breaks only that platform. Declare `capabilities`
honestly — a cloud tenant with no CLI should say so and let callers report the
gap, rather than raise a generic failure.

**A compliance rule.** `netauto/checks/builtin.py` for the core set,
`netauto/checks/vendor.py` for the workflow set. Scope it to a platform family
so a Junos config is never judged by IOS syntax. Give it a `reference` naming
the guide it comes from — "enable BPDU guard" is an opinion until it cites
something, and that difference matters in front of a change board. Give it
`remediation` text: a finding with no remedy is a complaint. Then add a case to
`CASES` in `tests/test_vendor_rules.py`, which fires every rule in both
directions — a rule that cannot fail and a rule that cannot pass both look
healthy from the outside.

**An MCP tool or GUI page.** Read-only, attributable, and covered. Device-
touching actions are logged against the account that made them.

## Tests

Cover the boundary, not the getter. The command guard has the heaviest
coverage in the repo because it is the safety-critical part, including
chaining-escape attempts.

Write tests that fail for the right reason. A test whose stub controls the
answer proves nothing — if a fake driver returns what you told it to return,
you have tested the fake. Prefer the real thing where it is cheap: the port
prober is tested against real loopback sockets, not a mocked `connect()`.

Tests must not touch the network or the developer's LAN. Patch at the seam
instead — `netauto.web.app.connect`, `netauto.scan.arp_sweep` — and assert on
what was passed to it.

They must also pass on a clean checkout. `config.yaml` and
`inventory/devices.yaml` are gitignored, so a test that reads them passes on
the machine that has them and fails everywhere else — which is exactly what CI
caught the day it was added. A route that needs an inventory should be given
one: patch `netauto.web.app.load_context` to return a `Settings` and an
`Inventory` the test controls.

`tests/test_docs.py` holds the documentation to the code: it exists because a
grep documented in `INSTALL.md` matched no log entry ever, and read as "no
commands were run". If you document a command, a count or a table, consider
pinning it there.

## Documentation

README's **What is not verified** section is load-bearing. Most drivers have
never met real hardware, and the README says so plainly. If your change adds
something unverified, add it there; if you verify something against real gear,
move it out and say what you ran it against.

The test count appears in `README.md` and `INSTALL.md`. Update both.

Agent definitions in `agents/` are canonical, and `tests/test_agents.py` checks
that installed copies have not drifted. After editing one:

```bash
cp agents/*.md ~/Work/.claude/agents/
```

Keep the `tools:` line on a single line — the frontmatter parser drops
everything after a wrap, and the failure looks like a missing tool.

## Commit messages

Explain why, not what; the diff already says what. State what you verified and,
just as importantly, what you did not — "no workflow has run against real
equipment" is more useful to the next reader than silence. If you found a bug
while doing something else, say how you confirmed it was pre-existing.
