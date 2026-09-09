# Contributing

Thanks for wanting to work on this. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
first.

This is a public tool. The design target is *any* Arduino UNO Q that needs
unattended sketch OTA, not one deployment. If a need comes from a bench,
land it as a flag, an interface implementation, or a config value — not a
special case.

## What to read

- [DESIGN.md](DESIGN.md) before changing flash, recover, or verify behaviour.
- [README.md](README.md) for install and the operator path.
- [AUTHORS.md](AUTHORS.md) for who publishes this and who the co-collaborators are.

`docs/plans/2026-09-04-ota-agent.md` is historical. Tasks 1–11 are done; do
not re-implement them.

## Development

Python **3.9** or newer. The board is 3.13; some machines that hack on this
are 3.9.6. Every module starts with `from __future__ import annotations`.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
python3 -m pytest tests/ -q
```

Behaviour changes: failing test first, in the style of the file you are
editing. `python3 -m pytest tests/ -q` should stay green.

Do not add markdown the pull request did not ask for. Agent handoff lives
in [CLAUDE.md](CLAUDE.md); keep project memory there rather than scattering
it.

## Pull requests

1. Branch from the default branch.
2. Keep the commit focused. Prefer the existing `feat` / `fix` / `docs`
   style: the *why* in the body, not a file list.
3. No secrets: no `*.pem`, no `.bench/`, no real device identifiers, no
   private keys. `tools/keygen.py` output stays on the build machine.
4. No names of internal products, fleets, vehicles, or organisations in
   code, tests, or comments. Generic language only.
5. Customisation belongs behind `UpdateSource`, `Gate`, and `HealthCheck`.
   Do not add a product-specific gate here. Product voltage/ignition policy
   stays out of this repo. `AlwaysGate` and `CellularSignalGate` (ModemManager
   + default-route probe) are the generic gates this repo ships.
6. Fill in the pull-request template. Say how you tested.

Cursor and Claude are co-collaborators on this project (see
[AUTHORS.md](AUTHORS.md)). AI-assisted patches are welcome on the same
terms as any other: they have to be reviewable, tested, and generic.

## Out of scope unless someone asks

AWS IoT Jobs, a custom `Gate`, an installer, Linux/rootfs OTA, and agent
self-update. Those are documented as non-goals, not missing features.

## Security reports

See [SECURITY.md](SECURITY.md). Do not open a public issue for a
vulnerability.
