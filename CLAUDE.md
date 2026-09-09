# unoq-ota — agent handoff

Pull-based OTA for the Arduino UNO Q: Linux flashes the STM32 over onboard
SWD (OpenOCD). **This repo is public.** No keys, no org/fleet/product names,
no deployment-specific telemetry. Integrators bring their own `Gate`, source,
and host files.

**Prime directive.** This tool exists to serve our own fleet, but it ships
publicly and must be general enough for anyone to use. Every feature lands as
a generic, configurable mechanism — a flag, an interface implementation, a
config value — with our fleet as one example among others. Never special-case
a deployment; if a need comes from the bench, build the general version of it.

Read `DESIGN.md` before changing flash, recover, or verify behaviour.
`docs/plans/2026-09-04-ota-agent.md` is **historical** (Tasks 1–11 done).
Do not re-implement those tasks.

Machine-local bench facts (IPs, serial, keys, installed units) live in
`.claude.local.md` (gitignored). If that file is missing, treat the bench as
unknown.

## Status (2026-09-08)

| Area | State |
|------|--------|
| MCU signed HTTP/local OTA | Implemented; Wi-Fi pull proven on hardware |
| S3 source (`--source s3`) | Implemented; mints GET URLs at fetch time. Not yet hardware-proven |
| systemd poller | Bench-proven: stock unit + drop-in, unattended coupled cycles, replay refusal |
| Daily verify-only timer | `unoq-ota.timer` + `--once --no-flash`; sequence watermark skip |
| AWS IoT Jobs poke | Shipped (`unoq-ota jobs`); MQTT `connect().result(timeout=30)` + `MQTT connected`; `ensure_plausible_clock` before connect so an epoch clock exits 1 for systemd restart |
| Router-stop guard | Bench-proven after the irreversible-stop fix; dependents restored |
| Boot reconciler | Implemented; mid-erase brick + **systemd** boot recovery proven |
| Optional `host_payload` | **Hardware-proven 2026-09-05**: coupled apply, and rollback of host tree + MCU on a forced host-health failure |
| Core-root override | `--core-root` / `UNOQ_OTA_CORE_ROOT`; bench-proven with `HOME=/root` |
| Journal + `--report-url` | Implemented; `committed`, `rolled_back` and `rejected` POSTs all bench-proven |
| `AlwaysGate` / `CellularSignalGate` | Shipped gates (`--gate always` default; `cellular-signal` for MM+route fetch gating). Do not add a product-specific gate here |
| Agent self-update / rootfs / Zephyr core | Out of scope forever as currently designed |

385 tests passing (`python3 -m pytest tests/ -q`).

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
python3 -m pytest tests/ -q
python3 -m pytest tests/test_host.py tests/test_agent.py -q   # host-payload slice
tools/keygen.py --out-dir /path/to/keys                      # never commit output
tools/sign-artifact.py sketch.bin --version 1.0.0 --sequence 1 \
  --url https://example.com/sketch.bin --private-key /path/to/key.pem --key-id bench
# optional coupled host files:
#   --host-payload app.tar.gz --host-url https://example.com/app.tar.gz
python3 tools/bench-http.py                                  # serves .bench/ + POST /events
```

On a board (after install):

```bash
unoq-ota --state-dir /var/lib/unoq-ota target
unoq-ota --state-dir /var/lib/unoq-ota reconcile
unoq-ota --state-dir /var/lib/unoq-ota status --json
unoq-ota --state-dir /var/lib/unoq-ota run --once --source http \
  --manifest-url URL --keys-dir /etc/unoq-ota/keys \
  --report-url URL --device-id HOSTNAME \
  --host-dir /opt/my-app --host-unit my-app.service \
  --max-payload-bytes 4000000                         # host flags optional
```

`--core-root PATH` (or `UNOQ_OTA_CORE_ROOT`) applies to every subcommand
that touches flash: `target`, `backup`, `reconcile`, `run`.

## Architecture

```
unoq_ota/
  interfaces.py   UpdateSource, Gate, HealthCheck  (the only extension points)
  agent.py        crash-safe state machine; MCU then optional host as one txn
  reconciler.py   boot recovery; does not read state.json
  flasher.py      OpenOCD; offset from boards.txt, never hardcoded
  verify.py       ed25519, digest, sequence, optional host_payload.sha256
  host.py         tar.gz → --host-dir; no exec; no symlinks; one previous tree
  events.py       journal.ndjson + best-effort POST
  state.py        fsync + atomic rename; default /var/lib/unoq-ota
  health/version_report.py   TCP 127.0.0.1:7500, not arduino-app-cli monitor
  sources/        local, http_manifest, s3_presigned, reporting wrapper
  jobs_runner.py  IoT Jobs poke (verify-only; not an UpdateSource)
  gates/always.py
systemd/          reconcile (mandatory) + poller/timer/jobs (drop-in for flags)
tools/            keygen, sign-artifact, bench-http
```

Flash is a function, not a Protocol. Customisation belongs behind the three
interfaces, not a fork.

**MCU + host transaction:** stage both → flash MCU → health → apply host →
optional unit restart/is-active. Any failure rolls **host then MCU**. Omit
`host_payload` and the update is MCU-only. Never execute archive members.

## Public-repo rules

- No `*.pem`, keys, `.bench/`, or real device identifiers in git.
- No names of internal products, fleets, vehicles, or organisations in
  code, docs, tests, or comments.
- Generic language only: “battery-powered or vehicle-mounted”, not a
  specific platform.
- Fleet-driven needs ship as general features: configurable paths and flags,
  not hardcoded assumptions; behaviour behind `UpdateSource` / `Gate` /
  `HealthCheck`, not a fork or an `if` for one deployment.
- Manifest `version` must match the sketch’s `OTA_FW_VERSION` or post-flash
  health fails and the agent rolls back.

## Invariants (do not break)

- Python **3.9**: `from __future__ import annotations` at the top of every
  module. The board is 3.13; some dev machines are 3.9.6.
- Sketch offset comes from `~/.arduino15/.../boards.txt`
  (`unoq.upload.address`). Never hardcode. Never call
  `/opt/openocd/bin/arduino-flash.sh` (wrong board’s offset).
- Every OpenOCD script: TCL `catch` around flash ops, explicit `shutdown`,
  wall-clock timeout + SIGKILL.
- Artifact is valid only if `ver==1`, `magic==0x2341`, **and**
  `e_shoff + e_shnum*e_shentsize == header.len == filesize`. Reject
  `WAIT_FOR_APP` (0x08).
- Reconciler must keep working with missing/corrupt `state.json`.
- `source.report` / HTTP POST is best-effort: a dead URL must not fail a
  flash or a rollback.

## Gotchas

- **MCU has no self-recovery.** Mid-erase = silent chip until Linux
  reflashes. Safety is the reconciler, not the Zephyr loader.
- **`User=root` ⇒ `Path.home()` is `/root`.** The Zephyr core lives in the
  interactive user’s `~/.arduino15`. Use `--core-root` or
  `UNOQ_OTA_CORE_ROOT` (core dir, `.arduino15` dir, or the home that owns
  one). The stock unit still sets `HOME=/home/arduino` as an image default;
  never assume `/root/.arduino15`.
- Health is **TCP `127.0.0.1:7500`**. `arduino-app-cli monitor` accepts a
  connection and yields no sketch lines.
- `arduino-router` `ExecStopPost` toggles GPIO 38 (SWD reset) and is
  `Restart=always`. The agent stops it around flash; without root it logs
  and flashes anyway.
- **A plain `systemctl stop arduino-router` does not hold** on the stock
  image, even as root: `arduino-router-serial.service` has
  `Requires=arduino-router.service` **and** `Restart=always`, so the
  propagated stop restarts it, re-pulls the router, and cancels our stop job
  (`Job for arduino-router.service canceled.`). Fixed 2026-09-05 with
  `--job-mode=replace-irreversibly`, plus restoring the dependent services
  the stop takes down (discovered at runtime, never a hardcoded list).
  Bench-proven. Do not "simplify" either half back out.
- **A working router stop makes the health port refuse connections for a
  second or two after a flash.** `_collect_tcp` retries until the caller's
  deadline for exactly this reason; a single refused connect used to read as
  dead firmware and rolled back a healthy update on the bench.
- Compile sketches **on the board** (`arduino-cli` / core `arduino:zephyr:unoq`).
  Host-side compiles have failed on `Arduino_RouterBridge`.
- Stock systemd `ExecStart=/usr/local/bin/unoq-ota run` is incomplete.
  Operators must drop-in `--source`, `--keys-dir`, and `--manifest-url` or
  `--source-dir`.
- Disk-space preflight reserves `--max-payload-bytes` (default 4 MB, the
  same cap the download enforces) for a `host_payload`, on **both** the
  state dir and `--host-dir`. It never trusts the manifest’s declared size:
  an inflated one would defer forever without counting an attempt.
- **`jobs` MQTT clientId defaults to `{thing}-ota`.** It must differ from the
  telemetry connection's id or AWS IoT will kick one client when the other
  connects. `wait_mqtt_connected` bounds `connect().result` at 30s and logs
  `MQTT connected`; a hang with no timeout used to leave the unit `active`
  with no broker session. `ensure_plausible_clock` runs before that connect
  (`check_clock` year floor 2020); an epoch clock is `PreflightError` and
  `jobs` exits 1 so systemd can retry after NTP or last-known-time persist.

## Where to continue

Prefer generic mechanisms that any integrator can use. Do not special-case a
deployment.

1. **Rewire the bench poller to `--source s3`.** Sign the manifest with
   `s3://` artifact URLs, put GetObject credentials on the device (never a
   presigned URL in the unit file), confirm one cycle. Then re-run LTE-only
   (`wlan0` down) and a forced health-failure rollback over cellular.
2. Bench hygiene: the root poller owns `state.json`, so non-root runs now
   fail with a clear `StateError`. Decide whether the agent should chown or
   the operator should.
3. Do **not** add a custom `Gate`, an installer, or Linux/rootfs OTA unless
   explicitly asked.

Fixed 2026-09-05 alongside the above: `State.core_version` is now written on
every transition; an unreadable `state.json` raises `StateError` instead of
silently reporting a fresh device (which would have dropped the poison list
and the sequence); `sign-artifact.py` grew the `--out` it always referenced.

Done 2026-09-05: `--core-root` / `UNOQ_OTA_CORE_ROOT` (no more `HOME`-only
lookup) and host bytes in the disk preflight, with `--max-payload-bytes`
moving the fetch cap and the reserve together.

TDD for behaviour changes: failing test first. Match existing test style.
Do not add markdown the user did not ask for beyond this handoff.
