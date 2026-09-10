# unoq-ota

Over-the-air firmware updates for the Arduino UNO Q's STM32, driven from the
board's own Linux side. No programmer, no USB cable, nobody standing next to
the board.

> Sketch OTA, boot recovery, optional host-file payloads, daily verify-only
> checks, and AWS IoT Jobs as a poke trigger are implemented.
> See [DESIGN.md](DESIGN.md).

## Why this works

The UNO Q is two computers on one board — a Qualcomm SoC running Linux and an
STM32U585 running Zephyr — and the Linux side has **direct SWD access to the
STM32 over GPIO**. Arduino ships a full OpenOCD on the board to use it; that's
how the IDE's network upload and App Lab both flash your sketch.

So the board can already reflash its own microcontroller. What's missing is
something to decide *what* to flash and *when*, and to be trustworthy enough to
do it while the board sits somewhere inconvenient. That's this project.

## What it does

- Fetches a signed manifest over HTTP, from a local directory, or from S3
  (`--source s3`, `s3://bucket/key`). The S3 source mints a short-lived GET
  URL at fetch time so a unit file never holds an expiring presigned URL.
  The same pull works on Wi-Fi or any other Linux IP bearer.
- Verifies signature, digest, board compatibility, and the sketch header
  **before** the MCU is touched at all.
- Flashes only the sketch partition, locally over SWD — the network is never in
  the loop during the write. The offset comes from the Arduino core installed
  on the board, never a constant; point the agent at that installation with
  `--core-root` (or `UNOQ_OTA_CORE_ROOT`) when it is not under the running
  account's `$HOME` — which is exactly the case under `systemd`'s `User=root`.
- Optionally unpacks a signed `host_payload` tarball into a directory you
  choose (`--host-dir`) and restarts a systemd unit you name (`--host-unit`).
  MCU and host are one transaction: if either side fails health, both roll back.
  Omit `host_payload` and the update is MCU-only. `--max-payload-bytes` sets
  how large a download may be and how much room the disk preflight reserves
  for one; the 4 MB default is a guess about your application, not a limit of
  the format.
- Checks that the new firmware actually came up, and **rolls back if it
  didn't**.
- Recovers a device whose flash was interrupted by power loss, on the next
  Linux boot, without needing its own state to be intact.

## What you should know before using it

**The MCU cannot recover itself.** A corrupt or half-written sketch does not
fall back to anything — the board ends up running nothing at all. Recovery
works only because Linux holds the SWD lines and unconditionally tries again
at boot. The safety of this system is the reconciler, not the bootloader.
[DESIGN.md](DESIGN.md#safety-model) explains this in detail, and it's worth
reading before you trust it with a remote device.

**Your sketch needs a few lines added.** Health checking requires the firmware
to report a version and a heartbeat counter. There is deliberately no
"did any bytes move?" fallback — that check passes firmware that is completely
dead, which makes rollback unreachable.

**Unstable power needs a `Gate`.** The dangerous window is the erase. Ships
with `AlwaysGate` (bench). Implement `Gate` in your own code if the device
can lose supply mid-write.

## Not in scope

Updating the Zephyr core image, the Linux rootfs, or the agent itself. A
`host_payload` may replace files in one directory you control; it is not a
rootfs updater. Changes that need a Zephyr Kconfig or devicetree rebuild
cannot be delivered this way.

## Layout

```
unoq_ota/
  agent.py        state machine
  reconciler.py   unconditional boot-time recovery
  flasher.py      OpenOCD invocation, offset resolution, header validation
  verify.py       signature, digest, sequence
  state.py        crash-safe persistence
  host.py         optional host-tree swap + rollback
  sources/        local, http_manifest, s3_presigned
  gates/          always, cellular_signal  (write your own)
  health/         version_report
tools/            keygen, sign-artifact
systemd/          unit files
examples/         sketch health-report contract
```

## Requirements

- An Arduino UNO Q with the Zephyr core installed (`arduino:zephyr:unoq`).
- Python 3.9 or newer on the Linux side.
- OpenOCD as shipped on the board (the agent does not bundle it).
- Root on the board for the systemd units (they stop `arduino-router` around
  a flash so GPIO 38 stays still). Membership in `gpiod` is enough to *talk*
  to SWD; the router-stop guard needs `systemctl`.

Compile sketches **on the board**. Host-side compiles have failed on
`Arduino_RouterBridge`.

## Install

On a development machine, or on the board:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'   # drop [dev] on a device
# S3 source (optional):  .venv/bin/pip install -e '.[s3]'
```

That provides the `unoq-ota` console script. A device install typically
symlinks it to `/usr/local/bin/unoq-ota`. The stock `unoq-ota.service` is
a long-running poller (`Type=simple`, `Restart=always`). Copying it with
`unoq-ota.timer` is not a daily verify-only install: the timer is unusable
until a drop-in sets `Type=oneshot`, clears `Restart=`, and adds
`--once --no-flash`. Enable the timer; do not enable the long-running
service alongside it. See [systemd](#systemd).

## Sketch contract

Health checking requires the firmware to print a version and a heartbeat.
Copy the few lines in [`examples/ota_health_report/ota_health_report.ino`](examples/ota_health_report/ota_health_report.ino)
into your sketch. The version string in the sketch (`OTA_FW_VERSION`) **must
match** the manifest's `version`, or post-flash health fails and the agent
rolls back.

Reports go out as `OTA-HEALTH <version> seq=<n>` on Serial. The agent
collects them from TCP `127.0.0.1:7500` (the router packet path), not from
`arduino-app-cli monitor`.

## Keys and signing

The private key never goes on a device.

### PEM key mode

```bash
tools/keygen.py --key-id bench --out-dir /path/to/keys
# copies to the device:  /etc/unoq-ota/keys/bench.public.b64
# stays on the signer:   /path/to/keys/bench.private.pem

tools/sign-artifact.py sketch.bin --version 1.0.0 --sequence 1 \
  --url https://example.com/sketch.bin \
  --private-key /path/to/keys/bench.private.pem --key-id bench \
  --out manifest.json
# optional coupled host files:
#   --host-payload app.tar.gz --host-url https://example.com/app.tar.gz
```

### AWS KMS mode

```bash
tools/sign-artifact.py sketch.bin --version 1.0.0 --sequence 1 \
  --url s3://your-bucket/releases/v1.0.0/artifact.bin \
  --kms-key-id alias/your-ota-signing-key --kms-region us-east-2 \
  --key-id kms-2026 --out manifest.json
# requires: pip install 'unoq-ota[s3]'  (botocore)
# requires: AWS credentials in the standard chain with kms:Sign on that key
```

`--out` writes the manifest to a file. Without it, the JSON goes to stdout
and progress goes to stderr, so `sign-artifact.py ... > manifest.json` still
produces a valid document.

`tools/bench-http.py` serves a directory and accepts `POST /events`, so a
bench can exercise the whole pull path without a cloud account.

## Running on a board

```bash
unoq-ota --state-dir /var/lib/unoq-ota target
unoq-ota --state-dir /var/lib/unoq-ota reconcile
unoq-ota --state-dir /var/lib/unoq-ota status --json
unoq-ota --state-dir /var/lib/unoq-ota run --once --source http \
  --manifest-url URL --keys-dir /etc/unoq-ota/keys \
  --report-url URL --device-id HOSTNAME \
  --host-dir /opt/my-app --host-unit my-app.service \
  --max-payload-bytes 4000000
```

`--core-root PATH` (or `UNOQ_OTA_CORE_ROOT`) applies to every subcommand
that touches flash: `target`, `backup`, `reconcile`, `run`. It accepts the
core directory, an `.arduino15` directory, or the home directory that owns
one. Under `User=root`, `$HOME` is `/root` and the core is usually not there.

`--host-dir` / `--host-unit` are optional. Omit `host_payload` from the
manifest and the update is MCU-only.

## systemd

Units and a timer ship in [`systemd/`](systemd/):

- `unoq-ota-reconcile.service` — oneshot at boot. Enable it. It does not
  need extra flags beyond `UNOQ_OTA_CORE_ROOT` if the core is not under
  `HOME`.
- `unoq-ota.service` — the poller. The stock `ExecStart=/usr/local/bin/unoq-ota run`
  is incomplete on purpose: `--source`, `--keys-dir`, and `--manifest-url`
  (or `--source-dir`) have no site-wide default. Stock `Restart=always`
  stays for benches. Add a drop-in:

```bash
sudo systemctl edit unoq-ota.service
```

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/unoq-ota run --source http \
  --manifest-url https://example.com/manifest.json \
  --keys-dir /etc/unoq-ota/keys
```

For a private S3 bucket, install the extra (`pip install 'unoq-ota[s3]'`)
and point at the object identity. Credentials come from the standard AWS
chain (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, a shared config file,
or an instance role) — never from a URL in the unit file:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/unoq-ota run --source s3 \
  --manifest-url s3://my-bucket/manifest.json \
  --keys-dir /etc/unoq-ota/keys
```

Sign the manifest with `--url s3://my-bucket/artifact.bin` (and
`--host-url s3://...` when there is a host payload) so artifact fetches
mint URLs the same way. A leftover https presigned URL in `--manifest-url`
is rejected at startup.

- `unoq-ota.timer` — daily check at 03:00 America/Mexico_City
  (`Persistent=true`, `RandomizedDelaySec=900`). The timer is unusable
  until a drop-in sets `Type=oneshot`, clears `Restart=`, and runs
  `--once --no-flash`. Enable the timer only; do not enable the long-running
  service alongside it. The stock unit stays `Type=simple` / `Restart=always`
  for benches that want a poller. The manifest is always fetched; artifact
  download and verify run only when the manifest sequence is newer than the
  last committed or verified sequence. Successful verify-only passes stamp
  `last_verified_*` and never flash. When the sequence is unchanged, leftover
  `staged.bin` / `staged-host.tar.gz` are unlinked so they cannot bait the
  boot reconciler, and artifact work is skipped (the manifest GET still runs).

```ini
[Service]
Type=oneshot
Restart=
ExecStart=
ExecStart=/usr/local/bin/unoq-ota run --source s3 --once --no-flash \
  --manifest-url s3://bucket/manifest.json \
  --keys-dir /etc/unoq-ota/keys
```

systemd without `Timezone=` should use `OnCalendar=*-*-* 09:00:00 UTC`.

- `unoq-ota-jobs.service` — long-running MQTT listener for IoT Jobs pokes.
  Each qualifying job (`{"operation": "check"}`) runs one verify-only cycle
  against the same `--source` / `--manifest-url` you configure in a drop-in
  (identical to the timer pattern above, but triggered on demand). Requires
  `pip install 'unoq-ota[aws]'`. IoT endpoint, cert, key, CA, and thing name
  come from flags or `/etc/unoq-ota/agent.env` (`UNOQ_OTA_IOT_*`). MQTT
  `clientId` defaults to `{thing}-ota` (`UNOQ_OTA_MQTT_CLIENT_ID`); **it must
  not equal the telemetry client's id** or the two connections will evict each
  other.

Optional environment in `/etc/unoq-ota/agent.env` (units already read it):
`UNOQ_OTA_REPORT_URL`, `UNOQ_OTA_DEVICE_ID`, `UNOQ_OTA_CORE_ROOT`, and the
`UNOQ_OTA_IOT_*` / `UNOQ_OTA_MQTT_CLIENT_ID` vars for the jobs unit.

## Security

Artifacts are signed with ed25519 and verified against a keyring on the device.
**No keys of any kind are committed to this repository** — generate your own
with `tools/keygen.py`.

Be aware of what this software is: an agent that writes arbitrary code into a
microcontroller, whose trust root is a file on a writable filesystem. Anyone
who can write that file owns the MCU.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Pull requests and issues are
welcome. Cursor and Claude are co-collaborators; see [AUTHORS.md](AUTHORS.md).

## License

GNU GPL version 3 or later — the same family Arduino uses for tools such as
[arduino-cli](https://github.com/arduino/arduino-cli). The [LICENSE](LICENSE)
file is the verbatim GPL-3.0 text (so GitHub and other scanners can identify
it). Copyright is in [NOTICE](NOTICE); machine-readable SPDX is in
[REUSE.toml](REUSE.toml) (`GPL-3.0-or-later`).

Arduino, Arduino UNO Q, and related names are trademarks of Arduino SA.
This project is not affiliated with Arduino.
