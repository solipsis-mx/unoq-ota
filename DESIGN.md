# unoq-ota — design

Over-the-air firmware updates for the STM32U585 on an Arduino UNO Q, driven
from the board's own Linux side.

**Status:** sketch OTA, boot reconciler, optional host payloads, verify-only
checks (`--no-flash`), and AWS IoT Jobs as a poke trigger are implemented.
Manifests still come from `LocalFileSource` or `HttpManifestSource` — Jobs
does not replace those.

## The idea in one paragraph

The UNO Q is two computers on one board: a Qualcomm SoC running Linux, and an
STM32U585 running Zephyr. The interesting fact — the one this whole project
rests on — is that **the Linux side has direct SWD access to the STM32**, over
GPIO. Arduino ships a full OpenOCD on the board to use it. That means the
board can reflash its own microcontroller with no programmer, no USB cable, and
nobody standing next to it. All that's missing is something to decide *what* to
flash and *when*, and to be trustworthy enough to do it unattended. That's this
project.

## Verified mechanism

OpenOCD lives at `/opt/openocd`, configured by `openocd_gpiod.cfg`:

```
adapter driver linuxgpiod
adapter gpio srst  38 -chip 1
adapter gpio swclk 26 -chip 1
adapter gpio swdio 25 -chip 1
transport select swd
source [find stm32u5x.cfg]
```

`/usr/local/bin/arduino-flash`, Arduino's `remoteocd` uploader, and the App Lab
orchestrator are all clients of this same local OpenOCD.

### Flash layout

```
0x08000000  ┌────────────────────────────┐
            │ Zephyr loader (linked here, │  the core image; spans into
            │ spans ~0x08037500)          │  the image-0 region below
0x08010000  │ image-0                     │ 768K
0x080D0000  │ bootanimation               │ 192K
0x08100000  │ user_sketch                 │ 768K   ← what we update
0x081C0000  │ storage                     │ 256K
```

There is **no separate bootloader**. The Zephyr loader is linked at
`0x08000000` (`CONFIG_FLASH_LOAD_OFFSET=0`) and occupies the start of flash
through part of `image-0`. Do not do offset arithmetic assuming a bootloader
sits below it.

### Getting the sketch offset right

Do **not** hardcode it, and do **not** use `/opt/openocd/bin/arduino-flash.sh`
— that script hardcodes `0x80F0000`, which is a *different Arduino board's*
offset and is wrong for the UNO Q. Nothing in the real upload path calls it.

Read the offset from the Arduino core installed on the board:

```
~/.arduino15/packages/arduino/hardware/zephyr/<version>/boards.txt
    unoq.upload.address=0x08100000
    unoq.upload.maximum_size=786432
```

This is the same source of truth the IDE uses, it requires no halt of the MCU,
and it stays correct across core upgrades.

Which `~` that is matters. Under `systemd` with `User=root`, `$HOME` is
`/root`, while the core is installed under whichever account ran
`arduino-cli core install`. So the search root is resolved per call, not at
import, and can be named explicitly with `--core-root` or
`UNOQ_OTA_CORE_ROOT` — as the core directory itself, as an `.arduino15`
directory, or as the home directory that owns one. A failure names every
path that was tried.

## Safety model

This is the most important section. Read it before trusting this software with
a device you can't physically reach.

### What the loader does with a bad sketch

The Zephyr loader reads a 16-byte header from the start of `user_sketch`:

| Offset | Field   | Required |
|--------|---------|----------|
| 0x07   | `ver`   | `0x01`   |
| 0x08   | `len`   | u32 length |
| 0x0C   | `magic` | `0x2341` |
| 0x0E   | `flags` | bitfield |

There are three distinct bad outcomes, and **none of them is a graceful
fallback**:

1. **Invalid header.** The loader logs `Invalid sketch header` and sets an
   internal `sketch_valid = false`. A source comment says it will "try to start
   a shell anyway" — but the shell is compiled out (`CONFIG_SHELL is not set`,
   and the USB-shell block is disabled on this board because it declares a
   router serial). There is no shell. Worse, the loader then reads `flags`
   anyway; on erased flash that's `0xFF`, which has the "wait for app" bit set,
   so it enters an unbounded sleep loop. **Result: MCU alive, running nothing,
   forever.**

2. **Valid header, corrupt or truncated body.** The loader XIPs the extension
   straight out of flash. Parsing fails, the load function returns an error,
   `main()` returns, and nothing else is running. **Result: MCU idle, silent.**
   This is exactly what an interrupted erase-and-program produces, because the
   header is written before the body.

3. **Statically-linked artifacts** jump to the image with no validation past
   the 16-byte header. A truncated one jumps into erased flash.

**Conclusion: the MCU has no self-recovery.** Any claim that a bad sketch
"can't brick the board" is false.

### What actually makes this safe

Recovery does not come from the MCU. It comes from the fact that **Linux holds
the SWD lines and can always reflash**. That is only true if something on Linux
unconditionally tries. So:

- **A boot-time reconciler runs on every Linux start, independent of the update
  state machine.** If the MCU produces no valid health signal within a timeout,
  it reflashes — current image, then previous, then a factory-golden image that
  is never overwritten. This, not the loader, is what makes bricking
  impossible. It must keep working even if the agent's own state file is
  missing, truncated, or corrupt.
- **The SWD write is local.** The artifact is fully downloaded and verified on
  disk before OpenOCD starts. A dropped network connection can never corrupt
  the MCU, because the network is not in the loop during the critical section.
- **We never write the core image.** Sketch-partition writes only. The core
  image *is* recoverable over the same SWD path, but leaving it alone shrinks
  the window where the device has no working loader at all.

### The dangerous window

`flash write_image erase` erases every sector the image covers before
programming any of it. From the first erased sector until the header lands,
a reset produces outcome (1) above. That window is seconds. On battery-powered
or vehicle installations, plan for brownouts inside it — an interrupted
program leaves flash in a state that can fault on read, not merely fail
cleanly.

Mitigations: a `Gate` that refuses to flash when supply is unstable, a
wall-clock timeout around OpenOCD, and the reconciler to clean up afterwards.

## Architecture

```
  boot ──► Reconciler ──────────────────────────► (unconditional recovery)
                │
                ▼
  ┌──────────────────────────────────────────┐
  │            Agent state machine            │
  │        (crash-safe, persisted)            │
  └──────────────────────────────────────────┘
     ▲            ▲             ▲          │
     │            │             │          ▼
 UpdateSource   Gate      HealthCheck    flash()
 (where from)  (when ok)  (did it work)  (OpenOCD/SWD)
```

Three interfaces. Flashing is a plain function, not an interface — there is
exactly one way to do it.

### `UpdateSource` — where updates come from

```python
class UpdateSource(Protocol):
    def check(self) -> Update | None: ...
    def report(self, update: Update, status: Status, detail: str) -> None: ...
```

Shipped:

- `LocalFileSource` — watches a directory. Development, testing, and
  air-gapped/manual deployments.
- `HttpManifestSource` — polls a manifest URL. Works with any static host:
  S3, GitHub Releases, a plain web server. **The default for most users.**
  Polls with jitter so a fleet doesn't update in lockstep.

Optional extra (`pip install unoq-ota[aws]`):

- **IoT Jobs poke** (`unoq-ota jobs`) — AWS IoT Jobs over MQTT as a
  **trigger**, not an `UpdateSource`. The manifest still comes from whichever
  `--source` you configure (local, http, or s3). When a job with
  `{"operation": "check"}` arrives, the agent runs one verify-only cycle
  (`--no-flash` is forced) against that source, then reports SUCCEEDED or
  FAILED to the job. Per-device targeting and rollout control live in Jobs;
  artifact delivery stays on HTTP/S3/local.

  CLI flags: `--iot-endpoint`, `--iot-cert`, `--iot-key`, `--iot-ca`,
  `--thing-name`, `--mqtt-client-id` (default `{thing}-ota`; also
  `UNOQ_OTA_IOT_*` / `UNOQ_OTA_MQTT_CLIENT_ID` env vars). All `--source`,
  `--keys-dir`, and `--manifest-url` flags from `run` apply.

### `Gate` — when flashing is permitted

```python
class Gate(Protocol):
    def may_flash(self) -> tuple[bool, str]: ...   # (allowed, reason)
```

Shipped: `AlwaysGate`. Everything else is deployment-specific and belongs in
your own code — the interface exists precisely so you don't have to fork this
repo to add one.

If your device is battery-powered or vehicle-mounted, **write a gate**. The
useful predicate is usually "supply voltage stable and expected to stay that
way for a minute," which is not the same as "idle." A device that looks idle
may be about to experience an engine crank.

The agent downloads, verifies, and stages regardless of the gate; only the
flash step blocks. A device can sit staged indefinitely.

### `HealthCheck` — did the new firmware actually come up

```python
class HealthCheck(Protocol):
    def wait_healthy(self, timeout_s: float) -> bool: ...
```

Shipped: `VersionReportHealthCheck`. Your sketch reports a version string and
a monotonically advancing counter over the bridge; the check asserts identity
*and* liveness *and* progress.

**There is deliberately no "any traffic" health check.** It is tempting and
nearly worthless: most sketches emit something on a timer regardless of whether
their actual work is functioning, so it passes firmware that is completely
dead in every way that matters. A health check that can't fail is worse than
none, because it makes rollback unreachable.

This does mean adopting `unoq-ota` requires a few lines in your sketch. That
trade is intentional.

## Coupled updates

MCU firmware is often version-locked to a host-side program — a Python service,
a data pipeline, anything that parses the MCU's output and expects a particular
message layout. Update one without the other and you get the worst kind of
failure: the flash succeeds, the firmware runs, health checks pass, and the
system is broken anyway because the two halves no longer agree.

So an update may optionally carry a **host payload** alongside the MCU
artifact. Both are applied as one transaction:

```
stage MCU artifact + host payload
        │
        ▼
flash MCU ──► swap host payload ──► restart host service
        │
        ▼
joint health check (MCU healthy AND host service healthy)
        │
   fail ├──► roll back BOTH ──► joint health check again
        │                              │
        │                         fail └──► escalate to golden
   pass ▼
     commit
```

If you don't need this, omit the host payload and the update is MCU-only.

## Update lifecycle

```
IDLE
  │ source.check() returns an Update
  ▼
DOWNLOADING ──── network failure ────► IDLE (backoff)
  │
  ▼
VERIFYING ─── bad signature / digest / header / target ───► REJECTED
  │                                            (poison this version, report)
  ▼
STAGED ────► gate.may_flash() false ──┐
  │  ◄───────────────────────────────┘  (report "waiting: <reason>")
  ▼
FLASHING
  │
  ▼
HEALTH_CHECK ── unhealthy ──► ROLLING_BACK ──► previous ──► healthy? ──► ROLLED_BACK
  │                                   │                        no
  ▼                                   └──────────► GOLDEN ─────┘
COMMITTED
```

Every version carries a persisted **attempt counter** (hard cap: 2) and lands
on a **poisoned list** when it fails. Without both, a firmware that reliably
fails its health check produces an infinite flash–rollback–reoffer loop that
keeps the device dead and burns flash endurance.

`ROLLED_BACK` is terminal for that version. The agent consults the poison list
locally before download, so this holds even if the server keeps advertising it.

### Verify-only checks (`--no-flash`)

`run --once --no-flash` and `jobs` download and verify a manifest but never
flash. On success the agent records `last_verified_sequence` (a watermark)
and reports `VERIFIED`. Subsequent cycles skip work when the manifest's
`sequence` is not newer than `max(sequence, last_verified_sequence)` — so a
daily timer or repeated job poke does not re-fetch an unchanged manifest.

Use this for unattended "is there an update?" checks without touching the MCU.

### On-disk state

```
/var/lib/unoq-ota/
  state.json      # state machine position, attempts, poisoned versions
  golden.bin      # provisioned once, never overwritten
  current.bin     # believed-resident image
  previous.bin    # rollback target
  staged.bin      # verified, awaiting gate
  ota.lock        # held across the flash step
  journal.ndjson  # append-only local record, survives loss of connectivity
```

`state.json` is written with `fsync` + atomic rename before every transition
that touches hardware. A disk-space precondition is checked before download;
the atomic-rename crash-safety story fails silently on a full filesystem.

**Drift is assumed, not excluded.** `current.bin` is a *belief*, and it is
wrong the moment anyone uses the IDE, App Lab, or a network upload. Before
flashing, the agent reads the resident header back over SWD; if it doesn't
match the belief, the device is re-baselined rather than rolled back to a
fiction.

## Flashing

```
openocd -d2 -s /opt/openocd -f openocd_gpiod.cfg -c "<script>"
```

with the script wrapping every flash operation in `catch` and ending in an
explicit `exit`. This matters: if a flash command throws and the script aborts
before `shutdown`, OpenOCD falls through to its **server loop** and sits
holding the SWD lines and your lock indefinitely. Arduino's own scripts use
`catch` for exactly this reason.

Also required:

- **A wall-clock timeout and SIGKILL.** `stm32u5x.cfg`'s clock configuration
  contains unbounded spin loops that never terminate on an undervolted target.
- **Post-write `verify_image`.** Note what this does and does not prove: it
  compares bytes at the offset you gave it. It cannot detect a *wrong* offset
  — a sketch written to the wrong address verifies perfectly against that
  wrong address — and it says nothing about whether the image will load.
- **File-side header validation before touching the MCU**, so a wrong-board
  artifact or an HTML error page saved as a `.bin` is caught on disk.
- **Reject `flags` bits we can't support**: the "wait for app" bit (0x08) makes
  the loader block on a magic value in backup SRAM that nothing writes outside
  an IDE upload, so such an artifact hangs on every boot.

### Contending with the rest of the board

Other software on a stock UNO Q also drives this hardware, and none of it knows
about you:

- `arduino-app-cli` and the Arduino cloud connector run by default and can
  flash the same target. Advisory locks don't bind them; the real mutexes are
  OpenOCD's port bind and the gpiod line request, which fail at an
  unpredictable moment — possibly mid-erase.
- **`arduino-router`'s systemd unit toggles GPIO 38 on stop — that is the SWD
  reset line.** The unit is `Restart=always`. If it restarts while you are
  erasing, systemd asserts reset on your target.

The agent therefore stops `arduino-router` for the duration of the flash and
restores it afterwards, and takes the lock before doing so.

## Manifest

```json
{
  "schema": 1,
  "version": "1.4.0",
  "sequence": 42,
  "artifact": { "url": "...", "size": 198432, "sha256": "9f2c..." },
  "host_payload": { "url": "...", "size": 40211, "sha256": "1ab3..." },
  "target": {
    "board": "arduino_uno_q",
    "link_mode": "dynamic",
    "sketch_offset": "0x08100000",
    "partition_size": 786432
  },
  "not_before": "2026-09-01T00:00:00Z",
  "expires":    "2026-12-01T00:00:00Z",
  "signature": { "alg": "ed25519", "key_id": "...", "sig": "base64..." }
}
```

- **Signed** with ed25519 over the canonical serialisation minus the signature
  block. Verification is fail-closed and ordered: signature → validity window →
  target compatibility → download → size → digest → header flags.
- **`sequence` is a monotonic counter enforced on-device.** Without it, a
  correctly-signed *old* manifest can be replayed to push known-bad firmware.
  Downgrades require an explicitly signed override.
- **Trust is a keyring, not a key.** Ship N public keys with overlap so you can
  rotate without physically visiting devices — otherwise rotation costs exactly
  what this project exists to avoid. Key-set updates are themselves signed.
- **No keys, public or private, are committed to this repository.**
  `tools/keygen.py` generates your own; the public key path is configuration.

### Clocks

Signature validity windows and HTTPS certificate validation both need a
plausible clock, and boards with cellular modems frequently start at an epoch
default until they get time from the network. The agent checks for a sane clock
before verification and defers rather than failing the update.

## Failure modes

| Failure | Outcome | Recovery |
|---|---|---|
| Network drops mid-download | `DOWNLOADING` | Retry with backoff; MCU untouched |
| Corrupt / tampered artifact | Caught in `VERIFYING` | `REJECTED` + poisoned; MCU untouched |
| Wrong-board or bad-flags artifact | Caught on disk | Never reaches the MCU |
| Replayed old manifest | Rejected by `sequence` | Reported |
| Power loss mid-erase or mid-program | MCU runs nothing | **Reconciler** reflashes on next Linux boot |
| Agent crashed / state file corrupt | MCU may be dead | **Reconciler** — it does not read agent state |
| New firmware unhealthy | Health check fails | Auto-rollback, then golden |
| Rollback also unhealthy | Escalation | Golden image |
| Repeated failures | Attempt cap + poison list | Stops trying, reports, stays on last good |
| Concurrent flash by other Arduino tooling | Lock + router stop | Abort if lock unavailable |
| Disk full | Precondition check | Refuse to start an update |

## Deliberate non-goals

- **Updating the Zephyr core image.** Possible over the same SWD path, but a
  failure there removes the loader itself. Deferred until the sketch path has
  field history. Note the consequence: anything requiring a Zephyr Kconfig or
  devicetree change (power-management modes, new drivers, different partition
  layouts) **cannot** be delivered by this tool as scoped.
- **Updating Linux, the agent itself, or the modem stack.** The MCU is
  recoverable from Linux; Linux is recoverable from nowhere. Treat the Linux
  side as the trusted root and update it by other means.
- **A/B slots.** There is one `user_sketch` partition. Rollback is a second
  flash, not a pointer swap.

## Testing

- **Unit:** every state transition including crash-resume at each point;
  signature/digest/sequence rejection with known-bad inputs; header validation
  against truncated, wrong-board, and bad-flag artifacts.
- **Integration, no hardware:** `LocalFileSource` + fake flasher, driving
  IDLE→COMMITTED, a full rollback, a golden escalation, and a poison-list loop
  that must terminate.
- **Bench, with hardware:** flash a good sketch and confirm it runs; flash a
  deliberately broken one and confirm the health check fails and rollback
  restores it; **pull power mid-erase and confirm the reconciler recovers it.**
  That last one is the test that decides whether this is safe to deploy.
