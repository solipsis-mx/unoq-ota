# unoq-ota

Over-the-air firmware updates for the Arduino UNO Q's STM32, driven from the
board's own Linux side. No programmer, no USB cable, nobody standing next to
the board.

> Sketch OTA, boot recovery, and optional host-file payloads are implemented.
> AWS IoT Jobs is designed as an `UpdateSource` extra and is **not shipped**.
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

- Fetches a signed manifest over HTTP (or from a local directory). The same
  pull works on Wi-Fi or any other Linux IP bearer.
- Verifies signature, digest, board compatibility, and the sketch header
  **before** the MCU is touched at all.
- Flashes only the sketch partition, locally over SWD — the network is never in
  the loop during the write.
- Optionally unpacks a signed `host_payload` tarball into a directory you
  choose (`--host-dir`) and restarts a systemd unit you name (`--host-unit`).
  MCU and host are one transaction: if either side fails health, both roll back.
  Omit `host_payload` and the update is MCU-only.
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
  sources/        local, http_manifest
  gates/          always  (write your own)
  health/         version_report
tools/            keygen, sign-artifact
systemd/          unit files
```

## Security

Artifacts are signed with ed25519 and verified against a keyring on the device.
**No keys of any kind are committed to this repository** — generate your own
with `tools/keygen.py`.

Be aware of what this software is: an agent that writes arbitrary code into a
microcontroller, whose trust root is a file on a writable filesystem. Anyone
who can write that file owns the MCU.

## License

MIT — see [LICENSE](LICENSE).
