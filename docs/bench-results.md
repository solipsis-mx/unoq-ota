# Bench results

Measured on a real UNO Q, 2026-09-04. Board reached over adb; everything below
ran on the board itself.

## The full cycle works

| Step | Result |
|---|---|
| Read `user_sketch` over SWD | works |
| Erase + write + `verify_image` | works |
| Reboot into new firmware | works, confirmed by its own output |
| Roll back to the previous image | works, confirmed by its output |

Sequence run: dump the resident sketch → flash it back unchanged (verify
byte-identical) → flash a different sketch → observe the new firmware
reporting → flash the original back → observe the original reporting again.

## Numbers

| | |
|---|---|
| Full erase + write + verify, 79 KB | **~7.5 s** |
| Read 79 KB over bit-banged SWD | ~6 s (≈13 KB/s) |
| Typical sketch size | 70–80 KB (of a 768 KB partition) |

The ~7.5 s figure is the window in which a power loss leaves the MCU running
nothing. It is short enough that a supply-stability `Gate` is a realistic
defence.

## Privileges

**No root required for flashing.** OpenOCD drove SWD as the ordinary `arduino`
user — membership in the `gpiod` group is sufficient.

`systemctl` operations (stopping `arduino-router`) do need root, so the agent
should run as a systemd unit rather than shell out to `sudo`.

Stopping `arduino-router` turned out **not** to be necessary for the flash
itself in these runs. It remains advisable: that unit toggles GPIO 38 — the SWD
reset line — in its `ExecStopPost`, and is `Restart=always`, so a restart
landing mid-erase would assert reset on the target.

## Artifact integrity: a stronger check than the magic number

Sketch artifacts are ELF files with the sketch header packed into the unused
`e_ident` padding (bytes 7–14) — which is why the header sits at the odd
offset 7. Two artifacts checked (one dumped off a board, one freshly compiled)
both satisfy:

```
e_shoff + e_shnum * e_shentsize  ==  header.len  ==  file size
```

Verify this before flashing. The magic number alone only proves the first 16
bytes arrived; this proves the *whole file* did. It is the only practical
defence against a valid header over a truncated body — the failure that leaves
the loader idle and silent with nothing to report.

Observed `flags` on normally-built sketches: `0x00`. The `WAIT_FOR_APP` bit
(0x08), which would make the loader block forever on a magic value nothing
writes, is not set by default builds.

## Core version skew is tolerable (one data point)

An artifact built with core **0.56.0** loaded and ran correctly on a board
whose installed core was **1.0.0**. Worth knowing, not worth relying on — the
manifest still carries `core_version`.

## Watch out: observing the MCU changes its behaviour

Two related traps cost real debugging time here.

**1. Output is dropped unless a monitor is attached.** With no monitor, the
sketch's serial output goes to `arduino-router`, which tries to parse it as its
packet protocol and fills the journal with:

```
ERROR Error in connection err="invalid packet, expected array, got: int8"
```

**2. Piping the monitor through another command can swallow everything.**

```bash
timeout 12 arduino-app-cli monitor | head -20     # produced nothing
timeout 12 arduino-app-cli monitor > /tmp/mon.log # worked
```

The first form looks exactly like "the firmware isn't running." Always capture
to a file.

**Consequence for the design:** a health check based on plain `Serial.print`
must hold a monitor connection open to see anything, which competes with other
monitor users and changes what the board does. For production use, report
health over the router's packet protocol instead of raw serial. The example
sketch uses raw serial for clarity; it is not the right choice for a device
you cannot reach.
