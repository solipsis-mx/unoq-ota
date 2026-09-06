# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue.

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability), or contact the administrators of
[solipsis-mx](https://github.com/solipsis-mx).

Include enough to reproduce: the version or commit, the command line, and
what you expected versus what happened. Do not attach private keys or a
device's `state.json`.

## In scope

This agent writes firmware onto a microcontroller. Reports that a device
can be made to:

- flash an image that failed signature, digest, or header checks
- skip sequence / anti-replay
- treat a silent MCU as healthy
- brick itself because boot recovery cannot run

are in scope.

## Out of scope

- Already having root (or write access to the keyring / `state.json`) on
  the Linux side. That *is* the trust boundary; anyone who can write the
  trusted public keys owns the MCU. The [README](README.md#security) says so.
- Issues in OpenOCD, the Arduino core, or Zephyr themselves.
- Denial of service by serving an unreachable `--manifest-url`. A dead
  source must not fail a flash or a rollback; it also need not make
  progress.

## Keys

Never commit a private key. Generate with `tools/keygen.py` and keep the
`.pem` on the signing machine. Devices receive only `<key_id>.public.b64`.
