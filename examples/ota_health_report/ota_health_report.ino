// SPDX-FileCopyrightText: 2026 Solipsis MX and the unoq-ota contributors
// SPDX-License-Identifier: MIT
/*
 * unoq-ota — health report contract
 *
 * Add these few lines to your own sketch so the OTA agent can tell whether
 * the firmware it just flashed is actually alive.
 *
 * The agent asserts three things, and it needs all three:
 *
 *   1. IDENTITY  — the version reported matches the version just flashed.
 *                  Without this, an old image that survived a failed flash
 *                  looks exactly like a successful update.
 *   2. LIVENESS  — a report arrived at all.
 *   3. PROGRESS  — seq advances between reports. Without this, a firmware
 *                  wedged after its first line still reads as healthy.
 *
 * A check that merely asks "did any bytes arrive?" passes firmware that is
 * dead in every way that matters, and a health check that cannot fail makes
 * rollback unreachable. Hence the contract.
 *
 * Line format (whitespace-separated, parsed by health/version_report.py):
 *
 *     OTA-HEALTH <version> seq=<n>
 */

#define OTA_FW_VERSION "test-1.0.0"

static uint32_t ota_seq = 0;
static uint32_t last_report_ms = 0;

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.print("OTA-BOOT ");
  Serial.println(OTA_FW_VERSION);
}

void loop() {
  // Report on a timer rather than blocking, so this drops into an existing
  // loop() without changing its timing.
  uint32_t now = millis();
  if (now - last_report_ms >= 1000) {
    last_report_ms = now;
    Serial.print("OTA-HEALTH ");
    Serial.print(OTA_FW_VERSION);
    Serial.print(" seq=");
    Serial.println(ota_seq++);
  }

  // your sketch's work goes here
}
