"""The default gate: flash whenever an update is ready.

Correct for a device on a bench. Wrong for anything battery-powered, where
the erase window is what a brownout interrupts -- see DESIGN.md.
"""

from __future__ import annotations


class AlwaysGate:
    def may_flash(self):
        return True, "always allowed"
