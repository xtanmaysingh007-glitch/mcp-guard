"""--freeze-clock for AgentDojo runs (benchmark only: the guard and the proxy never import this).

AgentDojo stamps some NEWLY created objects with the real time, datetime.now(), and the model reads those
stamps. Two identical runs then differ (F8, 2026-11-10: the one log that still differed split right after an
email timestamp). AgentDojo 0.1.35 does this in exactly four places, all in the workspace suite:
    email_client.send_email         timestamp of the email it sends
    cloud_drive_client.create_file  last_modified of the new file
    cloud_drive_client.append_to_file  last_modified of the file it changes
    types.Email                     default timestamp (only used when an email has none; the suite's
                                    own emails all have one)
Calendar events take their times from the call's arguments, and slack, banking and travel have no wall-clock
stamps at all.

freeze_clock() swaps datetime.now() in those modules for a deterministic clock: it starts at FROZEN_START and
ticks 1 second per stamp, and reset_clock() (called at the start of every task, see ResetClock in
agentdojo_adapter.py) starts it over. FROZEN_START is later than every date in the suites' data, like the real
clock, so "a new email is the newest" and "an appended file got a newer last_modified" stay true (the one
scoring check that reads a stamp, check_added_to_file, needs the latter; tests/test_freeze_clock.py runs every
task's ground truth both ways). The environment's current day and all pre-existing data are not touched.
"""
from __future__ import annotations

import datetime
import re
import types
from pathlib import Path

from agentdojo.default_suites.v1.tools import cloud_drive_client, email_client
from agentdojo.default_suites.v1.tools.types import Email

FROZEN_START = datetime.datetime(2025, 1, 1, 0, 0, 0)

_ticks = 0
_frozen = False
_REAL_EMAIL_DEFAULT = Email.model_fields["timestamp"].default_factory


def _next_stamp() -> datetime.datetime:
    global _ticks
    stamp = FROZEN_START + datetime.timedelta(seconds=_ticks)
    _ticks += 1
    return stamp


class _FrozenDateTime(datetime.datetime):
    """datetime.datetime, except now() reads the frozen clock (returns a plain datetime)."""

    @classmethod
    def now(cls, tz=None):
        return _next_stamp()


# A stand-in for the `datetime` module inside the patched AgentDojo modules: everything is the real module,
# except datetime.datetime.now().
_frozen_module = types.SimpleNamespace(**{k: getattr(datetime, k) for k in dir(datetime) if not k.startswith("__")})
_frozen_module.datetime = _FrozenDateTime


def freeze_clock() -> None:
    global _frozen
    email_client.datetime = _frozen_module
    cloud_drive_client.datetime = _frozen_module
    Email.model_fields["timestamp"].default_factory = _next_stamp
    Email.model_rebuild(force=True)
    _frozen = True
    reset_clock()


def unfreeze_clock() -> None:
    global _frozen
    email_client.datetime = datetime
    cloud_drive_client.datetime = datetime
    Email.model_fields["timestamp"].default_factory = _REAL_EMAIL_DEFAULT
    Email.model_rebuild(force=True)
    _frozen = False


def reset_clock() -> None:
    """Start the frozen clock over (a no-op for the real clock)."""
    global _ticks
    _ticks = 0


def latest_data_timestamp() -> datetime.datetime:
    """The latest date/time anywhere in the bundled suites' data (for the FROZEN_START check)."""
    import agentdojo

    found = []
    for f in (Path(agentdojo.__file__).parent / "data" / "suites").rglob("*.yaml"):
        for m in re.findall(r"\b(\d{4}-\d\d-\d\d)(?:[ T](\d\d:\d\d(?::\d\d)?))?", f.read_text(encoding="utf-8")):
            day, t = m
            found.append(datetime.datetime.fromisoformat(f"{day} {t or '00:00'}"))
    return max(found)
