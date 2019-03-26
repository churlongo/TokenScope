"""Line-oriented rendering of inspect, audit, and verify results.

Every function here returns a list of strings, one per output line, so results
diff cleanly in git and are trivial to test. No function reads the clock or the
environment; the reference time is passed in and echoed back so a report is
reproducible.
"""

from __future__ import annotations

import json

from .claims import Finding, present_claims
from .decode import DecodedToken
from .policy import Policy, describe
from .verify import Verdict
