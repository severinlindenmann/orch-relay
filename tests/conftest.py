"""Test-wide settings. The Drop routes (P3-D39) are off by default in production (review F1,
ORCH_RELAY_DROP); the suite runs with them on, and tests/test_drop_authz.py checks the off state."""

import os

os.environ.setdefault("ORCH_RELAY_DROP", "1")
