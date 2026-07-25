"""Opt-in physical USB hardware efficacy lane.

The first hardware milestone is the collection/configuration gate. Device
mutation and payload oracles land behind this marker in later plan steps.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.hardware


def test_hardware_profiles_are_explicitly_configured(hardware_profiles):
    assert hardware_profiles, "--run-hardware requires at least one safe profile"
