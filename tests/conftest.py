"""Shared fixtures."""

from __future__ import annotations

import sys
import types

import pytest


class FakeKeyring(types.ModuleType):
    """In-memory stand-in for the ``keyring`` module."""

    def __init__(self):
        super().__init__("keyring")
        self.items = {}

    def set_password(self, service, user, value):
        self.items[(service, user)] = value

    def get_password(self, service, user):
        return self.items.get((service, user))

    def delete_password(self, service, user):
        self.items.pop((service, user), None)


@pytest.fixture
def keyring(monkeypatch):
    kr = FakeKeyring()
    monkeypatch.setitem(sys.modules, "keyring", kr)
    return kr
