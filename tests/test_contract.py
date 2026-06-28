# Author: Tom Sapletta · https://tom.sapletta.com
# Part of the ifURI solution.
"""KSeF contracts cover the declarative runtime bindings without copying env variants."""
from __future__ import annotations

import json
from importlib.resources import files

import pytest

from urirun_connector_ksef import urirun_bindings

_uc = pytest.importorskip("urirun_contract")
_scaffold = pytest.importorskip("urirun_contract.contract_scaffold")
Contract = _uc.Contract
conform = _uc.conform


def _doc() -> dict:
    return json.loads(files("urirun_connector_ksef").joinpath("contracts.json").read_text())


def _contracts() -> dict:
    return {
        route: Contract(
            version=c["version"],
            effect=c["effect"],
            reversible=c["reversible"],
            inverse_route=c.get("inverseRoute", ""),
            inp=c["inp"],
            out=c["out"],
            errors=tuple(c["errors"]),
            examples=tuple(c["examples"]),
        )
        for route, c in _doc()["contracts"].items()
    }


def test_contract_conforms():
    conform(_contracts())


def test_every_runtime_binding_has_a_logical_contract():
    declared = set(_doc()["contracts"])
    actual = {_scaffold.route_key(uri) for uri in urirun_bindings()["bindings"]}

    assert len(urirun_bindings()["bindings"]) == 39
    assert actual == declared
