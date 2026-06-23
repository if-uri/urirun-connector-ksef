# Author: Tom Sapletta · https://tom.sapletta.com
import urirun
from urirun_connector_ksef import connector_manifest, urirun_bindings


def test_bindings_validate_and_cover_environments():
    doc = urirun_bindings()
    assert urirun.validate_binding_document(doc)["ok"], doc
    uris = set(doc["bindings"])
    for env in ("test", "demo", "prod"):
        for route in ("auth/challenge", "session/batch/open", "cert/enroll", "invoices/query"):
            assert f"ksef://{env}/{route}" in uris
    # 13 logical routes x 3 environments
    assert len(uris) == 39
    assert len(uris) % 3 == 0


def test_manifest_matches_bindings():
    manifest = connector_manifest()
    assert manifest["id"] == "ksef"
    assert set(manifest["routes"]) == set(urirun_bindings()["bindings"])


def test_send_route_carries_token_by_reference_only():
    doc = urirun_bindings()
    send = doc["bindings"]["ksef://test/session/online/{ref}/send"]
    assert send["adapter"] == "fetch"
    assert send["config"]["headers"]["Authorization"] == "Bearer {getv:KSEF_ACCESS_TOKEN}"  # reference, not value
