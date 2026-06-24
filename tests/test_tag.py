"""The imperative ksef handlers must stamp their output with the shared artifact/widget
contract (urirun.tag): a kind + live=False, so the host can classify ksef results as frozen
artifacts. The declarative HTTP routes are handled by the fetch adapter and are out of scope."""
import urirun_connector_ksef.core as c


def _assert_artifact(result, kind):
    assert result.get("kind") == kind, f"expected kind={kind}, got {result.get('kind')}"
    assert result.get("live") is False, "ksef results are frozen artifacts (live=False)"


def test_authenticate_dry_run_plan_tagged():
    r = c.authenticate(env="test", nip="1234567890")  # no execute -> dry-run plan
    _assert_artifact(r, "auth-plan")


def test_make_csr_tagged():
    r = c.make_csr("ACME sp. z o.o.", organization="ACME", country="PL")
    assert r["ok"]
    _assert_artifact(r, "csr")


def test_encrypt_invoice_tagged():
    r = c.encrypt_invoice(b"<Faktura>...</Faktura>")
    assert r["ok"]
    _assert_artifact(r, "encrypted-invoice")
