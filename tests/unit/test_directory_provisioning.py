"""Synthetic provisioning tests: no domain connections or real credentials."""

import json
from dataclasses import replace

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from test_directory_auth import FakeDirectory, login, setup
from test_directory_management import MemoryStore
from vg_api.directory_auth import DirectoryAuth
from vg_api.directory_provisioning import (
    DirectoryProvisioning,
    ProvisioningConfig,
    privileged_username,
)
from vg_core.domain import ControlPlane, DomainError

TECH = "00000000-0000-0000-0000-000000000001"


class Writer:
    exists = False
    fail = False
    calls = 0

    def inspect(self, username):
        assert username == "a.alice"
        return self.exists

    def create(self, username, password, writer_dn, writer_password):
        self.calls += 1
        assert len(password) >= 32
        if self.fail:
            raise ValueError("SECRET MUST NOT LEAK")
        return "00000000-0000-0000-0000-000000000002"


def application(enabled=True):
    # Get the tested directory configuration without changing shared fixture files.
    client, original = setup()
    from vg_api.directory import DirectoryConfig

    cfg = DirectoryConfig(
        host="dc.example.invalid",
        ca_file="/tmp/not-real",
        bind_dn="CN=Reader,DC=test",
        bind_password_env="TEST",
        user_base_dn="DC=test",
        group_base_dn="DC=test",
        org_id="org",
        tenant_ids=["tenant"],
        group_mappings=[
            {"group_dn": "CN=Tech,DC=test", "roles": ["technician"]},
            {"group_dn": "CN=Owners,DC=test", "roles": ["superadmin"]},
        ],
    )
    provider = FakeDirectory()
    provider.rows[TECH] = replace(provider.rows.pop("a"), id=TECH)
    auth = DirectoryAuth(ControlPlane((), {}), cfg, provider)
    app = FastAPI()

    @app.exception_handler(DomainError)
    async def handle(request, error):
        return JSONResponse({"detail": str(error)}, status_code=error.status)

    auth.install(app)
    writer, store = Writer(), MemoryStore()
    config = ProvisioningConfig(domain_base_dn="DC=test", target_ou_dn="OU=Managed,DC=test")
    DirectoryProvisioning(
        auth, config if enabled else None, store if enabled else None, provider=writer
    ).install(app)
    client = TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000))
    login(client, "boss")
    return client, writer, store


def body():
    return {
        "user_id": TECH,
        "confirmed_username": "a.alice",
        "consent": True,
        "writer_dn": "CN=Creator,DC=test",
        "writer_password": "fake-writer-secret",
    }


def test_preview_and_create_are_opt_in_and_never_return_passwords():
    client, writer, store = application()
    preview = client.post("/v1/directory/provisioning/preview", json={"user_id": TECH})
    assert preview.status_code == 200
    assert preview.json()["username"] == "a.alice"
    assert writer.calls == 0
    response = client.post("/v1/directory/provisioning/create", json=body())
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "disabled_pending_enrollment"
    saved = json.loads(store.data)["accounts"]["dc.example.invalid:a.alice"]
    assert saved["password"] not in response.text
    assert "fake-writer-secret" not in store.data.decode()
    assert writer.calls == 1
    assert client.post("/v1/directory/provisioning/create", json=body()).status_code == 409
    assert writer.calls == 1


def test_denied_and_incomplete_consent():
    client, writer, _ = application()
    bad = body()
    bad["consent"] = False
    assert client.post("/v1/directory/provisioning/create", json=bad).status_code == 422
    bad = body()
    bad["confirmed_username"] = "a.someone"
    assert client.post("/v1/directory/provisioning/create", json=bad).status_code == 409
    login(client, "alice")
    assert client.post("/v1/directory/provisioning/create", json=body()).status_code == 403
    assert writer.calls == 0


def test_storage_failure_prevents_ad_write_and_uncertainty_blocks_retry():
    client, writer, store = application()
    store.fail = True
    assert client.post("/v1/directory/provisioning/create", json=body()).status_code == 503
    assert writer.calls == 0
    store.fail = False
    writer.fail = True
    response = client.post("/v1/directory/provisioning/create", json=body())
    assert response.status_code == 503
    assert "SECRET MUST NOT LEAK" not in response.text
    assert client.post("/v1/directory/provisioning/create", json=body()).status_code == 409
    assert writer.calls == 1


def test_disabled_and_csrf():
    client, writer, _ = application(False)
    assert not client.get("/v1/directory/provisioning").json()["enabled"]
    assert client.post("/v1/directory/provisioning/create", json=body()).status_code == 503
    del client.headers["X-CSRF-Token"]
    assert client.post("/v1/directory/provisioning/create", json=body()).status_code == 403
    assert writer.calls == 0


def test_username_no_truncation_or_double_prefix():
    assert privileged_username("joe.bloe") == "a.joe.bloe"
    for name in ["a.joe", "A.joe", "x" * 19, "bad,name", "x@domain", "", "bad\\name"]:
        with pytest.raises(DomainError):
            privileged_username(name)
    with pytest.raises(ValueError):
        ProvisioningConfig(domain_base_dn="DC=test", target_ou_dn="OU=Managed,DC=other")


def test_ldaps_create_keeps_account_disabled_and_uses_password_extension():
    from contextlib import contextmanager
    from types import SimpleNamespace
    from unittest.mock import Mock

    from vg_api.directory_provisioning import LdapsProvisioner

    connection = Mock()
    connection.result = {"result": 0}
    connection.response = [
        {
            "type": "searchResEntry",
            "attributes": {"userAccountControl": ["514"]},
            "raw_attributes": {"objectGUID": [bytes.fromhex("02000000000000000000000000000000")]},
        }
    ]
    connection.add.return_value = True
    connection.extend.microsoft.modify_password.return_value = True

    @contextmanager
    def connect(dn, password):
        assert dn == "writer" and password == "writer-secret"
        yield connection

    directory = SimpleNamespace(_connection=connect)
    service = LdapsProvisioner(
        directory, ProvisioningConfig(domain_base_dn="DC=test", target_ou_dn="OU=Managed,DC=test")
    )
    service._scope = Mock()
    service._exists = Mock(return_value=False)
    service.create("a.alice", "generated-secret", "writer", "writer-secret")
    attributes = connection.add.call_args.args[2]
    assert attributes["userAccountControl"] == 514
    assert "memberOf" not in attributes
    assert "unicodePwd" not in attributes
    connection.extend.microsoft.modify_password.assert_called_once_with(
        "CN=a.alice,OU=Managed,DC=test", "generated-secret"
    )
    connection.modify.assert_not_called()


def test_sam_length_boundary_and_domain_collision_includes_groups():
    from types import SimpleNamespace
    from unittest.mock import Mock

    from vg_api.directory_provisioning import LdapsProvisioner

    assert len(privileged_username("j" * 18)) == 20
    with pytest.raises(DomainError):
        privileged_username("j" * 19)
    search = Mock(return_value=[{"dn": "CN=a.joe,OU=Groups,DC=test"}])
    provider = LdapsProvisioner(
        SimpleNamespace(_search=search),
        ProvisioningConfig(domain_base_dn="DC=test", target_ou_dn="OU=Managed,DC=test"),
    )
    connection = object()
    assert provider._exists(connection, "a.joe")
    search.assert_called_once_with(
        connection, "DC=test", "(sAMAccountName=a.joe)", ["objectGUID"], 2
    )
