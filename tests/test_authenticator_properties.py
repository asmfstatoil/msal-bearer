import pytest

from msal_bearer.authenticator import Authenticator


def test_init_sets_properties() -> None:
    auth = Authenticator(
        tenant_id="tenant",
        client_id="client",
        client_secret="secret",
        scopes=["scope"],
        user_name="user",
        user_assertion="assertion",
    )

    tenant_id = "tenant"

    assert auth.tenant_id == tenant_id
    assert auth.client_id == "client"
    assert auth.client_secret == "secret"
    assert auth.scopes == ["scope"]
    assert auth.user_name == "user"
    assert auth.user_assertion == "assertion"
    assert auth.authority == f"https://login.microsoftonline.com/{tenant_id}"
    assert auth.token == ""


def test_init_prefers_explicit_authority() -> None:
    authority = "https://custom.authority.example"
    auth = Authenticator(tenant_id="tenant", authority=authority)

    assert auth.authority == authority


def test_scopes_property_converts_string_to_list() -> None:
    auth = Authenticator(client_id="client")

    auth.scopes = "scope"

    assert auth.scopes == ["scope"]


def test_scopes_property_defaults_to_client_default() -> None:
    auth = Authenticator(client_id="client")

    assert auth.scopes == ["client/.default"]


def test_token_property_rejects_non_string() -> None:
    auth = Authenticator()

    with pytest.raises(ValueError, match="Token must be a string"):
        auth.token = None  # type: ignore[assignment]


def test_auth_type_property_for_preset_token() -> None:
    auth = Authenticator(client_id="client")
    auth.token = "preset-token"

    assert auth.auth_type == "preset"


def test_auth_type_property_for_client_secret() -> None:
    auth = Authenticator(client_id="client", client_secret="secret")

    assert auth.auth_type == "client_secret"


def test_auth_type_property_for_obo() -> None:
    auth = Authenticator(
        client_id="client",
        client_secret="secret",
        user_assertion="assertion",
    )

    assert auth.auth_type == "obo"
    with pytest.raises(
        ValueError, match="Tenant ID must be set for public app authentication."
    ):
        assert auth.get_public_app_token()


def test_auth_type_property_for_public_app() -> None:
    auth = Authenticator(tenant_id="tenant", client_id="client")

    assert auth.auth_type == "public_app"


def test_auth_type_property_for_azure_fallback() -> None:
    auth = Authenticator()

    assert auth.auth_type == "azure"

    with pytest.raises(
        ValueError, match="Tenant ID must be set for azure token authentication."
    ):
        _ = auth.get_az_token(scope="scope")


def test_get_az_token_returns_access_token_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth = Authenticator(tenant_id="tenant")

    class DummyAccessToken:
        def __init__(self, token: str):
            self.token = token

    class DummyCredential:
        def get_token(self, scope: str, tenant_id: str):
            assert scope == "scope"
            assert tenant_id == "tenant"
            return DummyAccessToken("az-token")

    monkeypatch.setattr("msal_bearer.authenticator.DefaultAzureCredential", DummyCredential)

    assert auth.get_az_token(scope="scope") == "az-token"


def test_get_az_token_raises_for_empty_scope_list() -> None:
    auth = Authenticator(tenant_id="tenant")

    with pytest.raises(
        ValueError,
        match="At least one scope must be set for azure token authentication.",
    ):
        auth.get_az_token(scope=[])
