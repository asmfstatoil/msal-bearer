import pytest
import msal
import msal_extensions

import msal_bearer.bearerauth as bearerauth


def test_set_and_get_token_location() -> None:
    original = bearerauth.get_token_location()
    try:
        bearerauth.set_token_location("custom_cache.bin")
        assert bearerauth.get_token_location() == "custom_cache.bin"
    finally:
        bearerauth.set_token_location(original)


def test_set_token_location_raises_for_invalid_string() -> None:
    with pytest.raises(ValueError, match="Invalid location string"):
        bearerauth.set_token_location("abc")


def test_set_token_location_raises_for_non_string() -> None:
    with pytest.raises(TypeError, match="Input location shall be a string"):
        bearerauth.set_token_location(123)  # type: ignore[arg-type]


def test_set_user_name_and_get_user_name() -> None:
    original = bearerauth._username
    try:
        bearerauth.set_user_name("alice")
        assert bearerauth.get_user_name() == "alice"
    finally:
        bearerauth._username = original


def test_set_user_name_raises_for_non_string() -> None:
    with pytest.raises(TypeError, match="Input username shall be a string"):
        bearerauth.set_user_name(1)  # type: ignore[arg-type]


def test_get_user_name_falls_back_to_login_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bearerauth, "_username", "")
    monkeypatch.setattr(bearerauth, "get_login_name", lambda: "from-login")

    assert bearerauth.get_user_name() == "from-login"


def test_get_login_name_returns_first_matching_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ["LOGNAME", "USER", "LNAME", "USERNAME"]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("USER", "user-value")

    assert bearerauth.get_login_name() == "user-value"


def test_get_login_name_returns_empty_when_no_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ["LOGNAME", "USER", "LNAME", "USERNAME"]:
        monkeypatch.delenv(name, raising=False)

    assert bearerauth.get_login_name() == ""


def test_get_tenant_authority() -> None:
    assert (
        bearerauth.get_tenant_authority("tenant")
        == "https://login.microsoftonline.com/tenant"
    )


def test_get_app_with_cache_reuses_apps_without_crossing_cache_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DummyApp:
        def __init__(self, client_id: str, authority: str, token_cache: object):
            self.client_id = client_id
            self.authority = authority
            self.token_cache = token_cache

    created_apps = []
    created_persistences = []

    def create_app(client_id: str, authority: str, token_cache: object) -> DummyApp:
        app = DummyApp(client_id, authority, token_cache)
        created_apps.append(app)
        return app

    monkeypatch.setattr(bearerauth, "_app_cache", {})
    monkeypatch.setattr(bearerauth, "_token_location", "token_cache.bin")
    monkeypatch.setattr(
        msal_extensions,
        "build_encrypted_persistence",
        lambda location: created_persistences.append(location) or location,
    )
    monkeypatch.setattr(
        msal_extensions,
        "PersistedTokenCache",
        lambda persistence: ("cache", persistence),
    )
    monkeypatch.setattr(msal, "PublicClientApplication", create_app)

    first = bearerauth.get_app_with_cache(
        "client", "https://authority", "cache-one.bin"
    )
    repeated = bearerauth.get_app_with_cache(
        "client", "https://authority", "cache-one.bin"
    )
    different_cache = bearerauth.get_app_with_cache(
        "client", "https://authority", "cache-two.bin"
    )
    different_authority = bearerauth.get_app_with_cache(
        "client", "https://other-authority", "cache-one.bin"
    )
    bearerauth._discard_cached_app("client", "https://authority", "cache-one.bin")
    recreated = bearerauth.get_app_with_cache(
        "client", "https://authority", "cache-one.bin"
    )

    assert repeated is first
    assert different_cache is not first
    assert different_authority is not first
    assert recreated is not first
    assert len(created_apps) == 4
    assert len(created_persistences) == 4


def test_bearerauth_init_accepts_token_dict_with_access_token() -> None:
    auth = bearerauth.BearerAuth({"access_token": "abc123"})

    assert auth.token == "abc123"


def test_bearerauth_init_keeps_string_token() -> None:
    auth = bearerauth.BearerAuth("plain-token")

    assert auth.token == "plain-token"


def test_bearerauth_init_rejects_dict_without_access_token() -> None:
    token_dict = {"access_result": "abc123", "expires_in": 3600}

    with pytest.raises(
        ValueError,
        match="Token must be a string or a dict with key 'access_token'",
    ):
        bearerauth.BearerAuth(token_dict)


def test_bearerauth_token_property_is_read_only() -> None:
    auth = bearerauth.BearerAuth("token-1")

    with pytest.raises(AttributeError):
        auth.token = "token-2"  # type: ignore[misc]


def test_bearerauth_call_sets_authorization_header() -> None:
    class DummyRequest:
        def __init__(self):
            self.headers = {}

    request = DummyRequest()
    auth = bearerauth.BearerAuth("token-1")

    returned_request = auth(request)

    assert returned_request is request
    assert request.headers["authorization"] == "Bearer token-1"
