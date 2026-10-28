from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union


if TYPE_CHECKING:
    from azure.identity import InteractiveBrowserCredential
    from msal import PublicClientApplication

_token_location = "token_cache.bin"
_username = ""
_app_cache: Dict[Tuple[str, str, str], PublicClientApplication] = {}
_app_cache_lock = threading.RLock()


def get_token(tenant_id: str, client_id: str, scopes: List[str]) -> str:
    """Get token for specified scopes for specified public Azure app registration.

    Args:
        tenant_id (str): Azure tenant ID.
        client_id (str): Public Azure app client ID to request token from.
        scopes (List[str]): Scopes to get token for.

    Returns:
        str: Token as string
    """
    b = BearerAuth.get_auth(tenantID=tenant_id, clientID=client_id, scopes=scopes)
    return b.token


def set_token_location(location: str):
    """Set location of token cache

    Args:
        location (str): Location of token cache file.

    Raises:
        ValueError: Raised if input location is not a valid location string.
        TypeError: Raised if input location is not a string.
    """
    global _token_location

    if isinstance(location, str):
        if len(location) > 4 and "." in location:
            _token_location = location
        else:
            raise ValueError(f"Invalid location string {location}")
    else:
        raise TypeError("Input location shall be a string.")


def get_token_location() -> str:
    """Getter for token location.

    Returns:
        str: Token location (pathlike)
    """
    return _token_location


def set_user_name(username: str):
    """Set user name.

    Args:
        username (str): User name to use for user_impersonation
    Raises:
        TypeError: Raises TypeError if input username is not string.
    """
    global _username

    if not isinstance(username, str):
        raise TypeError("Input username shall be a string.")

    _username = username


def get_user_name() -> Union[str, None]:
    """Get user name if set using set_user_name or return result from get_login_name()

    Returns:
        Union[str, None]: User name
    """
    if not _username:
        return get_login_name()

    return _username


def get_login_name() -> str:
    """Get login name of current user.

    Returns:
        str: Login name or empty string if not found.
    """
    env_names = ["LOGNAME", "USER", "LNAME", "USERNAME"]
    for name in env_names:
        tmpName = os.getenv(name)
        if tmpName is not None:
            return tmpName

    return ""


def get_app_with_cache(
    client_id: str, authority: str, token_location: str = ""
) -> PublicClientApplication:
    """Get msal PublicClientApplication to authenticate against, with cached token if available.

    Args:
        client_id (str): Azure Client ID to request token from.
        authority (str): Authority to authenticate against. Should be like f"https://login.microsoftonline.com/{tenantID}".
        token_location (str, optional): Location of token persistance file.
                Defaults to "" which uses previously set value or "token_cache.bin" if not yet set.

    Returns:
        PublicClientApplication: Application object to authenticate with.
    """

    from msal import PublicClientApplication
    from msal_extensions import (
        FilePersistence,
        PersistedTokenCache,
        build_encrypted_persistence,
    )

    if isinstance(token_location, str) and len(token_location) > 0:
        set_token_location(token_location)

    cache_location = os.path.abspath(token_location or get_token_location())
    cache_key = (client_id, authority, cache_location)
    with _app_cache_lock:
        app = _app_cache.get(cache_key)
        if app is not None:
            return app

        try:
            persistence = build_encrypted_persistence(cache_location)
        except (ImportError, RuntimeError):
            # Handle linux case of missing gi library (ImportError)
            persistence = FilePersistence(cache_location)

        cache = PersistedTokenCache(persistence)
        app = PublicClientApplication(
            client_id=client_id, authority=authority, token_cache=cache
        )
        _app_cache[cache_key] = app
        return app


def _discard_cached_app(client_id: str, authority: str, token_location: str) -> None:
    cache_key = (client_id, authority, os.path.abspath(token_location))
    with _app_cache_lock:
        _app_cache.pop(cache_key, None)


def get_tenant_authority(tenant_id: str) -> str:
    """Get url to default authority to authenticate against.

    Args:
        tenant_id (str): Tenant ID.

    Returns:
        str: Authority url.
    """
    return f"https://login.microsoftonline.com/{tenant_id}"


def get_interactive_browser_credential(
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    auth_location: Optional[str] = None,
) -> InteractiveBrowserCredential:
    """Return InteractiveBrowserCredential that will persist token cache.

    Args:
        tenant_id (Optional[str], optional): Azure tenant id. Defaults to None.
        client_id (Optional[str], optional): Azure client id. Defaults to None.
        auth_location (Optional[str], optional): Path to the persisted authentication record. Defaults to None, which will convert to f"{name}_auth.json" or "msal-bearer_auth.json" if client_id is not set.

    Returns:
        InteractiveBrowserCredential: Credential used to get token.
    """
    from azure.identity import (
        AuthenticationRecord,
        InteractiveBrowserCredential,
        TokenCachePersistenceOptions,
    )

    if client_id:
        name = client_id
    else:
        name = "msal-bearer"

    if auth_location is None:
        auth_location = f"{name}_auth.json"

    cache_options = TokenCachePersistenceOptions(name=name)

    if os.path.isfile(auth_location):
        try:
            with open(auth_location, "r") as f:
                auth_record = f.read()
        except Exception as e:
            print(
                f"Failed reading authentication record from {auth_location} due to {e}"
            )
            os.remove(auth_location)
            return get_interactive_browser_credential(
                tenant_id=tenant_id, client_id=client_id, auth_location=auth_location
            )

        credential = InteractiveBrowserCredential(
            tenant_id=tenant_id,
            client_id=client_id,  # nb! authentication_record contains client_id and will override this
            cache_persistence_options=TokenCachePersistenceOptions(),
            authentication_record=AuthenticationRecord.deserialize(auth_record),
        )
    else:
        if client_id is None:
            credential = InteractiveBrowserCredential(
                tenant_id=tenant_id, cache_persistence_options=cache_options
            )
        else:
            credential = InteractiveBrowserCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                cache_persistence_options=cache_options,
            )
        auth_record = credential.authenticate()
        with open(auth_location, "w") as f:
            f.write(auth_record.serialize())

    return credential


class BearerAuth:
    """Class for getting bearer token authentication using msal.

    Get BearerAuth object by calling get_auth.
    """

    def __init__(self, token: Union[dict, str]):
        if isinstance(token, dict) and "access_token" in token:
            token = token["access_token"]

        if not isinstance(token, str):
            raise ValueError(
                "Token must be a string or a dict with key 'access_token'."
            )
        self._token = token

    def __call__(self, r):
        r.headers["authorization"] = f"Bearer {self.token}"
        return r

    @property
    def token(self) -> str:
        """Token property for BearerAuth object."""
        return self._token

    @staticmethod
    def get_auth(
        tenantID: str,
        clientID: str,
        scopes: List[str],
        username: Optional[str] = "",
        token_location: Optional[str] = "",
        authority: Optional[str] = "",
        verbose: Optional[bool] = False,
    ) -> "BearerAuth":
        """Get BearerAuth object interactively with access token for an azure application.

        Args:
            tenantID (str): Azure tenant ID.
            clientID (str): Public Azure app client ID to request token from.
            scopes (List[str]): Scopes to get token for.
            username (str, optional): User name to authenticate. Defaults to "", which result in first account of app to be selected.".
            token_location (str, optional): Path to token cache. Defaults to "", which will call get_token_location().
            authority (str, optional): Authenticator. Defaults to "", which converts to f"https://login.microsoftonline.com/{tenantID}".
            verbose (bool, optional): Set true to print messages. Defaults to False.

        Raises:
            Exception: Raises exception if unable to get token.

        Returns:
            BearerAuth: Token bearing authenticator object.
        """
        if authority is None or (isinstance(authority, str) and len(authority) == 0):
            authority = get_tenant_authority(tenant_id=tenantID)

        result = None
        accounts = None

        if not token_location:
            token_location = get_token_location()

        try:
            # Try to get Access Token silently from cache
            app = get_app_with_cache(
                client_id=clientID, authority=authority, token_location=token_location
            )
            # User name must match including domain, if not caching will not work.
            accounts = app.get_accounts(username=username)
        except Exception:
            _discard_cached_app(clientID, authority, token_location)
            if os.path.isfile(token_location):
                if verbose:
                    print(
                        f"Failed getting accounts from app with cache. Attempts to delete cache-file at {token_location}"
                    )
                os.remove(token_location)
            app = get_app_with_cache(
                client_id=clientID, authority=authority, token_location=token_location
            )
            accounts = app.get_accounts(username=username)

        if accounts:
            if verbose:
                print(f"Found account in token cache: {username}")
                print("Attempting to obtain a new Access Token using the Refresh Token")
            result = app.acquire_token_silent(scopes=scopes, account=accounts[0])

        if result is None or (
            isinstance(result, dict)
            and "error_codes" in result
            and 50173 in result["error_codes"]
        ):
            # Try to get a new Access Token using the Interactive Flow
            if verbose:
                print(
                    "Interactive Authentication required to obtain a new Access Token."
                )
            try:
                result = app.acquire_token_interactive(
                    scopes=scopes, domain_hint=tenantID
                )
            except OSError:
                if os.path.isfile(token_location):
                    _discard_cached_app(clientID, authority, token_location)
                    os.remove(token_location)
                    app = get_app_with_cache(
                        client_id=clientID,
                        authority=authority,
                        token_location=token_location,
                    )
                    result = app.acquire_token_interactive(
                        scopes=scopes, domain_hint=tenantID
                    )
                else:
                    raise

        if (
            result
            and isinstance(result, dict)
            and "access_token" in result
            and result["access_token"]
        ):
            if verbose:
                print("Success")
            return BearerAuth(result["access_token"])

        if verbose:
            print(f"Failed, returned:\n{result}")
        raise Exception("Failed authenticating")
