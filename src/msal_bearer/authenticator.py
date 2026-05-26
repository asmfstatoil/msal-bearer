import warnings
from typing import List, Literal, Optional, Union

from azure.identity import DefaultAzureCredential
from msal import ConfidentialClientApplication

from msal_bearer import BearerAuth


class Authenticator:
    """Class for authentication to Azure.

    Supporting three methods:
    1. Public app authentication (tenant_id, client_id must be set)
    2. Client secret authentication (client_id and client_secret must be set)
    3. Azure authentication (if no other method is possible), will cycle through DefaultAzureCredential methods with its various ways of authenticating.

    """

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        authority: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scopes: Optional[Union[str, List[str]]] = None,
        user_name: Optional[str] = None,
        user_assertion: Optional[str] = None,
    ):
        """Initializer for Authenticator class.

        Args:
            tenant_id (Optional[str], optional): Azure tenant id. Defaults to None.
            client_id (Optional[str], optional): _description_. Defaults to None.
            client_secret (Optional[str], optional): _description_. Defaults to None.
            authority (Optional[str], optional): _description_. Defaults to None, which converts to f"https://login.microsoftonline.com/{tenant_id}".
            redirect_uri (Optional[str], optional): _description_. Defaults to None.
            scopes (Optional[Union[str, List[str]]], optional): Scopes to fetch token for. Defaults to None, which will convert to client_id/.default.
            user_name (Optional[str], optional): User name used for hinting during interactive login and checking for cache. Defaults to None.
            user_assertion (Optional[str]): User assertion token used for on-behalf-of flow. Defaults to not set.
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

        if authority:
            self.authority = authority
        elif tenant_id is not None:
            self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        else:
            self.authority = None

        self.redirect_uri = redirect_uri
        self.token = ""
        self.user_name = user_name
        if scopes:
            self.scopes = scopes
        else:
            self.scopes = []

        self.user_assertion = user_assertion

    @property
    def client_id(self) -> Union[str, None]:
        return self._client_id

    @client_id.setter
    def client_id(self, client_id: Optional[str]) -> None:
        self._client_id = client_id

    @property
    def tenant_id(self) -> Union[str, None]:
        return self._tenant_id

    @tenant_id.setter
    def tenant_id(self, tenant_id: Optional[str]) -> None:
        self._tenant_id = tenant_id

    @property
    def client_secret(self) -> Optional[str]:
        return self._client_secret

    @client_secret.setter
    def client_secret(self, client_secret: Optional[str]) -> None:
        self._client_secret = client_secret

    @property
    def token(self) -> str:
        """Token property for Authenticator object. If getting token from external authentication."""
        return self._token

    @token.setter
    def token(self, token: str) -> None:
        if not isinstance(token, str):
            raise ValueError("Token must be a string.")
        self._token = token

    @property
    def scopes(self) -> List[str]:
        if len(self._scopes) == 0 and self.client_id is not None:
            return [f"{self.client_id}/.default"]
        return self._scopes

    @scopes.setter
    def scopes(self, scope: Union[List[str], str]) -> None:
        if isinstance(scope, str):
            scope = [scope]
        self._scopes = scope

    @property
    def auth_type(
        self,
    ) -> Literal["preset", "client_secret", "obo", "public_app", "azure"]:
        if self.token:
            return "preset"
        elif self.client_id:
            if self.client_secret:
                if self.user_assertion:
                    return "obo"
                else:
                    return "client_secret"
            elif self.tenant_id:
                return "public_app"

        # Not found, will try defaultazurecredentials,
        # https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential?view=azure-python
        return "azure"

    def set_client_id(self, client_id: str) -> None:
        warnings.warn(
            "set_client_id is deprecated; assign to property client_id instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.client_id = client_id

    def get_client_id(self) -> Union[str, None]:
        warnings.warn(
            "get_client_id is deprecated; use property client_id instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.client_id

    def get_tenant_id(self) -> Union[str, None]:
        warnings.warn(
            "get_tenant_id is deprecated; use property tenant_id instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.tenant_id

    def set_client_secret(self, client_secret: str) -> None:
        warnings.warn(
            "set_client_secret is deprecated; assign to property client_secret instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.client_secret = client_secret

    def set_token(self, token: str) -> None:
        warnings.warn(
            "set_token is deprecated; assign to property token instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.token = token

    def set_scope(self, scope: Union[List[str], str]) -> None:
        warnings.warn(
            "set_scope is deprecated; assign to property scopes instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.scopes = scope

    def get_scope(self) -> List[str]:
        warnings.warn(
            "get_scope is deprecated; use property scopes instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.scopes

    def get_auth_type(
        self,
    ) -> Literal["preset", "client_secret", "obo", "public_app", "azure"]:
        warnings.warn(
            "get_auth_type is deprecated; use auth_type instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.auth_type

    def get_token(self, scopes: Optional[List[str]] = None) -> str:
        """Get token for Authenticator object. Will detect the type of authentication and call submethods.

        Args:
            scopes (Optional[List[str]], optional): Scopes to fetch token for. Defaults to None, which will use self.scopes.

        Raises:
            ValueError: Returns ValueError if token acquisition fails due to missing parameters or failure in authentication.
        Returns:
            str: Authenticator token.
        """
        auth_type = self.auth_type
        if auth_type == "preset":
            return self.token

        if scopes is None or len(scopes) == 0:
            scopes = self.scopes

        if auth_type in ["client_secret", "obo"]:
            c = ConfidentialClientApplication(
                client_id=self.client_id,
                client_credential=self.client_secret,
                authority=self.authority,
            )

            if auth_type == "client_secret":
                d = c.acquire_token_for_client(scopes=scopes)
            elif auth_type == "obo":
                d = c.acquire_token_on_behalf_of(
                    user_assertion=self.user_assertion,
                    scopes=scopes,
                )
            if d is None:
                raise ValueError("Could not get token.")
            if "access_token" not in d:
                raise ValueError(
                    f"Could not get token: {d.get('error_description', d.get('error'))}"
                )
            return d["access_token"]
        elif auth_type == "public_app":
            return self.get_public_app_token(scope=scopes)

        return self.get_az_token(scope=scopes)

    def get_az_token(self, scope: Union[List[str], str]) -> str:
        """Getter for token uzing azure authentication.

        Returns:
            str: Token from azure authentication
        """
        if not self.tenant_id:
            raise ValueError("Tenant ID must be set for azure token authentication.")

        if isinstance(scope, list):
            if len(scope) == 0:
                raise ValueError(
                    "At least one scope must be set for azure token authentication."
                )
            scope = scope[0]
        credential = DefaultAzureCredential()
        token = credential.get_token(scope, tenant_id=self.tenant_id)
        return token.token

    def get_public_app_token(
        self,
        username: Optional[str] = None,
        scope: Optional[Union[List[str], str]] = None,
    ) -> str:
        if not self.tenant_id:
            raise ValueError("Tenant ID must be set for public app authentication.")
        if not self.client_id:
            raise ValueError("Client ID must be set for public app authentication.")

        if not username:
            username = self.user_name  # type: ignore
        else:
            self.user_name = username

        # User name is not required. There will be no token caching and login requires user input, but it will work.
        if username is not None:
            username = username.upper()

        if scope is None:
            scope = self.scopes

        if isinstance(scope, str):
            scope = [scope]

        if not self.tenant_id:
            raise ValueError("Tenant ID must be set for public app authentication.")
        if not self.client_id:
            raise ValueError("Client ID must be set for public app authentication.")

        auth = BearerAuth.get_auth(
            tenantID=self.tenant_id,
            clientID=self.client_id,
            scopes=scope,
            username=username,
        )
        return auth.token  # type: ignore
