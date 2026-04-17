from azure.identity import DefaultAzureCredential
from typing import List, Literal, Optional, Union

from msal_bearer import BearerAuth
from msal import ConfidentialClientApplication


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
        if client_id is not None:
            self.set_client_id(client_id)
        else:
            self.client_id = None

        if client_secret is not None:
            self.set_client_secret(client_secret)
        else:
            self.client_secret = None

        if authority is None and tenant_id is not None:
            self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        else:
            self.authority = None
        self.redirect_uri = redirect_uri
        self.token = ""
        self.user_name = user_name
        if scopes:
            self.set_scope(scopes)
        else:
            self.scopes = []

        self.user_assertion = user_assertion

    def set_client_id(self, client_id: str) -> None:
        self.client_id = client_id

    def get_client_id(self) -> str:
        if not self.client_id:
            raise ValueError("Client ID is not set")
        return self.client_id

    def get_tenant_id(self) -> str:
        if not self.tenant_id:
            raise ValueError("Tenant ID is not set")
        return self.tenant_id

    def set_client_secret(self, client_secret: str) -> None:
        self.client_secret = client_secret

    def set_token(self, token: str) -> None:
        self.token = token

    def set_scope(self, scope: Union[List[str], str]) -> None:
        if isinstance(scope, str):
            scope = [scope]
        self.scopes = scope

    def get_scope(self) -> List[str]:
        if self.scopes is None or len(self.scopes) == 0:
            return [f"{self.get_client_id()}/.default"]
        return self.scopes

    def get_auth_type(
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

    def get_token(self, scopes: Optional[List[str]] = None) -> str:
        """Get token for Authenticator object. Will detect the type of authentication and call submethods.

        Args:
            scopes (Optional[List[str]], optional): Scopes to fetch token for. Defaults to None, which will call self.get_scope()

        Raises:
            ValueError: _description_

        Returns:
            str: Authenticator token.
        """
        auth_type = self.get_auth_type()
        if auth_type == "preset":
            return self.token

        if scopes is None or len(scopes) == 0:
            scopes = self.get_scope()

        if auth_type in ["client_secret", "obo"]:
            c = ConfidentialClientApplication(
                client_id=self.get_client_id(),
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
        if isinstance(scope, list):
            scope = scope[0]
        credential = DefaultAzureCredential()
        token = credential.get_token(scope, tenant_id=self.get_tenant_id())
        return token[0]

    def get_public_app_token(
        self,
        username: Optional[str] = None,
        scope: Optional[Union[List[str], str]] = None,
    ) -> str:
        if not username:
            username = self.user_name  # type: ignore
        else:
            self.user_name = username

        # User name is not required. There will be no token caching and login requires user input, but it will work.
        if username is not None:
            username = username.upper()

        if scope is None:
            scope = self.get_scope()

        if isinstance(scope, str):
            scope = [scope]

        auth = BearerAuth.get_auth(
            tenantID=self.get_tenant_id(),
            clientID=self.get_client_id(),
            scopes=scope,
            username=username,
        )
        return auth.token  # type: ignore
