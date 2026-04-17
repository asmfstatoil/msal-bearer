import logging
from msal_bearer.bearerauth import (
    BearerAuth,
    get_user_name,
    get_token,
    get_tenant_authority,
)
from msal_bearer.authenticator import Authenticator

__all__ = [
    "Authenticator",
    "BearerAuth",
    "get_user_name",
    "get_token",
    "get_tenant_authority",
]

logging.getLogger(__name__).addHandler(logging.NullHandler())
