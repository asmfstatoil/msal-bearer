# msal-bearer
Python package to get authorization token interactively for a msal application.  
For public client application using user impersonation it also handles local cache and refreshing the token.

## Usage 1: Public client application user impersonation


````
from msal_bearer import BearerAuth

tenant_id = "YOUR_TENANT_ID"
client_id = "YOUR_CLIENT_ID"
scope = ["YOUR_SCOPE"]

auth = BearerAuth.get_auth(
    tenantID=tenant_id,
    clientID=client_id,
    scopes=scope
)

# Supports requests
response = requests.get("https://www.example.com/", auth=auth)

# and httpx
client = httpx.Client()
response = client.get("https://www.example.com/", auth=auth)

````

## Usage 2: Confidential client with secret

````
from msal_bearer import Authenticator

tenant_id = "YOUR_TENANT_ID"
client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
scope = ["YOUR_SCOPE"]

a = Authenticator(
    tenant_id=tenant_id
    client_id=client_id,
    client_secret=client_secret,
)
token = a.get_token(scopes=scope)

````

## Usage 2: Confidential client with user_assertion for OBO authentication on streamlit

````
from msal_bearer import Authenticator

tenant_id = "YOUR_TENANT_ID"
client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
scope = ["YOUR_SCOPE"]

user_assertion = st.context.headers["X-Forwarded-Access-Token"]

a = Authenticator(
    tenant_id=tenant_id
    client_id=client_id,
    client_secret=client_secret,
    user_assertion=user_assertion,
)
token = a.get_token(scopes=scope)

````

## Installing
Clone and install using poetry or install from pypi using pip. 

````
pip install msal_bearer
````


## Alternatives
Other similar packages include https://pypi.org/project/msal-requests-auth/ (for confidential client applications) and https://pypi.org/project/msal-interactive-token-acquirer/ (no caching implemented).

