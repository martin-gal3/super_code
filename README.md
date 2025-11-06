from typing import List, Optional, Callable, Type, Union
from collections.abc import Container
from fastapi.security import OAuth2PasswordBearer
import uvicorn
from fastapi import FastAPI, Depends, Query, Body, HTTPException, status
from pydantic import BaseModel, SecretStr, Field, SecretStr
from jose import ExpiredSignatureError, JWTError, jwt
import functools
import requests
from json import JSONDecodeError
from urllib.parse import urlencode
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

"""SETTINGs"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    app_name: str = "Awesome API"
    admin_email: str
    items_per_user: int = 50

    model_config = SettingsConfigDict(env_file=".env")

@lru_cache
def get_settings():
    return Settings()

"""LIFESPAN"""
# MONGO_URI = "mongodb://localhost:27017"
# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     # ✅ Create once - shared across requests
#     app.state.mongo = AsyncIOMotorClient(MONGO_URI, maxPoolSize=100)
#     await app.state.mongo.admin.command("ping")  # optional health check
#     yield
#     # ✅ Cleanup on shutdown
#     app.state.mongo.close()
# app = FastAPI(lifespan=lifespan)

# https://fastapi.tiangolo.com/tutorial/sql-databases/#create-a-session-dependency


"""LIFESPAN"""



"""SETTINGs"""

app = FastAPI(swagger_ui_parameters={"syntaxHighlight": {"theme": "obsidian"}})
app.swagger_ui_init_oauth = {
    "usePkceWithAuthorizationCodeGrant": True,
    "clientId": "toto",
    "clientSecret": "SarGvLcv3YokxCDTIbauAPKTxARsLjxu",
}
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class MandatoryActionException(HTTPException):
    """Throw if the exchange of username and password for an access token fails"""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=400, detail=detail)


class KeycloakError(Exception):
    """Thrown if any response of keycloak does not match our expectation

    Attributes:
        status_code (int): The staftus code of the response received
        reason (str): The reason why the requests did fail
    """

    def __init__(self, status_code: int, reason: str):
        self.status_code = status_code
        self.reason = reason
        super().__init__(f"HTTP {status_code}: {reason}")


class UsernamePassword(BaseModel):
    """Represents a request body that contains username and password

    Attributes:
        username (str): Username
        password (str): Password, masked by swagger
    """

    username: str
    password: SecretStr

class KeycloakToken(BaseModel):
    """Keycloak representation of a token object

    Attributes:
        access_token (str): An access token
        refresh_token (str): An a refresh token, default None
        id_token (str): An issued by the Authorization Server token id, default None
    """

    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None

    def __str__(self):
        """String representation of KeycloakToken"""
        return f"Bearer {self.access_token}"

class OIDCUser(BaseModel):
    """Represents a user object of Keycloak, parsed from access token

    Attributes:
        sub (str):
        iat (int):
        exp (int):
        scope (str):
        email_verified (bool):
        name (Optional[str]):
        given_name (Optional[str]):
        family_name (Optional[str]):
        email (Optional[str]):
        preferred_username (Optional[str]):
        realm_access (dict):
        resource_access (dict):
        extra_fields (dict):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    azp: Optional[str] = None
    sub: str
    iat: int
    exp: int
    scope: Optional[str] = None
    email_verified: bool
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email: Optional[str] = None
    preferred_username: Optional[str] = None
    realm_access: Optional[dict] = None
    resource_access: Optional[dict] = None
    extra_fields: dict = Field(default_factory=dict)

    @property
    def roles(self) -> List[str]:
        """Returns the roles of the user

        Returns:
            List[str]: If the realm access dict contains roles
        """
        if not self.realm_access and not self.resource_access:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' and 'resource_access' sections of the provided access token are missing.",
            )
        roles = []
        if self.realm_access:
            if "roles" in self.realm_access:
                roles += self.realm_access["roles"]
        if self.azp and self.resource_access:
            if self.azp in self.resource_access:
                if "roles" in self.resource_access[self.azp]:
                    roles += self.resource_access[self.azp]["roles"]
        if not roles:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' and 'resource_access' sections of the provided access token did not "
                       "contain any 'roles'",
            )
        return roles

    def __str__(self) -> str:
        """String representation of an OIDCUser"""
        return self.preferred_username
    
# class KeycloakUser(BaseModel):
#     """Represents a user object of Keycloak.

#     Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
#     details. This is a mere proxy object.
#     """

#     id: str
#     username: str
#     enabled: bool
#     firstName: Optional[str] = None
#     lastName: Optional[str] = None
#     email: Optional[str] = None
#     disableableCredentialTypes: List[str]
#     requiredActions: List[str]
#     realmRoles: Optional[List[str]] = None
#     notBefore: int
#     access: Optional[dict] = None
#     attributes: Optional[dict] = None

def result_or_error(
        response_model: Type[BaseModel] = None, is_list: bool = False
) -> Union[List[BaseModel], BaseModel, KeycloakError]:
    """Decorator used to ease the handling of responses from Keycloak.
    """
    def inner(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            def create_list(json_data: List[dict]):
                return [response_model.parse_obj(entry) for entry in json_data]

            def create_object(json_data: dict):
                return response_model.parse_obj(json_data)

            result: requests.Response = f(*args, **kwargs)  # The actual call

            if (
                    type(result) != requests.Response
            ):  # If the object given is not a response object, directly return it.
                return result

            if result.status_code in range(100, 299):  # Successful
                if response_model is None:  # No model given
                    try:
                        return result.json()
                    except JSONDecodeError:
                        return result.content.decode("utf-8")
                else:  # Response model given
                    if is_list:
                        return create_list(result.json())
                    else:
                        return create_object(result.json())
            else:
                try:
                    raise KeycloakError(
                        status_code=result.status_code, reason=result.json()
                    )
                except JSONDecodeError:
                    raise KeycloakError(
                        status_code=result.status_code,
                        reason=result.content.decode("utf-8"),
                    )

        return wrapper

    return inner

class FastAPIKeycloak:
    """Instance to wrap the Keycloak API with FastAPI

    Attributes: _admin_token (KeycloakToken): A KeycloakToken instance, containing the access token that is used for
    any admin related request

    Example:
        ```python
        app = FastAPI()
        idp = KeycloakFastAPI(
            server_url="https://auth.some-domain.com/auth",
            client_id="some-test-client",
            client_secret="some-secret",
            admin_client_secret="some-admin-cli-secret",
            realm="Test",
            callback_uri=f"http://localhost:8081/callback"
        )
        ```
    """


    def __init__(
            self,
            server_url: str,
            client_id: str,
            client_secret: str,
            realm: str,
            callback_uri: str,
            scope: str = "openid profile email",
            timeout: int = 10,
            ssl_verification: bool = True,
            algorithms: str  | None = None
    ):
        """FastAPIKeycloak constructor

        Args:
            server_url (str): The URL of the Keycloak server, with `/auth` suffix
            client_id (str): The id of the client used for users
            client_secret (str): The client secret
            realm (str): The realm (name)
            admin_client_id (str): The id for the admin client, defaults to 'admin-cli'
            admin_client_secret (str): Secret for the `admin-cli` client
            callback_uri (str): Callback URL of the instance, used for auth flows. Must match at least one
            `Valid Redirect URIs` of Keycloak and should point to an endpoint that utilizes the authorization_code flow.
            timeout (int): Timeout in seconds to wait for the server
            scope (str): OIDC scope
        """
        self.server_url = server_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.callback_uri = callback_uri
        self.timeout = timeout
        self.scope = scope
        self.ssl_verification = ssl_verification
        self.algorithms = algorithms
        # self._get_admin_token()  # Requests an admin access token on startup

    @functools.cached_property
    def authorization_uri(self):
        """The authorization endpoint URL"""
        return self.open_id_configuration.get("authorization_endpoint")

    @functools.cached_property
    def user_auth_scheme(self) -> OAuth2PasswordBearer:
        """Returns the auth scheme to register the endpoints with swagger

        Returns:
            OAuth2PasswordBearer: Auth scheme for swagger
        """
        return OAuth2PasswordBearer(tokenUrl=self.token_uri)

    @functools.cached_property
    def logout_uri(self):
        """The logout endpoint URL"""
        return self.open_id_configuration.get("end_session_endpoint")

    @functools.cached_property
    def login_uri(self):
        """The URL for users to login on the realm. Also adds the client id, the callback and the scope."""
        params = {
            "scope": self.scope,
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.callback_uri,
        }
        return f"{self.authorization_uri}?{urlencode(params)}"

    @functools.cached_property
    def token_uri(self):
        """The token endpoint URL"""
        return self.open_id_configuration.get("token_endpoint")

    @functools.cached_property
    def realm_uri(self):
        """The realm's endpoint URL"""
        return f"{self.server_url}/realms/{self.realm}"

    @functools.cached_property
    def public_key(self) -> str:
        """Returns the Keycloak public key

        Returns:
            str: Public key for JWT decoding
        """
        response = requests.get(url=self.realm_uri, timeout=self.timeout, verify=self.ssl_verification)
        public_key = response.json()["public_key"]
        return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

    @functools.cached_property
    def open_id_configuration(self) -> dict:
        """Returns Keycloaks Open ID Connect configuration

        Returns:
            dict: Open ID Configuration
        """
        response = requests.get(
            url=f"{self.realm_uri}/.well-known/openid-configuration",
            timeout=self.timeout,
            verify=self.ssl_verification
        )
        return response.json()

    @result_or_error(response_model=KeycloakToken)
    def user_login(self, username: str, password: str) -> KeycloakToken:
        """Models the password OAuth2 flow. Exchanges username and password for an access token. Will raise detailed
        errors if login fails due to requiredActions
            - To avoid calling this multiple times, you may want to check all requiredActions of the user if it fails
            due to a (sub)instance of an MandatoryActionException
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": self.scope,
        }
        response = requests.post(url=self.token_uri, headers=headers, data=data, timeout=self.timeout, verify=self.ssl_verification)
        response.raise_for_status()
        return response

    def _decode_token(
            self, token: str, options: dict = None, audience: str = None, algorithms: str | Container[str] | None = None
    ) -> dict:
        """Decodes a token, verifies the signature by using Keycloaks public key. Optionally verifying the audience

        Args:
            token (str):
            options (dict):
            audience (str): Name of the audience, must match the audience given in the token

        Returns:
            dict: Decoded JWT

        Raises:
            ExpiredSignatureError: If the token is expired (exp > datetime.now())
            JWTError: If decoding fails or the signature is invalid
            JWTClaimsError: If any claim is invalid
        """
        if options is None:
            options = {
                "verify_signature": True,
                "verify_aud": audience is not None,
                "verify_exp": True,
            }
        return jwt.decode(
            token=token, key=self.public_key, options=options, audience=audience, algorithms=algorithms
        )
    
    def get_current_user(self, required_roles: List[str] = None, extra_fields: List[str] = None) -> Callable[OAuth2PasswordBearer, OIDCUser]:
        """Returns the current user based on an access token in the HTTP-header. Optionally verifies roles are possessed
        by the user
        """

        def current_user(
                token: OAuth2PasswordBearer = Depends(self.user_auth_scheme),
        ) -> OIDCUser:
            """Decodes and verifies a JWT to get the current user
            """
            try:
                decoded_token = self._decode_token(token=token, audience="account", algorithms=self.algorithms)
            except JWTError as e:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED) from e

            user = OIDCUser.parse_obj(decoded_token)
            if required_roles:
                for role in required_roles:
                    if role not in user.roles:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f'Role "{role}" is required to perform this action',
                        )

            if extra_fields:
                for field in extra_fields:
                    user.extra_fields[field] = decoded_token.get(field, None)

            return user

        return current_user

    @result_or_error(response_model=KeycloakToken)
    def exchange_authorization_code(
            self, session_state: str, code: str
    ) -> KeycloakToken:
        """Models the authorization code OAuth2 flow. Opening the URL provided by `login_uri` will result in a
        callback to the configured callback URL. The callback will also create a session_state and code query
        parameter that can be exchanged for an access token.

        Args:
            session_state (str): Salt to reduce the risk of successful attacks
            code (str): The authorization code

        Returns:
            KeycloakToken: If the exchange succeeds

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "session_state": session_state,
            "grant_type": "authorization_code",
            "redirect_uri": self.callback_uri,
        }
        return requests.post(url=self.token_uri, headers=headers, data=data, timeout=self.timeout, verify=self.ssl_verification)

    
idp = FastAPIKeycloak(
    server_url="http://localhost:8080",
    client_id="toto",
    client_secret="SarGvLcv3YokxCDTIbauAPKTxARsLjxu",
    # admin_client_secret="BIcczGsZ6I8W5zf0rZg5qSexlloQLPKB",
    realm="testrealm",
    callback_uri="http://localhost:8000/callback"
)


# Example User Requests

@app.get("/me")
def get_me(user: OIDCUser = Depends(idp.get_current_user())):
    return user


@app.get("/me/roles")
def get_my_roles(user: OIDCUser = Depends(idp.get_current_user())):
    return user.roles


@app.get("/admin")
def company_admin(user: OIDCUser = Depends(idp.get_current_user(required_roles=["admin"]))):
    return f'Hi admin {user}'


@app.get("/login")
def login(user: UsernamePassword = Depends()):
    return idp.user_login(username=user.username, password=user.password.get_secret_value())

@app.get("/login-link")
def login_redirect():
    return RedirectResponse(idp.login_uri)

@app.get("/callback")
def callback(session_state: str, code: str):
    return idp.exchange_authorization_code(session_state=session_state, code=code)

@app.get("/")  # Unprotected
def root():
    return 'Hello World'

@app.get("/logout", tags=["auth-flow"])
def logout():
    return RedirectResponse(idp.logout_uri)

if __name__ == '__main__':
    uvicorn.run('app:app', host="127.0.0.1", port=8081)
