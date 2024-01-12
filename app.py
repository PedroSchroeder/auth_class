from fastapi import FastAPI, Security, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi_azure_auth import SingleTenantAzureAuthorizationCodeBearer
from fastapi_azure_auth.exceptions import InvalidAuth
from fastapi_azure_auth.user import User
from pydantic import AnyHttpUrl, BaseSettings


class Settings(BaseSettings):
    """
    Settings for the application, get values from .env file.
    """
    BACKEND_CORS_ORIGINS: list[str | AnyHttpUrl] = ['http://localhost:8000']
    OPENAPI_CLIENT_ID: str = ""
    AUTH_CLIENT_ID: str = ""
    TENANT_ID: str = ""
    SCOPE_DESCRIPTION: str = "user_impersonation"

    @property
    def SCOPE_NAME(self) -> str:
        return f'api://{self.AUTH_CLIENT_ID}/{self.SCOPE_DESCRIPTION}'

    @property
    def SCOPES(self) -> dict:
        return {
            self.SCOPE_NAME: self.SCOPE_DESCRIPTION,
        }

    @property
    def OPENAPI_AUTHORIZATION_URL(self) -> str:
        return f"https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/authorize"

    @property
    def OPENAPI_TOKEN_URL(self) -> str:
        return f"https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/token"

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        case_sensitive = True

settings = Settings()





app = FastAPI(
    swagger_ui_oauth2_redirect_url='/oauth2-redirect',
    swagger_ui_init_oauth={
        'usePkceWithAuthorizationCodeGrant': True,
        'clientId': settings.OPENAPI_CLIENT_ID,
        'scopes': settings.SCOPE_NAME,
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


azure_scheme = SingleTenantAzureAuthorizationCodeBearer(
    app_client_id=settings.AUTH_CLIENT_ID,
    tenant_id=settings.TENANT_ID,
    scopes=settings.SCOPES,
)

@app.on_event('startup')
async def load_config() -> None:
    """
    Load OpenID config on startup.
    """
    await azure_scheme.openid_config.load_config()

def validate_user(expected_role: str):
    def role_checker(user: User = Depends(azure_scheme)):
        if expected_role in user.roles:
            return user
        raise InvalidAuth(f"User does not have the required role: {expected_role}")

    return role_checker


@app.get("/sge")
async def sge(user: User = Depends(validate_user("sge"))):
    return user.dict()

@app.get("/nw")
async def nw(user: User = Depends(validate_user("nw"))):
    return user.dict()