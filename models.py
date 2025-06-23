import asyncio
import httpx
import time

from typing import List, Optional
from pydantic import BaseModel, HttpUrl
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from fastmcp.server import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse


class ClientRegistrationRequest(BaseModel):
    redirect_uris: List[HttpUrl]
    client_name: Optional[str] = None
    client_uri: Optional[HttpUrl] = None
    logo_uri: Optional[HttpUrl] = None
    scope: Optional[str] = "openid profile email"
    response_types: Optional[List[str]] = ["code"]
    grant_types: Optional[List[str]] = ["authorization_code", "refresh_token"]
    application_type: Optional[str] = "web"


class ClientRegistrationResponse(BaseModel):
    client_id: str
    client_secret: Optional[str] = None
    client_id_issued_at: int
    client_secret_expires_at: int
    redirect_uris: List[str]
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    scope: str
    response_types: List[str]
    grant_types: List[str]
    application_type: str


# --- ngrok URL cache (global, set at startup) ---
ngrok_public_url = None

async def fetch_ngrok_url():
    global ngrok_public_url
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get("http://127.0.0.1:4040/api/tunnels")
            tunnels = resp.json().get("tunnels", [])
            for tunnel in tunnels:
                public_url = tunnel.get("public_url")
                if public_url and public_url.startswith("https://"):
                    ngrok_public_url = public_url.rstrip("/")
                    return
    except Exception as e:
        print(f"Could not get ngrok url: {e}")
    ngrok_public_url = None


class DynamicClientRegistrationFastMCP(FastMCP):
    def __init__(self, name, instructions, auth=None, *, okta_client=None, protected_route=None, metadata_route=None, metadata_url=None):
        super().__init__(name=name, instructions=instructions, auth=auth)
        self.okta_client = okta_client
        self.protected_route = protected_route or ".well-known/oauth-protected-resource"
        self.metadata_route = metadata_route or ".well-known/oauth-authorization-server"
        self.metadata_url = metadata_url
    def http_app(self, *args, **kwargs):
        app = super().http_app(*args, **kwargs)

        app.add_middleware(
            CORSMiddleware,
            allow_origins=[
                "http://localhost",
                "http://localhost:6274",
                "http://127.0.0.1",
                "http://127.0.0.1:6274"
            ],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"]
        )

        async def root(_: Request):
            return None

        root_route = APIRoute(
            path="/",
            endpoint=root,
            methods=["GET", "POST"],
            name="root"
        )

        async def custom_protected(request: Request):
            if request.method == "OPTIONS":
                # CORS preflight response
                headers = {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
                return JSONResponse(content=None, status_code=200, headers=headers)
            
            data = {
                "resource_documentation": "https://mcp-server.com/docs",
            }
            return JSONResponse(content=data)

        # Route value from init parameters
        custom_protected_route = APIRoute(
            path=f"/{self.protected_route}",
            endpoint=custom_protected,
            methods=["GET", "OPTIONS"],
            name="custom_protected_override"
        )

        async def custom_discovery(request: Request):
            if request.method == "OPTIONS":
                # CORS preflight response
                headers = {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
                return JSONResponse(content=None, status_code=200, headers=headers)
            
            # Metadata URL from init parameters
            async with httpx.AsyncClient() as client:
                response = await client.get(self.metadata_url)
                data = response.json()
                # Use cached ngrok_public_url if available, else fallback
                registration_url = None
                if ngrok_public_url:
                    registration_url = ngrok_public_url + "/registration"
                else:
                    registration_url = str(request.base_url) + "/registration"
                
                data["registration_endpoint"] = registration_url
                return JSONResponse(content=data)

        # Metadata route from init parameters
        custom_discovery_route = APIRoute(
            path=f"/{self.metadata_route}",
            endpoint=custom_discovery,
            methods=["GET", "OPTIONS"],
            name="custom_discovery_override"
        )

        async def registration(request: ClientRegistrationRequest) -> ClientRegistrationResponse:
            #print(request)

            now = int(time.time())

            grant_types = [grant for grant in request.grant_types if grant != "urn:ietf:params:oauth:grant-type:device_code"] \
                if request.grant_types else ["authorization_code", "refresh_token"]

            if request.client_name == 'claudeai':
                application_type = "browser"
                token_endpoint_auth_method = "none"
            elif request.client_name == 'Visual Studio Code':
                application_type = "native"
                token_endpoint_auth_method = "none"
            else:
                # chatgpt
                application_type = "web"
                token_endpoint_auth_method = "client_secret_post"

            oauth_settings = {
                "redirect_uris": [str(uri) for uri in request.redirect_uris],
                "response_types": request.response_types or ["code"],
                "grant_types": grant_types,
                "application_type": application_type
            }

            if request.client_uri:
                oauth_settings["client_uri"] = str(request.client_uri)

            if request.logo_uri:
                oauth_settings["logo_uri"] = str(request.logo_uri)

            app_settings = {
                "name": "oidc_client",
                "label": request.client_name or "App Client",
                "signOnMode": "OPENID_CONNECT",
                "credentials": {
                    "oauthClient": {
                        "autoKeyRotation": True,
                        "token_endpoint_auth_method": token_endpoint_auth_method
                    }
                },
                "settings": {
                    "oauthClient": oauth_settings
                }
            }

            try:
                # Okta client from init parameters
                app = await self.okta_client.create_application(app_settings)
                app = app[0]

                # "DynamicAppCreationGroup" group
                group_id = "00gsbhkxyfyQaAMCm697"
                await self.okta_client.create_application_group_assignment(appId=app.id, groupId=group_id, application_group_assignment={})

                await asyncio.sleep(2)

            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Okta application creation failed: {str(e)}")
            
            # Map Okta app to response
            creds = getattr(app, "credentials", {})
            oauth_creds = getattr(creds, "oauth_client", {}) if creds else {}
            settings = getattr(app, "settings", {})
            oauth_client = getattr(settings, "oauth_client", {})

            response = ClientRegistrationResponse(
                client_id=getattr(app, "id", ""),
                client_secret=getattr(oauth_creds, "client_secret", "") or "",
                client_id_issued_at=now,
                client_secret_expires_at=0,
                redirect_uris=getattr(oauth_client, "redirect_uris", []),
                client_name=getattr(app, "label", None),
                client_uri=getattr(oauth_client, "client_uri", None),
                logo_uri=getattr(oauth_client, "logo_uri", None) or "http://fake.com/logo.png",
                scope=getattr(oauth_client, "scope", "openid"),
                response_types=getattr(oauth_client, "response_types", ["code"]),
                grant_types=getattr(oauth_client, "grant_types", ["authorization_code", "refresh_token"]),
                application_type=getattr(oauth_client, "application_type", "web")
            )

            return response

        registration_route = APIRoute(
            path="/registration",
            endpoint=registration,
            methods=["POST"],
            name="registration"
        )
        app.router.routes.insert(0, registration_route)
        app.router.routes.insert(0, custom_protected_route)
        app.router.routes.insert(0, custom_discovery_route)
        app.router.routes.insert(0, root_route)

        # Startup event: fetch ngrok URL once
        @app.on_event("startup")
        async def _():
            await fetch_ngrok_url()

        return app