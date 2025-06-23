import httpx
import json
import os

from pathlib import Path
from dotenv import load_dotenv
from models import DynamicClientRegistrationFastMCP
from fastmcp.server.auth import BearerAuthProvider
from okta.client import Client as OktaClient


load_dotenv()

RECORDS = json.loads(Path(__file__).with_name("records.json").read_text())
LOOKUP = {r["id"]: r for r in RECORDS}

# Your Okta settings
OKTA_DOMAIN = "https://trial-5021879.okta.com"
OKTA_ISSUER = f"{OKTA_DOMAIN}/oauth2/default"
OKTA_AUDIENCE = "api://default"  # or the audience value you set
OKTA_JWKS_URL = f"{OKTA_ISSUER}/v1/keys"
PROTECTED_ROUTE = ".well-known/oauth-protected-resource"
METADATA_ROUTE = ".well-known/oauth-authorization-server"
OKTA_METADATA_URL = f"{OKTA_ISSUER}/{METADATA_ROUTE}"
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN")

if not OKTA_API_TOKEN:
    raise ValueError("OKTA_API_TOKEN environment variable is required")

okta_client = OktaClient({
    "orgUrl": OKTA_DOMAIN,
    "token": OKTA_API_TOKEN
})


def create_server():
    bearer_auth = BearerAuthProvider(
        jwks_uri=OKTA_JWKS_URL,
        issuer=OKTA_ISSUER,
        audience=OKTA_AUDIENCE
    )

    mcp = DynamicClientRegistrationFastMCP(
        name="Cupcake MCP",
        instructions="Search cupcake orders",
        auth=bearer_auth,
        okta_client=okta_client,
        protected_route=PROTECTED_ROUTE,
        metadata_route=METADATA_ROUTE,
        metadata_url=OKTA_METADATA_URL
    )

    @mcp.tool()
    async def search(query: str) -> dict:
        """
        Search for cupcake orders – keyword match.
        """
        toks = query.lower().split()
        ids = []
        for r in RECORDS:
            hay = " ".join(
                [
                    r.get("title", ""),
                    r.get("text", ""),
                    " ".join(r.get("metadata", {}).values()),
                ]
            ).lower()
            if any(t in hay for t in toks):
                ids.append(r["id"])
        return {"ids": ids}

    @mcp.tool()
    async def fetch(id: str) -> dict:
        """
        Fetch a cupcake order by ID.
        """
        if id not in LOOKUP:
            raise ValueError("unknown id")
        return LOOKUP[id]
        

    return mcp


if __name__ == "__main__":
    create_server().run(transport="sse", host="127.0.0.1", port=8000)
