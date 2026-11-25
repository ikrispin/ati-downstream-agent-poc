"""Exercise renewal through the real pinned SDK using a simulated OAuth server."""

import json
import os
import time
from urllib.parse import parse_qs

import httpx
import pytest
from mcp.client.auth import OAuthFlowError
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from ati_lscore.oauth import AuthenticationRequired, OAuthStorage, support_auth

SERVER = "https://support.test/mcp"
ISSUER = "https://auth.test/realm"


async def initial_credentials(directory):
    storage = OAuthStorage(directory)
    await storage.set_client_info(
        OAuthClientInformationFull(
            client_id="test-client", issuer=ISSUER, redirect_uris=["http://localhost:8121/callback"]
        )
    )
    await storage.set_tokens(
        OAuthToken(
            access_token="expired-access",
            refresh_token="private-refresh",
            token_type="Bearer",
            expires_in=900,
            scope="read",
        )
    )
    expired = time.time() - 1000
    os.utime(directory / "tokens.json", (expired, expired))
    return storage


def oauth_server(calls, *, reject_refresh=False):
    def handle(request):
        calls.append((request.method, str(request.url)))
        if request.url.path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(
                200,
                json={
                    "resource": SERVER,
                    "authorization_servers": [ISSUER],
                    "scopes_supported": ["read"],
                },
            )
        if ".well-known" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token",
                    "response_types_supported": ["code"],
                },
            )
        if str(request.url) == ISSUER + "/token":
            form = parse_qs(request.content.decode())
            assert form["grant_type"] == ["refresh_token"]
            assert form["client_id"] == ["test-client"]
            assert form["resource"] == [SERVER]
            if reject_refresh:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(
                200,
                json={
                    "access_token": "renewed-access",
                    "refresh_token": "rotated-private-refresh",
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "scope": "read",
                },
            )
        assert str(request.url) == SERVER, f"Unexpected OAuth request: {request.url}"
        if request.headers.get("authorization") == "Bearer renewed-access":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": (
                    'Bearer resource_metadata="https://support.test/'
                    '.well-known/oauth-protected-resource", scope="read"'
                )
            },
        )

    return httpx.MockTransport(handle)


async def test_legacy_saved_tokens_refresh_after_401_and_survive_new_provider(tmp_path):
    storage = await initial_credentials(tmp_path)
    calls = []
    async with httpx.AsyncClient(
        auth=support_auth(SERVER, tmp_path), transport=oauth_server(calls)
    ) as client:
        response = await client.post(SERVER)
    assert response.status_code == 200
    assert (await storage.get_tokens()).refresh_token == "rotated-private-refresh"
    assert any(url == ISSUER + "/token" for _, url in calls)

    calls.clear()
    async with httpx.AsyncClient(
        auth=support_auth(SERVER, tmp_path), transport=oauth_server(calls)
    ) as client:
        assert (await client.post(SERVER)).status_code == 200
    assert calls == [("POST", SERVER)]

    # A newly created provider must use the persisted renewal state, not repeat
    # the browser authorization flow or reset the old token's expiry.
    expired = time.time() - 1000
    os.utime(tmp_path / "tokens.json", (expired, expired))
    calls.clear()
    async with httpx.AsyncClient(
        auth=support_auth(SERVER, tmp_path), transport=oauth_server(calls)
    ) as client:
        response = await client.post(SERVER)
    assert response.status_code == 200
    assert calls[0] == ("POST", ISSUER + "/token")


@pytest.mark.parametrize("cached", [False, True])
async def test_rejected_refresh_reports_action_without_exposing_credentials(tmp_path, cached):
    await initial_credentials(tmp_path)
    if cached:
        async with httpx.AsyncClient(
            auth=support_auth(SERVER, tmp_path), transport=oauth_server([])
        ) as client:
            assert (await client.post(SERVER)).status_code == 200
        expired = time.time() - 1000
        os.utime(tmp_path / "tokens.json", (expired, expired))
    async with httpx.AsyncClient(
        auth=support_auth(SERVER, tmp_path), transport=oauth_server([], reject_refresh=True)
    ) as client:
        with pytest.raises(AuthenticationRequired, match="support-login") as error:
            await client.post(SERVER)
    assert "private-refresh" not in str(error.value)


async def test_cached_discovery_cannot_change_the_registered_issuer(tmp_path):
    await initial_credentials(tmp_path)
    async with httpx.AsyncClient(
        auth=support_auth(SERVER, tmp_path), transport=oauth_server([])
    ) as client:
        assert (await client.post(SERVER)).status_code == 200
    path = tmp_path / "discovery.json"
    data = json.loads(path.read_text())
    data["oauth_metadata"]["issuer"] = "https://other.test/realm"
    data["oauth_metadata"]["token_endpoint"] = "https://other.test/token"
    path.write_text(json.dumps(data))
    calls = []
    async with httpx.AsyncClient(
        auth=support_auth(SERVER, tmp_path), transport=oauth_server(calls)
    ) as client:
        with pytest.raises(OAuthFlowError, match="issuer mismatch"):
            await client.post(SERVER)
    assert calls == []
