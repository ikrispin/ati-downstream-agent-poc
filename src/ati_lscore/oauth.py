"""ATI-owned OAuth state. Tokens are local, owner-readable, and never logged."""

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from mcp.client.auth import OAuthClientProvider
from mcp.client.auth.utils import validate_metadata_issuer
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthMetadata,
    OAuthToken,
    ProtectedResourceMetadata,
)

from .models import AuthenticationRequired


class OAuthStorage:
    def __init__(self, directory: Path):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _read(self, name, kind):
        path = self.directory / name
        return kind.model_validate_json(path.read_text()) if path.exists() else None

    def _write(self, name, value):
        path = self.directory / name
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(value) if isinstance(value, dict) else value.model_dump_json())
        os.replace(temporary, path)

    async def get_tokens(self):
        return self._read("tokens.json", OAuthToken)

    async def set_tokens(self, tokens):
        self._write("tokens.json", tokens)

    async def get_client_info(self):
        return self._read("client.json", OAuthClientInformationFull)

    async def set_client_info(self, client_info):
        self._write("client.json", client_info)


class PersistentOAuthClientProvider(OAuthClientProvider):
    """Restore renewal state missing from the pinned MCP 1.30 provider.

    The SDK validates discovery and handles refresh requests. These small hooks
    retain that validated metadata across connections and permit a one-time
    refresh after a 401 for legacy state that predates the metadata cache.
    """

    allow_challenge_refresh = True
    _challenge_refresh = False

    async def _initialize(self):
        await super()._initialize()
        storage = self.context.storage
        path = storage.directory / "discovery.json"
        if not path.exists() or not self.context.client_info:
            # With legacy state, let the SDK discover the issuer on a 401 before
            # sending any refresh token. Never guess a token endpoint.
            return
        saved = json.loads(path.read_text())
        issuer = self.context.client_info.issuer
        if saved["server_url"] != self.context.server_url or not issuer:
            return
        metadata = OAuthMetadata.model_validate(saved["oauth_metadata"])
        validate_metadata_issuer(metadata, issuer)
        prm = saved.get("protected_resource_metadata")
        if prm:
            prm = ProtectedResourceMetadata.model_validate(prm)
            await self._validate_resource_match(prm)
        self.context.oauth_metadata = metadata
        self.context.auth_server_url = issuer
        self.context.protected_resource_metadata = prm
        tokens = self.context.current_tokens
        if tokens is not None and tokens.expires_in is not None:
            issued_at = (storage.directory / "tokens.json").stat().st_mtime
            self.context.token_expiry_time = issued_at + tokens.expires_in - 30

    def _save_discovery(self):
        context = self.context
        if context.oauth_metadata is not None:
            context.storage._write(
                "discovery.json",
                {
                    "server_url": context.server_url,
                    "oauth_metadata": context.oauth_metadata.model_dump(mode="json"),
                    "protected_resource_metadata": context.protected_resource_metadata.model_dump(
                        mode="json"
                    )
                    if context.protected_resource_metadata
                    else None,
                },
            )

    async def _perform_authorization(self):
        if self.allow_challenge_refresh and self.context.can_refresh_token():
            self._challenge_refresh = True
            return await self._refresh_token()
        return await super()._perform_authorization()

    async def _handle_token_response(self, response):
        if self._challenge_refresh:
            self._challenge_refresh = False
            if response.status_code != 200:
                raise AuthenticationRequired("Run ati-lscore support-login")
        await super()._handle_token_response(response)
        self._save_discovery()


def support_auth(url: str, directory: Path, *, redirect_handler=None, callback_handler=None):
    async def require_login(_url):
        raise AuthenticationRequired("Run ati-lscore support-login")

    async def require_callback():
        raise AuthenticationRequired("Run ati-lscore support-login")

    auth = PersistentOAuthClientProvider(
        server_url=url,
        client_metadata=OAuthClientMetadata(
            client_name="ATI native LSCore domain tools",
            redirect_uris=["http://localhost:8121/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=OAuthStorage(directory),
        redirect_handler=redirect_handler or require_login,
        callback_handler=callback_handler or require_callback,
    )
    auth.allow_challenge_refresh = redirect_handler is None
    return auth


async def login(url: str, directory: Path) -> None:
    """Listen on loopback while the user completes OAuth in their browser."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    future = asyncio.get_running_loop().create_future()

    async def callback(reader, writer):
        request = await reader.readline()
        path = request.decode().split(" ")[1]
        args = parse_qs(urlsplit(path).query)
        if "code" in args and not future.done():
            future.set_result((args["code"][0], args.get("state", [None])[0]))
        body = b"ATI sign-in received. You can return to the terminal."
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()

    async def redirect(auth_url):
        # Intentionally let the human choose a browser; never print tokens.
        print("Open this Support authorization URL in your browser:", auth_url, flush=True)

    async def receive():
        return await asyncio.wait_for(future, 300)

    async with await asyncio.start_server(callback, "127.0.0.1", 8121):
        auth = support_auth(url, directory, redirect_handler=redirect, callback_handler=receive)
        async with streamablehttp_client(url, auth=auth) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                print(
                    json.dumps(
                        {
                            "signed_in": True,
                            "case_tool_available": any(
                                t.name == "GetCaseDetailsByCaseId" for t in tools.tools
                            ),
                        }
                    )
                )
