"""Run ATI or call its public A2A interface without MAS."""

import argparse
import asyncio
import json
import logging
from uuid import uuid4

import httpx

from .config import Settings


async def invoke(settings, prompt, url=None):
    async with httpx.AsyncClient(timeout=settings.deadline + 30) as client:
        response = await client.post(
            (url or settings.public_url) + "/a2a/jsonrpc",
            headers={"Authorization": f"Bearer {settings.token}", "A2A-Version": "1.0"},
            json={
                "jsonrpc": "2.0",
                "id": uuid4().hex,
                "method": "SendMessage",
                "params": {
                    "message": {
                        "messageId": uuid4().hex,
                        "contextId": "ati-direct-client",
                        "role": "ROLE_USER",
                        "parts": [{"text": prompt}],
                    }
                },
            },
        )
        response.raise_for_status()
        return response.json()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    commands.add_parser("support-login")
    call = commands.add_parser("invoke")
    call.add_argument("prompt")
    call.add_argument("--url")
    args = parser.parse_args()
    settings = Settings.load()
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("ati_downstream").setLevel(logging.INFO)
    if args.command == "serve":
        import uvicorn

        from .a2a_service import create_app

        uvicorn.run(
            create_app(settings.investigator(), settings.public_url, settings.token),
            host=settings.host,
            port=settings.port,
        )
    elif args.command == "support-login":
        from .oauth import login

        asyncio.run(login(settings.support_url, settings.state_dir / "oauth"))
    else:
        print(json.dumps(asyncio.run(invoke(settings, args.prompt, args.url)), indent=2))


if __name__ == "__main__":
    main()
