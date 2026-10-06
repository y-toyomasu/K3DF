"""Run an isolated synthetic authentication check without runtime credentials."""

import asyncio
import io
import json
import secrets

from credential import write_credential
from probe import verify
from server import start_server


async def run():
    username = "ap02user"
    password = secrets.token_urlsafe(36)
    write_credential(io.StringIO(json.dumps({"username": username, "password": password})))
    listener = await start_server(host="127.0.0.1")
    try:
        await verify(username, password)
    finally:
        listener.close()
        await listener.wait_closed()


if __name__ == "__main__":
    asyncio.run(run())
    print("AP-02 isolated SSH positive, negative, and channel-denial checks passed.")
