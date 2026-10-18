"""Run an isolated synthetic authentication check without runtime credentials."""

import asyncio
import os
import secrets

from credential import AP2_PASSWORD_ENV
from probe import verify
from server import start_server


async def run():
    username = "ap02user"
    password = secrets.token_urlsafe(36)
    os.environ[AP2_PASSWORD_ENV] = password
    listener = await start_server(host="127.0.0.1")
    try:
        await verify(username, password)
    finally:
        listener.close()
        await listener.wait_closed()


if __name__ == "__main__":
    asyncio.run(run())
    print("AP-02 isolated SSH positive, negative, and channel-denial checks passed.")
