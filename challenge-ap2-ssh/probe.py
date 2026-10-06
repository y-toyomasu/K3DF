"""Non-secret SSH acceptance probe, run inside the SSH runtime container."""

import asyncio
import secrets

import asyncssh

from credential import CREDENTIAL_PATH, _decode


async def verify(username, password):
    connection = await asyncssh.connect(
        "127.0.0.1",
        port=2222,
        username=username,
        password=password,
        known_hosts=None,
        client_keys=[],
    )
    try:
        try:
            await connection.create_process()
        except asyncssh.ChannelOpenError:
            pass
        else:
            raise AssertionError("SSH session channel was accepted")
    finally:
        connection.close()
        await connection.wait_closed()

    try:
        await asyncssh.connect(
            "127.0.0.1",
            port=2222,
            username=username,
            password=password + secrets.token_urlsafe(12),
            known_hosts=None,
            client_keys=[],
            agent_path=None,
        )
    except asyncssh.PermissionDenied:
        return
    raise AssertionError("invalid SSH credential was accepted")


if __name__ == "__main__":
    username, password = _decode(CREDENTIAL_PATH.read_bytes())
    asyncio.run(verify(username, password))
    print("AP-02 SSH authentication and denial checks passed; no credential values emitted.")
