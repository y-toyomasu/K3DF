"""Non-root SSH authentication endpoint for the isolated AP-02 challenge."""

import asyncio
import sys

import asyncssh

from credential import configured_password, verify_password


class ChallengeSSHServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return verify_password(username, password)

    def public_key_auth_supported(self):
        return False

    def host_based_auth_supported(self):
        return False

    def kbdint_auth_supported(self):
        return False

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        return False

    def session_requested(self):
        return None

    def server_requested(self, listen_host, listen_port):
        return False


async def start_server(host="0.0.0.0"):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    return await asyncssh.create_server(
        ChallengeSSHServer,
        host=host,
        port=2222,
        server_host_keys=[host_key],
        process_factory=None,
        sftp_factory=None,
        encoding=None,
        agent_forwarding=False,
        x11_forwarding=False,
    )


async def serve():
    configured_password()
    await start_server()
    await asyncio.Future()


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode == "serve":
        try:
            asyncio.run(serve())
        except ValueError:
            raise SystemExit("AP-02 password configuration is missing or invalid") from None
        return
    raise SystemExit("invalid operation")


if __name__ == "__main__":
    main()
