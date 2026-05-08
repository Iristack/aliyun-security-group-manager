"""Public IP fetcher using UDP socket trick."""

import socket

from ip_fetcher_plugin import IpFetcherPlugin

# External target for UDP socket connection to determine local routing IP
DEFAULT_TARGET = ("8.8.8.8", 80)
# Socket timeout in seconds
SOCKET_TIMEOUT = 2


class SocketTrick(IpFetcherPlugin):
    """Fetch public IPv4 by opening a UDP socket to an external host."""

    @property
    def name(self) -> str:
        return "SocketTrick"

    def fetch(self) -> str | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(SOCKET_TIMEOUT)
                sock.connect(DEFAULT_TARGET)
                ip = sock.getsockname()[0]
                return ip
        except TimeoutError:
            self.logger.error("Timeout fetching IP using %s", self.name)
            return None
        except OSError as e:
            self.logger.error("Network error in %s: %s", self.name, e)
            return None
        except Exception as e:
            self.logger.error("Unexpected error in %s: %s", self.name, e)
            return None
