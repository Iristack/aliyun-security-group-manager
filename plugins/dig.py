"""Public IP fetcher using dig + OpenDNS resolver."""

import subprocess

from ip_fetcher_plugin import IpFetcherPlugin

# Default command to query public IP via OpenDNS
DEFAULT_CMD = [
    "dig",
    "+short",
    "myip.opendns.com",
    "@resolver1.opendns.com",
]
# Timeout in seconds for the subprocess
CMD_TIMEOUT = 10


class DigFromMyIpOpenDns(IpFetcherPlugin):
    """Fetch public IPv4 via dig query to OpenDNS resolver."""

    @property
    def name(self) -> str:
        return "DigFromMyIpOpenDns"

    def fetch(self) -> str | None:
        try:
            result = subprocess.run(
                DEFAULT_CMD,
                capture_output=True,
                text=True,
                timeout=CMD_TIMEOUT,
                check=True,
            )
            ip = result.stdout.strip()
            return ip if ip else None
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout fetching IP using %s", self.name)
            return None
        except subprocess.CalledProcessError as e:
            self.logger.error(
                "Error fetching IP using %s: %s", self.name, e.stderr or e
            )
            return None
        except Exception as e:
            self.logger.error("Unexpected error in %s: %s", self.name, e)
            return None
