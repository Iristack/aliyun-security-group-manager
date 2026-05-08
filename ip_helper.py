"""IP helper with plugin-based public IP detection."""

import importlib.util
import inspect
import ipaddress
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from ip_fetcher_plugin import IpFetcherPlugin

logger = logging.getLogger("IpHelper")

# Default plugin timeout in seconds
PLUGIN_TIMEOUT = 10


class IpHelper:
    """Load and execute IP fetcher plugins."""

    def __init__(
        self,
        plugin_dir: str = "plugins",
        cur_v4_plugins: list[str] | None = None,
        cur_v6_plugins: list[str] | None = None,
    ) -> None:
        self._plugins: dict[str, IpFetcherPlugin] = {}
        self._plugin_dir: str = plugin_dir
        self._cur_v4 = cur_v4_plugins or []
        self._cur_v6 = cur_v6_plugins or []

        self._load_plugins()

    def _load_plugins(self) -> None:
        """Dynamically load plugins from the plugin directory."""
        if not os.path.isdir(self._plugin_dir):
            logger.warning("Plugin directory not found: %s", self._plugin_dir)
            return

        for filename in os.listdir(self._plugin_dir):
            if not filename.endswith(".py") or filename.startswith("__"):
                continue

            module_name = filename[:-3]
            filepath = os.path.join(self._plugin_dir, filename)

            try:
                spec = importlib.util.spec_from_file_location(
                    f"sgm.plugins.{module_name}", filepath
                )
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for _name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, IpFetcherPlugin)
                        and obj is not IpFetcherPlugin
                        and not inspect.isabstract(obj)
                    ):
                        instance = obj()
                        self._plugins[instance.name] = instance
                        logger.info("Loaded plugin: %s", instance.name)
            except Exception as e:
                logger.error("Failed to load plugin %s: %s", module_name, e)

    def _validate_ipv4(self, address: str) -> bool:
        """Validate that the address is a valid IPv4 string."""
        try:
            return ipaddress.ip_address(address).version == 4
        except ValueError:
            return False

    def get_public_ip_v4(self) -> str | None:
        """Fetch public IPv4 using configured plugins.

        Plugins are tried in order. If no order is configured, all loaded
        plugins are tried concurrently and the first valid result is returned.
        """
        if not self._plugins:
            logger.warning("No IP fetcher plugins loaded")
            return None

        # Ordered mode: try plugins sequentially
        if self._cur_v4:
            for name in self._cur_v4:
                plugin = self._plugins.get(name)
                if plugin is None:
                    logger.error("Plugin %s not found", name)
                    continue

                address = plugin.fetch()
                if not address:
                    logger.warning("Plugin %s returned empty address", name)
                    continue
                if not self._validate_ipv4(address):
                    logger.error("Plugin %s returned invalid IPv4: %s", name, address)
                    continue

                logger.info("Plugin %s returned valid IPv4: %s", name, address)
                return address

            return None

        # Unordered mode: try all plugins concurrently
        with ThreadPoolExecutor(max_workers=len(self._plugins)) as executor:
            futures = {
                executor.submit(p.fetch): p.name for p in self._plugins.values()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    address = future.result(timeout=PLUGIN_TIMEOUT)
                except Exception as e:
                    logger.error("Plugin %s raised exception: %s", name, e)
                    continue

                if not address:
                    logger.warning("Plugin %s returned empty address", name)
                    continue
                if not self._validate_ipv4(address):
                    logger.error("Plugin %s returned invalid IPv4: %s", name, address)
                    continue

                logger.info("Plugin %s returned valid IPv4: %s", name, address)
                return address

        return None
