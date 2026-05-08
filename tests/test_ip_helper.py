"""Tests for IpHelper plugin loading and IP validation."""

import os

from ip_fetcher_plugin import IpFetcherPlugin
from ip_helper import IpHelper


class _FakePlugin(IpFetcherPlugin):
    """A stub plugin that returns a configured address."""

    def __init__(self, return_value: str | None = "1.2.3.4") -> None:
        super().__init__()
        self._return_value = return_value

    @property
    def name(self) -> str:
        return "FakePlugin"

    def fetch(self) -> str | None:
        return self._return_value


class TestIpHelperPluginLoading:
    def test_no_plugin_dir_returns_none(self) -> None:
        helper = IpHelper(plugin_dir="/nonexistent/path")
        assert helper.get_public_ip_v4() is None

    def test_empty_plugin_dir_returns_none(self, tmp_path) -> None:
        helper = IpHelper(plugin_dir=str(tmp_path))
        assert helper.get_public_ip_v4() is None

    def test_ordered_mode_returns_first_valid(self) -> None:
        helper = IpHelper.__new__(IpHelper)
        helper._plugin_dir = ""
        helper._cur_v4 = ["FakePlugin"]
        helper._cur_v6 = []
        helper._plugins = {"FakePlugin": _FakePlugin("5.6.7.8")}
        result = helper.get_public_ip_v4()
        assert result == "5.6.7.8"

    def test_ordered_mode_skips_invalid_ip(self) -> None:
        class _BadPlugin(_FakePlugin):
            @property
            def name(self) -> str:
                return "BadPlugin"

            def fetch(self) -> str | None:
                return "not-an-ip"

        helper = IpHelper.__new__(IpHelper)
        helper._plugin_dir = ""
        helper._cur_v4 = ["BadPlugin"]
        helper._cur_v6 = []
        helper._plugins = {"BadPlugin": _BadPlugin()}
        result = helper.get_public_ip_v4()
        assert result is None

    def test_ordered_mode_skips_missing_plugin(self) -> None:
        helper = IpHelper.__new__(IpHelper)
        helper._plugin_dir = ""
        helper._cur_v4 = ["MissingPlugin"]
        helper._cur_v6 = []
        helper._plugins = {}
        result = helper.get_public_ip_v4()
        assert result is None

    def test_unordered_mode_concurrent(self) -> None:
        helper = IpHelper.__new__(IpHelper)
        helper._plugin_dir = ""
        helper._cur_v4 = []
        helper._cur_v6 = []
        helper._plugins = {"FakePlugin": _FakePlugin("9.8.7.6")}
        result = helper.get_public_ip_v4()
        assert result == "9.8.7.6"

    def test_ipv6_address_rejected(self) -> None:
        helper = IpHelper.__new__(IpHelper)
        helper._plugin_dir = ""
        helper._cur_v4 = ["FakePlugin"]
        helper._cur_v6 = []
        helper._plugins = {"FakePlugin": _FakePlugin("::1")}
        result = helper.get_public_ip_v4()
        assert result is None

    def test_loads_real_plugins(self) -> None:
        plugin_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "plugins")
        helper = IpHelper(plugin_dir=plugin_dir)
        assert "DigFromMyIpOpenDns" in helper._plugins
        assert "SocketTrick" in helper._plugins
