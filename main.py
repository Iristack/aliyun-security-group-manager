import logging
import os
import platform
import signal
import sys
import threading
from importlib.metadata import PackageNotFoundError, version
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import FrameType

import click

from aliyun_api import AliyunApi
from conf_helper import ConfHelper
from db_helper import DBHelper
from ip_helper import IpHelper

logger = logging.getLogger("SGM")
stared_sync:bool = False

# Module-level shutdown event
_shutdown_event = threading.Event()

SGM_DESCRIPTION = "Security Group Manager - Monitor public IP and sync Aliyun security groups"

try:
    _version = version("securitygroupmanager")
except PackageNotFoundError:
    _version = "0.0.1"


def _get_log_path() -> str:
    """Return platform-appropriate log file path."""
    os_type = platform.system()
    if os_type == "Windows":
        base = os.path.join(Path.home(), "AppData", "Local", "sgm")
    elif os_type == "Darwin":
        base = os.path.expanduser("~/Library/Logs/sgm")
    else:
        base = "/var/log/sgm"

    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "sgm.log")


def _init_logging(verbose: bool = False) -> None:
    """Configure logging with console + rotating file handlers."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "[%(asctime)s]-[%(name)s]-[%(levelname)s]: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stdout),
        RotatingFileHandler(
            _get_log_path(),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        ),
    ]

    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, handlers=handlers)


def _signal_handler(signum: int, frame: FrameType | None) -> None:
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    logger.info("Received signal %d, shutting down...", signum)
    _shutdown_event.set()


def _get_ip_helper() -> IpHelper:
    """Return the lazily-initialized IpHelper singleton."""
    conf = ConfHelper.get_instance()
    return IpHelper(
        plugin_dir=os.path.join(os.path.dirname(__file__), "plugins"),
        cur_v4_plugins=conf.get("plugins.ipv4"),
    )


def fetch_public_ipv4() -> str | None:
    """Check current public IP and sync security groups if changed.

    Returns the current IP address, or None if detection failed.
    """
    ip_helper = _get_ip_helper()
    cur_ip = ip_helper.get_public_ip_v4()
    last_ip = DBHelper.get_instance().get_last_ip()
    global stared_sync

    if cur_ip is None:
        logger.warning("Failed to fetch current public IP")
        return None

    if last_ip != cur_ip or stared_sync is False:
        logger.info("IP changed: %s -> %s", last_ip, cur_ip)
        DBHelper.get_instance().save_ip_change(last_ip, cur_ip)

        try:
            AliyunApi().sync_security_groups(last_ip, cur_ip)
            stared_sync = True
        except Exception as e:
            logger.error("Failed to sync security groups: %s", e)

    logger.info("Current public IP: %s", cur_ip)
    return cur_ip


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=_version, prog_name="sgm")
def cli() -> None:
    """Security Group Manager - Monitor and sync Aliyun security groups."""


@cli.command()
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default="./cfg/sgm.yaml",
    show_default=True,
    help="Path to configuration file",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option(
    "--once", is_flag=True, help="Run once and exit instead of polling",
)
def run(config: str, verbose: bool, once: bool) -> None:
    """Start the IP monitor daemon."""
    _init_logging(verbose=verbose)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    conf = ConfHelper.get_instance(config_path=config)
    interval = conf.model.interval

    logger.info(SGM_DESCRIPTION)
    logger.info("Polling interval: %d seconds", interval)

    if once:
        fetch_public_ipv4()
        return

    while not _shutdown_event.is_set():
        try:
            fetch_public_ipv4()
        except Exception as e:
            logger.error("Error during IP fetch: %s", e)

        _shutdown_event.wait(timeout=interval)

    logger.info("Shutdown complete")


@cli.command()
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default="./cfg/sgm.yaml",
    show_default=True,
    help="Path to configuration file",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
def check(config: str, verbose: bool) -> None:
    """Run a single IP check and display result."""
    _init_logging(verbose=verbose)
    ConfHelper.get_instance(config_path=config)

    ip = fetch_public_ipv4()
    if ip:
        click.echo(f"Current public IP: {ip}")
    else:
        click.echo("Failed to detect public IP", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default="./cfg/sgm.yaml",
    show_default=True,
    help="Path to configuration file",
)
@click.option(
    "-n", "--limit",
    default=10,
    show_default=True,
    help="Number of records to display",
)
def history(config: str, limit: int) -> None:
    """Show IP change history."""
    ConfHelper.get_instance(config_path=config)
    records = DBHelper.get_instance().get_history(limit=limit)
    if not records:
        click.echo("No IP change history found.")
        return
    for rec in records:
        click.echo(f"{rec['change_time']}  {rec['old_ip'] or '(none)'} -> {rec['new_ip']}")


if __name__ == "__main__":
    cli()
