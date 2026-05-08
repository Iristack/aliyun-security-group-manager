"""Base class for IP fetcher plugins."""

import logging
from abc import ABC, abstractmethod


class IpFetcherPlugin(ABC):
    """Abstract base class for public IP detection plugins."""

    def __init__(self) -> None:
        module_name = self.__class__.__module__
        self.logger = logging.getLogger(module_name)

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique plugin identifier."""

    @abstractmethod
    def fetch(self) -> str | None:
        """Return the current public IP address, or None on failure."""
