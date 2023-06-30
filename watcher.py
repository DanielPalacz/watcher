
from abc import ABC, abstractmethod
from typing import Any, Optional


class WatcherBase(ABC):
    """ Abstract class for different type of Watchers. """

    @abstractmethod
    def watch(self, **spot_settings) -> Any:
        pass

    @abstractmethod
    def __prepare_watching_spot_settings(self, *args, **kwargs) -> Optional[dict]:
        pass

    @abstractmethod
    def __parse_watching_findings(self, *args, **kwargs) -> Any:
        pass


class IpSocksWatcher(WatcherBase):
    """ Adopts / utilizes psutil api for providing network sockets information. """

    @abstractmethod
    def watch(self, **spot_settings) -> Any:
        pass

    def __prepare_watching_spot_settings(self, *args, **kwargs) -> None:
        pass

    def __parse_watching_findings(self, *args, **kwargs) -> None:
        pass


class UnixSocksWatcher(WatcherBase):
    """ Adopts / utilizes psutil api for providing Unix sockets information. """

    @abstractmethod
    def watch(self, **spot_settings) -> Any:
        pass

    @abstractmethod
    def __prepare_watching_spot_settings(self, *args, **kwargs) -> Optional[dict]:
        pass

    @abstractmethod
    def __parse_watching_findings(self, *args, **kwargs) -> Any:
        pass
