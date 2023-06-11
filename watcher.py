
from abc import ABC, abstractmethod
from typing import Any, Optional


class WatcherBase(ABC):
    """ Abstract class for different type of Watchers. """

    @classmethod
    @abstractmethod
    def watch(cls, **spot_settings) -> Any:
        pass

    @classmethod
    @abstractmethod
    def __prepare_watching_spot_settings(cls, *args, **kwargs) -> Optional[dict]:
        pass

    @classmethod
    @abstractmethod
    def __parse_watching_findings(cls, *args, **kwargs) -> Any:
        pass


class IpSocksWatcher(WatcherBase):
    """ Adopts / utilizes psutil api for providing network sockets information. """

    @classmethod
    @abstractmethod
    def watch(cls, **spot_settings) -> Any:
        pass

    @classmethod
    def __prepare_watching_spot_settings(cls, *args, **kwargs) -> None:
        pass

    @classmethod
    def __parse_watching_findings(cls, *args, **kwargs) -> None:
        pass


class UnixSocksWatcher(WatcherBase):
    """ Adopts / utilizes psutil api for providing Unix sockets information. """

    @classmethod
    @abstractmethod
    def watch(cls, **spot_settings) -> Any:
        pass

    @classmethod
    @abstractmethod
    def __prepare_watching_spot_settings(cls, *args, **kwargs) -> Optional[dict]:
        pass

    @classmethod
    @abstractmethod
    def __parse_watching_findings(cls, *args, **kwargs) -> Any:
        pass
