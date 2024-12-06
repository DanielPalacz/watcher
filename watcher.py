
from abc import ABC, abstractmethod
from typing import Any, Optional

from psutil import net_connections
import psutil
from typing import TypeVar

from network_types import IpConnection, IpSockEndpoint, IpSockTrProtocolMapping


# PsutilSconnT = TypeVar('PsutilSconnT', bound=sconn)


class WatcherService(ABC):
    """ Abstract class for different type of Watchers.

    Usage should be as follows:
        watcher = Watcher(**params)
        watching_insights = watcher.run()
    """
    @abstractmethod
    def run(self, **kwargs) -> list[str]:
        pass


class IpConnectionWatcher(WatcherService):
    """ Representation of ip connection.

    Args:
        spot_settings: watching parameters

    Attributes:
        __spot_settings (dict): watching parameters
    """
    def __init__(self, **spot_settings):
        self.__spot_settings = spot_settings

    def run(self) -> list[str]:
        connections_ = self.__fetch_ip_connections()
        return connections_

    def __fetch_ip_connections(self):
        kind_ = self.__spot_settings.get("kind") or "inet4"
        # Fetch all network connections
        connections = psutil.net_connections(kind=kind_)
        return [str(conn) for conn in connections]


class UnixSockWatcher(WatcherService):
    """ Adopts / utilizes psutil api for providing Unix sockets information. """

    def __init__(self, **spot_settings):
        self.__spot_settings = spot_settings

    def run(self) -> list[str]:
        connections_ = self.__fetch_unix_domain_socket_connections()
        return connections_

    @staticmethod
    def __fetch_unix_domain_socket_connections():
        kind_ = "unix"
        # Fetch all network connections
        connections = psutil.net_connections(kind=kind_)
        return [str(conn) for conn in connections]


class WatchingManager:
    def __init__(self, service: WatcherService): # Depends on abstraction
        self.service = service

    def watch(self):
        watching_insights = self.service.run()

if __name__ == "__main__":
    findings = IpConnectionWatcher().run()
    for finding in findings:
        print(finding)

    print()
    findings = UnixSockWatcher().run()
    for finding in findings:
        print(finding)

