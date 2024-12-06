import datetime
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from linecache import cache
from typing import Any, Optional, Literal

from psutil import net_connections
import psutil
from psutil._common import sconn
from typing import TypeVar
from socket import SOCK_DGRAM, SOCK_STREAM

from network_types import IpConnection, IpSockEndpoint, IpSockTrProtocolMapping


sconnT = TypeVar('sconnT', bound=sconn)
IPvT = Literal["inet4", "inet6"]
TransportT = Literal["tcp", "udp"]


class FoundingObject(ABC):

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __repr__(self) -> str:
        pass


@dataclass
class IpConnectionFounding(FoundingObject):
    ip_version: str
    transport_version: str
    local_address: str
    remote_address: str
    connection_state: str
    pid_number: str
    pid_details: str = "-"


    def __str__(self) -> str:
        try:
            p = psutil.Process(int(self.pid_number))
            self.pid_details = f"{str(p).replace('psutil.Process', '')[1:-1]}"
        except ValueError:
            pass

        return (f"{self.ip_version}:{self.transport_version}, "
                f"Local:{self.local_address}, "
                f"Remote:{self.remote_address}, "
                f"Status:{self.connection_state}, "
                f"ProcessID:{self.pid_number}, ProcessDetails({self.pid_details})")

    def __repr__(self) -> str:
        try:
            p = psutil.Process(int(self.pid_number))
            self.pid_details = f"{str(p).replace('psutil.Process', '')[1:-1]}"
        except ValueError:
            pass

        return (f"{self.ip_version}:{self.transport_version}, "
                f"Local:{self.local_address}, "
                f"Remote:{self.remote_address}, "
                f"Status:{self.connection_state}, "
                f"ProcessID:{self.pid_number}, ProcessDetails({self.pid_details})")


class WatcherService(ABC):
    """ Abstract class for different type of Watchers.

    Usage should be as follows:
        watcher = Watcher(**watching_params)
        watching_insights = watcher.run()
    """
    @abstractmethod
    def run(self, **kwargs) -> list[FoundingObject]:
        """ Provides list of findings spotted by Watcher service """
        pass


class IpConnectionWatcher(WatcherService):
    """ Implements WatcherService functionality for different Ip connection types

    Args:
        ip_kind: ip version, allowed: inet4(IP4), inet6(IP6)
        transport_kind: transport protocol, allowed: tcp, udp

    Attributes:
        __ip_kind (IPvT):  ip version, allowed: inet4(IP4), inet6(IP6)
        __transport_kind (TransportT): transport protocol, allowed: tcp, udp
    """
    IP_MAPPER = {
        "inet4": "IP4",
        "inet6": "IP6"
    }

    TRANSPORT_MAPPER = {
        "tcp": SOCK_STREAM,
        "udp": SOCK_DGRAM
    }

    def __init__(self, *, ip_kind: IPvT, transport_kind: TransportT):
        self.__ip_kind = ip_kind
        self.__transport_kind = transport_kind

    def run(self) -> list[IpConnectionFounding]:
        """ Provides list of findings spotted by IpConnectionWatcher service """
        ip_foundings = self.__fetch_ip_connections()
        return [ip_founding for ip_founding in ip_foundings]

    def __fetch_ip_connections(self):
        # Fetch all network connections:
        connections = psutil.net_connections(kind=self.__ip_kind)
        # Filter specific transport layer connections:
        return [self.__prepare_ip_finding(conn) for conn in connections if conn.type == self.TRANSPORT_MAPPER[self.__transport_kind]]


    def __prepare_ip_finding(self, connection_finding: sconnT) -> IpConnectionFounding:
        if connection_finding.pid is None:
            pid_ = "-"
        else:
            pid_ = connection_finding.pid

        ip_founding = IpConnectionFounding(ip_version=self.IP_MAPPER[self.__ip_kind],
                                           transport_version=self.__transport_kind.upper(),
                                           local_address=str(connection_finding.laddr).replace(' ', ''),
                                           remote_address=str(connection_finding.raddr).replace(' ', ''),
                                           connection_state=connection_finding.status,
                                           pid_number=pid_
                                           )

        return ip_founding


class UnixSockWatcher(WatcherService):
    """ Implements WatcherService functionality for Unix sockets. """

    def run(self) -> list[str]:
        connections_ = self.__fetch_unix_domain_socket_connections()
        return [str(conn) for conn in connections_]

    @staticmethod
    def __fetch_unix_domain_socket_connections() -> list[sconnT]:

        # Fetch all unix domain socket connections
        connections = psutil.net_connections(kind= "unix")
        return [conn for conn in connections]


class WatchingManager:
    def __init__(self, service: WatcherService): # Depends on abstraction
        self.service = service

    def watch(self):
        watching_insights = self.service.run()

if __name__ == "__main__":
    findings = IpConnectionWatcher(ip_kind="inet4", transport_kind="tcp").run()
    for finding in findings:
        print(finding)

