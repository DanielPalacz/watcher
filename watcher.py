
from abc import ABC, abstractmethod
from typing import Any, Optional

from psutil import net_connections
from psutil._common import sconn
from typing import TypeVar

from network_types import IpConnection, IpSockEndpoint, IpSockTrProtocolMapping


PsutilSconnT = TypeVar('PsutilSconnT', bound=sconn)


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


class IpConnectionWatcher(WatcherBase):
    """ Adopts / utilizes psutil api for providing ip connections information. """

    def watch(self, **spot_settings) -> Any:
        kind_ = spot_settings.get("kind") or "inet"
        connections_ = [self.__prepare_ip_connection(conn_) for conn_ in net_connections(kind=kind_)]

    def __prepare_watching_spot_settings(self, *args, **kwargs) -> None:
        pass

    def __parse_watching_findings(self, *args, **kwargs) -> None:
        pass

    @staticmethod
    def __prepare_ip_connection(conn_raw: PsutilSconnT) -> IpConnection:
        tr_protocol_ = IpSockTrProtocolMapping([(conn_raw.family, conn_raw.type)])
        start_socket = IpSockEndpoint(*[conn_raw.laddr.ip, tr_protocol_, conn_raw.laddr.port])
        end_socket = IpSockEndpoint(*[conn_raw.raddr.ip, tr_protocol_, conn_raw.raddr.port])

        return IpConnection(start_socket=start_socket, end_socket=end_socket, conn_state=conn_raw.status)


class IpSocksWatcher(WatcherBase):
    """ Adopts / utilizes psutil api for providing network sockets information. """

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
