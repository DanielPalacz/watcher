from typing import Literal, Optional
from enum import Enum
from dataclasses import dataclass
from collections import namedtuple

from socket import AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM
from types import MappingProxyType


ConnStateT = Literal["ESTABLISHED", "LAST_ACK", "LISTEN", "NONE", "TIME_WAIT"]
NetProtocolT = Literal["IP", "IP6"]
TrProtocolT = Literal["TCP", "TCP6", "UDP", "UDP6"]

IpSockEndpoint = namedtuple("IpSocket", "ip_addr tr_prot port_num")
UnixSock = namedtuple("UnixSock", "type state inode path")


class ExtendedEnum(Enum):

    @classmethod
    def members(cls):
        return list(map(lambda m: m.name, cls))


class ConnState(ExtendedEnum):
    ESTABLISHED = 1
    LAST_ACK = 2
    LISTEN = 3
    NONE = 4
    TIME_WAIT = 5


class NetProtocol(ExtendedEnum):
    IP = 1
    IP6 = 2


class TrProtocol(ExtendedEnum):
    TCP = 1
    TCP6 = 2
    UDP = 3
    UDP6 = 4


IpSockTrProtocolMapping = MappingProxyType({
    "tcp": (AF_INET, SOCK_STREAM),
    "tcp6": (AF_INET6, SOCK_STREAM),
    "udp": (AF_INET, SOCK_DGRAM),
    "udp6": (AF_INET6, SOCK_DGRAM)

})


@dataclass(frozen=True)
class SocketPairs:
    local_socket: IpSockEndpoint
    remote_socket: IpSockEndpoint


class IpConnection:
    """ Representation of ip connection.

    Attributes:
        _start_socket (IpSockEndpoint): ip socket endpoint object (assumed opening endpoint)
        _end_socket (IpSockEndpoint): ip socket endpoint object  (assumed ending endpoint)
        _conn_state (None, IpSockEndpoint): state of ip connection, None is acceptable
    """
    def __init__(self, start_socket: IpSockEndpoint, end_socket: IpSockEndpoint, conn_state: Optional[ConnStateT] = None):
        """ Constructor

        Args:
            start_socket: ip socket endpoint object (assumed opening endpoint)
            end_socket: ip socket endpoint object  (assumed ending endpoint)
            conn_state: state of ip connection, None is acceptable
        """

        if start_socket.tr_prot != end_socket.tr_prot:
            raise ValueError("Different transport protocols used in socket endpoints.", start_socket.tr_prot, end_socket.tr_prot)

        self._start_socket = start_socket
        self._end_socket = end_socket
        self._conn_state = conn_state
