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
    (AF_INET, SOCK_STREAM): "tcp",
    (AF_INET6, SOCK_STREAM): "tcp6",
    (AF_INET, SOCK_DGRAM): "udp",
    (AF_INET6, SOCK_DGRAM): "udp6"
})


@dataclass(frozen=True)
class SocketPairs:
    local_socket: IpSockEndpoint
    remote_socket: IpSockEndpoint


class IpConnection:
    """ Representation of ip connection.

    Args:
        start_socket: ip socket endpoint object (assumed opening endpoint)
        end_socket: ip socket endpoint object  (assumed ending endpoint)
        conn_state: state of ip connection, None is acceptable

    Attributes:
        _start_socket (IpSockEndpoint): ip socket endpoint object (assumed opening endpoint)
        _end_socket (IpSockEndpoint): ip socket endpoint object  (assumed ending endpoint)
        _conn_state (ConnStateT): state of ip connection, None is acceptable
    """
    def __init__(self, start_socket: IpSockEndpoint, end_socket: IpSockEndpoint, conn_state: ConnStateT = "NONE"):
        if start_socket.tr_prot != end_socket.tr_prot:
            raise ValueError("Different transport protocols used in socket endpoints.", start_socket.tr_prot, end_socket.tr_prot)

        if conn_state not in ConnState.members():
            raise ValueError("Connection state has to be one of following:", ConnState.members())

        self._start_socket = start_socket
        self._end_socket = end_socket
        self._conn_state = conn_state

    def __str__(self):
        return f"IP Connection object [IPv{self.ip_version}, {self._start_socket}, {self._end_socket}]"

    def __repr__(self):
        return f"IP Connection object [IPv{self.ip_version}, {self._start_socket}, {self._end_socket}]"

    @property
    def ip_version(self):
        if "6" in self._start_socket.tr_prot:
            return "6"
        return "4"

    @property
    def transport_protocol(self):
        return self._start_socket.tr_prot

if __name__ == "__main__":
    pass
