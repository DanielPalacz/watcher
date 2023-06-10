from typing import Literal
from enum import Enum
from dataclasses import dataclass


class ConnState(Enum):
    ESTABLISHED = 1
    LAST_ACK = 2
    LISTEN = 3
    NONE = 4
    TIME_WAIT = 5


class NetProtocol(Enum):
    IP = 1
    IP6 = 2


class TrProtocol(Enum):
    TCP = 1
    TCP6 = 2
    UDP = 3
    UDP6 = 4


@dataclass(frozen=True)
class IpSocket:
    ip_addr: str
    port_num: int


@dataclass(frozen=True)
class SocketPairs:
    local_socket: IpSocket
    remote_socket: IpSocket


@dataclass(frozen=True)
class IpConnection:
    __slots__ = ['local_socket', 'remote_socket']
    local_socket: IpSocket
    remote_socket: IpSocket
    conn_state: Literal["ESTABLISHED", "LAST_ACK", "LISTEN", "NONE", "TIME_WAIT"]


@dataclass(frozen=True)
class UnixDomainSocket:
    ip_addr: str
    port_num: int

