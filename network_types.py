from typing import Literal
from enum import Enum
from dataclasses import dataclass
from collections import namedtuple


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


IpSock = namedtuple("IpSocket", "ip_addr port_num")
UnixSock = namedtuple("UnixSock", "type state inode path")


@dataclass(frozen=True)
class SocketPairs:
    local_socket: IpSock
    remote_socket: IpSock


@dataclass(frozen=True)
class IpConn:
    __slots__ = ['local_socket', 'remote_socket']
    local_socket: IpSock
    remote_socket: IpSock
    conn_state: Literal["ESTABLISHED", "LAST_ACK", "LISTEN", "NONE", "TIME_WAIT"]
