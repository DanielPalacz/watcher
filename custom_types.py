from abc import ABC, abstractmethod
from typing import Literal
from enum import Enum
from dataclasses import dataclass, field


import psutil

NetProtocolCodeT = Literal["inet4", "inet6"]
NetProtocolT = Literal["IP4", "IP6"]
TrProtocolT = Literal["TCP", "UDP"]
ConnStateT = Literal["ESTABLISHED", "LAST_ACK", "LISTEN", "NONE", "TIME_WAIT"]


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


class FindingObject(ABC):

    FINDING_TYPE = None

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __repr__(self) -> str:
        pass


@dataclass
class IpConnection(FindingObject):
    """ Class for extended representation of IP connection

    Args:
        ip_version: ip version, allowed: IP4 or IP6
        transport_version: transport protocol, allowed: tcp, udp
        local_address: local address (IP, port) with following structure:
                                                                          addr(ip='127.0.0.1',port=9150)
        remote_address: local address (IP, port) with following structure:
                                                                          addr(ip='127.0.0.1',port=56162)
        connection_state: ip connection state,
                          one of following: "ESTABLISHED", "LAST_ACK", "LISTEN", "NONE", "TIME_WAIT"
        pid_number: pid number of the process linked with the given connection
        pid_details: process details of the process linked with the given connection or '-' if there is no such process

    Attributes:
        the same as Args

    """
    ip_version: NetProtocolT
    transport_version: TrProtocolT
    local_address: str
    remote_address: str
    connection_state: ConnStateT
    pid_number: str
    pid_details: str = "-"

    FINDING_TYPE: str = field(init=False, default="IP CONNECTION")

    def __str__(self) -> str:
        try:
            p = psutil.Process(int(self.pid_number))
            self.pid_details = f"{str(p).replace('psutil.Process', '')[1:-1]}"
        except ValueError:
            pass

        return (f"{self.ip_version}:{self.transport_version}; "
                f"Local:{self.local_address}; "
                f"Remote:{self.remote_address}; "
                f"Status:{self.connection_state}; "
                f"ProcessID:{self.pid_number}; ProcessDetails({self.pid_details})")

    def __repr__(self) -> str:
        return self.__str__()


if __name__ == "__main__":
    pass
