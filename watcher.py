from abc import ABC, abstractmethod
from typing import Any

import psutil
from typing import TypeVar
from socket import SOCK_DGRAM, SOCK_STREAM

from custom_types import FindingObject, NetProtocolT, TrProtocolT, IpConnection

sconnT = TypeVar('sconnT')



class WatcherService(ABC):
    """ Abstract class for different type of Watchers.

    Usage should be as follows:
        watcher = Watcher(**watching_params)
        watching_insights = watcher.run()
    """
    @abstractmethod
    def run(self, **kwargs) -> list[FindingObject]:
        """ Provides list of findings spotted by Watcher service """
        pass


class IpConnectionWatcher(WatcherService):
    """ Implements WatcherService functionality for different Ip connection types

    Args:
        ip_kind: ip version, allowed: IP4 or IP6
        transport_kind: transport protocol, allowed: TCP or UDP

    Attributes:
        __ip_kind (IPvT):  ip version, allowed: IP4 or IP6
        __transport_kind (TransportT): transport protocol, allowed: TCP or UDP
    """

    IP_MAPPER = {
        "IP4": "inet4",
        "IP6": "inet6"
    }

    TRANSPORT_MAPPER = {
        "TCP": SOCK_STREAM,
        "UDP": SOCK_DGRAM
    }

    def __init__(self, *, ip_kind: NetProtocolT, transport_kind: TrProtocolT):
        self.__ip_kind: NetProtocolT = ip_kind
        self.__transport_kind: transport_kind = transport_kind

    def run(self) -> list[IpConnection]:
        """ Provides list of findings spotted by IpConnectionWatcher service """
        ip_findings = self.__fetch_ip_connections()
        return [ip_finding for ip_finding in ip_findings]

    def __fetch_ip_connections(self):
        # Fetch all network connections:
        ip_kind_ = self.IP_MAPPER[self.__ip_kind]
        connections = psutil.net_connections(kind=ip_kind_)
        # Filter specific transport layer connections:
        return [self.__prepare_ip_connection(conn) for conn in connections if conn.type == self.TRANSPORT_MAPPER[self.__transport_kind]]


    def __prepare_ip_connection(self, connection_finding: sconnT) -> IpConnection:
        if connection_finding.pid is None:
            pid_ = "-"
        else:
            pid_ = connection_finding.pid

        ip_connection = IpConnection(ip_version=self.__ip_kind,
                                   transport_version=self.__transport_kind,
                                   local_address=str(connection_finding.laddr).replace(' ', ''),
                                   remote_address=str(connection_finding.raddr).replace(' ', ''),
                                   connection_state=connection_finding.status,
                                   pid_number=pid_
                                   )

        return ip_connection


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


class AnalyzerService(ABC):
    """ Abstract class for Analyzer Services """

    def analyze(self, findings: list[FindingObject]) -> list[tuple[FindingObject, bool]]:
        """ Method provides analyzing list of findings functionality

        Args:
            findings (list[FindingObject]): list of finding elements

        Returns:
            List of tuples with finding object and finding check. Example below:
            [(Finding1, FindingCheck1_bool), (Finding2, FindingCheck2_bool) ... ]
        """
        analyzing_results = []
        for finding_item in findings:
            finding_item_check = self.analyze_item(finding_item)
            analyzing_results.append((finding_item, finding_item_check))
        return analyzing_results

    @abstractmethod
    def analyze_item(self, founding: FindingObject) -> bool:
        pass # logic to be implemented


class IpConnectionAnalyzer(AnalyzerService):
    """ Class implements analyzing functionality  for IP connections"""

    @abstractmethod
    def analyze_item(self, founding: FindingObject) -> bool:
        pass


class ReporterService(ABC):
    """ Abstract class for reporting functionality """

    @classmethod
    @abstractmethod
    def report(cls, findings_checks) -> Any:
        """ Abstract method for reporting functionality

        Args:
            findings_checks (list[tuple[FindingObject, bool]]): list of tuples with finding object and finding check,
                                                                Example below:
                                                                [
                                                                    (Finding1, FindingCheck1_bool),
                                                                    (Finding2, FindingCheck2_bool) ...
                                                                ]
        Returns:
            Any
        """
        pass


class BasicReporter(ReporterService):
    """ Class implements basic reporting functionality """

    @classmethod
    def report(cls, findings_checks) -> None:
        """ Method implements basic way of reporting for problematic checks.

        Args:
            findings_checks (list[tuple[FindingObject, bool]]): list of tuples with finding object and finding check,
                                                          Example below:
                                                          [(Finding1, FindingCheck1_bool),
                                                           (Finding2, FindingCheck2_bool) ... ]

        Returns:
            None, only printing to console is performed
        """
        problematic_checks = [finding for finding in findings_checks if finding[1]]
        if problematic_checks:
            print("There are following problematic findings:")
        for problematic_finding in problematic_checks:
            problematic_finding, finding_marker = problematic_finding
            print(" *", str(problematic_finding))



class SupervisorManager:
    """ Class combining few functionalities through compositions and act as Supervisor

    Args:
        analyzer: object of Analyzer Service
        reporter: object of Reporter Service
        watcher: object of Watcher Service

    Attributes:
        analyzer (AnalyzerService): object of Analyzer Service
        reporter (ReporterService): object of Reporter Service
        watcher (WatcherService): object of Watcher Service
    """
    def __init__(self, analyzer: AnalyzerService, reporter: ReporterService, watcher: WatcherService): # depende
        self.analyzer = analyzer
        self.reporter = reporter
        self.watcher = watcher

    def report(self) -> None:
        """ Methods implements reporting functionality (based on Reported service)"""
        findings = self.watcher.run()
        findings_checks = self.analyzer.analyze(findings)
        self.reporter.report(findings_checks)


if __name__ == "__main__":
    # Mock
    class _MockedAnalyzerService(AnalyzerService):
        def analyze_item(self, founding: FindingObject) -> bool:
            return True

    mocked_analyzer = _MockedAnalyzerService()
    basic_reporter = BasicReporter()
    ip_watcher = IpConnectionWatcher(ip_kind="IP4", transport_kind="TCP")

    supervisor = SupervisorManager(analyzer=mocked_analyzer, reporter=basic_reporter, watcher=ip_watcher)
    supervisor.report()
