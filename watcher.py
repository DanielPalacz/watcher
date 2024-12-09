from abc import ABC, abstractmethod
from typing import Any

import psutil
from typing import TypeVar
from socket import SOCK_DGRAM, SOCK_STREAM

from custom_types import FindingObject, NetProtocolT, TrProtocolT, IpConnection
from tools import ask_ai

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

    def analyze(self, findings: list[FindingObject]) -> list[tuple[FindingObject, str]]:
        """ Method provides analyzing list of findings functionality

        Args:
            findings (list[FindingObject]): list of finding elements

        Returns:
            List of tuples with finding object and finding check. Example below:
            [
             (Finding1, FindingCheck1_bool, FindingCheck1_comment),
             (Finding2, FindingCheck2_bool, FindingCheck2_comment) ...
            ]
        """
        analyzing_results = []
        for finding_item in findings:
            finding_item_comment = self.analyze_item(finding_item)
            analyzing_results.append((finding_item, finding_item_comment))

        return analyzing_results

    @abstractmethod
    def analyze_item(self, founding: FindingObject) -> str:
        pass # logic to be implemented


class Ip4ConnectionAnalyzer(AnalyzerService):
    """ Class implements analyzing functionality  for IP connections"""

    def analyze_item(self, finding: FindingObject) -> str:
        sentence = ""
        finding_split = str(finding).split(';')

        sentence += "There is following socket opened on my host: "
        sentence += finding_split[1].replace(" Local:addr", "")

        if "127.0.0.1" in finding_split[2]:
             sentence += " and second socket is also opened on my host: "
             sentence += finding_split[2].replace(" Remote:addr", "")
        elif "192.168.0.179" in finding_split[2]:
             sentence += " and second socket is also opened on my host: "
             sentence += finding_split[2].replace(" Remote:addr", "")
        elif "Remote:()" in finding_split[2]:
            sentence += " and second socket is not setuped"
        else:
            sentence += " and second socket: "
            sentence += finding_split[2].replace(" Remote:addr", "")

        sentence = sentence + " and status of connection is " + finding_split[3].replace(" Status:", "") + "."

        if "ProcessDetails(-)" in finding_split[5]:
            sentence += " And there is no process correlated with this connection."
        else:
            sentence = sentence + " And there is process correlated with this connection." + finding_split[5]

        sentence += " - could you say if there is something suspicious with this?"

        ai_answer = ask_ai(sentence)

        return ai_answer


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
        if findings_checks:
            print("There are following findings:")

        for finding in findings_checks:
            finding, finding_comment = finding
            print(" *", repr(finding), "\n", finding_comment, "\n\n\n")



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
        def analyze_item(self, founding: FindingObject) -> tuple[bool, str]:
            return True, "Comment"

    mocked_analyzer = _MockedAnalyzerService()
    ip_analyzer = Ip4ConnectionAnalyzer()
    basic_reporter = BasicReporter()
    ip_watcher = IpConnectionWatcher(ip_kind="IP4", transport_kind="TCP")

    supervisor = SupervisorManager(analyzer=ip_analyzer, reporter=basic_reporter, watcher=ip_watcher)
    supervisor.report()
