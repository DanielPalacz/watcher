import click

from watcher import Ip4ConnectionAnalyzer, BasicReporter, IpConnectionWatcher, SupervisorManager, HtmlReporter


class Config:
    """Configuration class will be used across click module context for handling configuration details"""

    def __init__(self):
        self.version = "0.1"


pass_config = click.make_pass_decorator(Config, ensure=True)


@click.group()
@pass_config
def cli(config):
    """Hello in the app!"""
    pass


@cli.command()
@pass_config
@click.option('--report_type', default="Console", help='Type of report.')
def ip4_connections_check(config, report_type) -> None:
    """ Command runs IP4 connections checks.

    \b
    report_type:
      - by default it is 'Console' report
      - other possible option is 'Html' report"""

    report_types = ["Console", "Html"]

    if report_type == "Console":
        basic_reporter = BasicReporter()
    elif report_type == "Html":
        basic_reporter = HtmlReporter()
    else:
        raise ValueError("report type has to be one of:", report_types)

    ip_analyzer = Ip4ConnectionAnalyzer()
    ip_watcher = IpConnectionWatcher(ip_kind="IP4", transport_kind="TCP")
    supervisor = SupervisorManager(analyzer=ip_analyzer, reporter=basic_reporter, watcher=ip_watcher)
    supervisor.report("IP4:TCP")


if __name__ == "__main__":
    cli()
