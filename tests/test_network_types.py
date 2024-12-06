import pytest

from network_types import IpSockEndpoint, IpConnection


def test_ip_socket_endpoint_setup():
    ip_sock_params = ["1.1.1.1", "tcp", "80"]
    ip_sock_obj = IpSockEndpoint(*ip_sock_params)

    assert ip_sock_obj.ip_addr == ip_sock_params[0]
    assert ip_sock_obj.tr_prot == ip_sock_params[1]
    assert ip_sock_obj.port_num == ip_sock_params[2]


def test_ip_connection_instance_init():
    ip_sock1 = IpSockEndpoint(*["1.1.1.1", "tcp", "80"])
    ip_sock2 = IpSockEndpoint(*["1.1.1.2", "tcp", "82"])

    ip_conn = IpConnection(start_socket=ip_sock1, end_socket=ip_sock2)
    assert ip_conn
    assert str(ip_conn) == "IP Connection object [IPv4, IpSocket(ip_addr='1.1.1.1', tr_prot='tcp', port_num='80'), IpSocket(ip_addr='1.1.1.2', tr_prot='tcp', port_num='82')]"
    assert repr(ip_conn) == "IP Connection object [IPv4, IpSocket(ip_addr='1.1.1.1', tr_prot='tcp', port_num='80'), IpSocket(ip_addr='1.1.1.2', tr_prot='tcp', port_num='82')]"
    assert ip_conn._conn_state == "NONE"

def test_ip_connection_instance_init_negative():
    ip_sock1 = IpSockEndpoint(*["1.1.1.1", "tcp", "80"])
    ip_sock2 = IpSockEndpoint(*["1.1.1.2", "tcp6", "82"])

    with pytest.raises(ValueError):
        IpConnection(start_socket=ip_sock1, end_socket=ip_sock2)
