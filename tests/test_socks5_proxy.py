import socket
import struct
from unittest.mock import MagicMock

from hypothesis import given, settings, strategies as st

from src.proxy.config import ProxyConfig, BlacklistItem
from src.proxy.socks5_proxy import SOCKS5Proxy


valid_proxy_types = st.sampled_from(["http", "socks5"])
valid_hosts = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789.-"),
    min_size=1,
    max_size=50
).filter(lambda x: not x.startswith("-") and not x.endswith("-") and ".." not in x)
valid_ports = st.integers(min_value=1, max_value=65535)
valid_buffer_sizes = st.integers(min_value=256, max_value=65536)
valid_max_connections = st.integers(min_value=1, max_value=1000)
valid_response_codes = st.sampled_from([0, 204, 401, 403, 404, 500])
valid_blacklist_urls = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789.-"),
    min_size=1,
    max_size=50
)


@st.composite
def valid_blacklist_item(draw):
    return BlacklistItem(domain=draw(valid_blacklist_urls), response=draw(valid_response_codes))


valid_blacklists = st.lists(valid_blacklist_item(), min_size=0, max_size=10)


@st.composite
def valid_proxy_configs(draw):
    from src.proxy.config import AuthConfig
    return ProxyConfig(
        proxy_type=draw(valid_proxy_types),
        host=draw(valid_hosts),
        port=draw(valid_ports),
        buffer_size=draw(valid_buffer_sizes),
        max_connections=draw(valid_max_connections),
        blacklist=tuple(draw(valid_blacklists)),
        auth=AuthConfig(enabled=False, username="", password=""),
    )


@st.composite
def socks5_greeting_with_version(draw, version: int):
    nmethods = draw(st.integers(min_value=1, max_value=255))
    methods = draw(st.binary(min_size=nmethods, max_size=nmethods))
    return bytes([version, nmethods]) + methods


@st.composite
def valid_socks5_greeting(draw):
    return draw(socks5_greeting_with_version(0x05))


@st.composite
def invalid_socks5_greeting(draw):
    version = draw(st.integers(min_value=0, max_value=255).filter(lambda x: x != 0x05))
    return draw(socks5_greeting_with_version(version))


@st.composite
def ipv4_address(draw):
    octets = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
    return bytes(octets)


@st.composite
def ipv6_address(draw):
    return draw(st.binary(min_size=16, max_size=16))


@st.composite
def domain_address(draw):
    domain = draw(st.text(
        alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789.-"),
        min_size=1,
        max_size=255
    ).filter(lambda x: not x.startswith("-") and not x.endswith("-") and ".." not in x))
    domain_bytes = domain.encode('utf-8')
    return bytes([len(domain_bytes)]) + domain_bytes, domain


@st.composite
def socks5_connect_request_ipv4(draw):
    addr = draw(ipv4_address())
    port = draw(st.integers(min_value=1, max_value=65535))
    port_bytes = struct.pack('!H', port)
    request = bytes([0x05, 0x01, 0x00, 0x01]) + addr + port_bytes
    expected_host = socket.inet_ntoa(addr)
    return request, expected_host, port


@st.composite
def socks5_connect_request_domain(draw):
    domain_data, domain = draw(domain_address())
    port = draw(st.integers(min_value=1, max_value=65535))
    port_bytes = struct.pack('!H', port)
    request = bytes([0x05, 0x01, 0x00, 0x03]) + domain_data + port_bytes
    return request, domain, port


@st.composite
def socks5_connect_request_ipv6(draw):
    addr = draw(ipv6_address())
    port = draw(st.integers(min_value=1, max_value=65535))
    port_bytes = struct.pack('!H', port)
    request = bytes([0x05, 0x01, 0x00, 0x04]) + addr + port_bytes
    expected_host = socket.inet_ntop(socket.AF_INET6, addr)
    return request, expected_host, port


@st.composite
def socks5_unsupported_command_request(draw):
    cmd = draw(st.integers(min_value=0, max_value=255).filter(lambda x: x != 0x01))
    addr = draw(ipv4_address())
    port = draw(st.integers(min_value=1, max_value=65535))
    port_bytes = struct.pack('!H', port)
    request = bytes([0x05, cmd, 0x00, 0x01]) + addr + port_bytes
    return request, cmd


def create_mock_socket(recv_data: bytes, buffer_size: int = 4096):
    mock_socket = MagicMock(spec=socket.socket)
    mock_socket.recv.return_value = recv_data
    sent_data = []
    mock_socket.send.side_effect = lambda data: sent_data.append(data) or len(data)
    mock_socket.sent_data = sent_data
    return mock_socket


@settings(deadline=None)
@given(config=valid_proxy_configs(), greeting=valid_socks5_greeting())
def test_property_9_socks5_version_handling_valid(config: ProxyConfig, greeting: bytes):
    """
    **Validates: Requirements 5.3, 5.4**
    """
    proxy = SOCKS5Proxy(config)
    mock_socket = create_mock_socket(greeting, config.buffer_size)
    result = proxy._handle_greeting(mock_socket)
    assert result is True
    assert mock_socket.sent_data == [bytes([0x05, 0x00])]


@settings(deadline=None)
@given(config=valid_proxy_configs(), greeting=invalid_socks5_greeting())
def test_property_9_socks5_version_handling_invalid(config: ProxyConfig, greeting: bytes):
    """
    **Validates: Requirements 5.3, 5.4**
    """
    proxy = SOCKS5Proxy(config)
    mock_socket = create_mock_socket(greeting, config.buffer_size)
    result = proxy._handle_greeting(mock_socket)
    assert result is False
    assert mock_socket.sent_data == []


@settings(deadline=None)
@given(config=valid_proxy_configs(), request_data=socks5_connect_request_ipv4())
def test_property_10_socks5_address_parsing_ipv4(config: ProxyConfig, request_data: tuple):
    """
    **Validates: Requirement 5.5**
    """
    request, expected_host, expected_port = request_data
    proxy = SOCKS5Proxy(config)
    mock_socket = create_mock_socket(request, config.buffer_size)
    result = proxy._handle_connection_request(mock_socket)
    assert result is not None
    host, port = result
    assert host == expected_host
    assert port == expected_port


@settings(deadline=None)
@given(config=valid_proxy_configs(), request_data=socks5_connect_request_domain())
def test_property_10_socks5_address_parsing_domain(config: ProxyConfig, request_data: tuple):
    """
    **Validates: Requirement 5.5**
    """
    request, expected_host, expected_port = request_data
    proxy = SOCKS5Proxy(config)
    mock_socket = create_mock_socket(request, config.buffer_size)
    result = proxy._handle_connection_request(mock_socket)
    assert result is not None
    host, port = result
    assert host == expected_host
    assert port == expected_port


@settings(deadline=None)
@given(config=valid_proxy_configs(), request_data=socks5_connect_request_ipv6())
def test_property_10_socks5_address_parsing_ipv6(config: ProxyConfig, request_data: tuple):
    """
    **Validates: Requirement 5.5**
    """
    request, expected_host, expected_port = request_data
    proxy = SOCKS5Proxy(config)
    mock_socket = create_mock_socket(request, config.buffer_size)
    result = proxy._handle_connection_request(mock_socket)
    assert result is not None
    host, port = result
    assert host == expected_host
    assert port == expected_port


@settings(deadline=None)
@given(config=valid_proxy_configs(), request_data=socks5_unsupported_command_request())
def test_property_11_socks5_unsupported_command_response(config: ProxyConfig, request_data: tuple):
    """
    **Validates: Requirement 5.6**
    """
    request, cmd = request_data
    proxy = SOCKS5Proxy(config)
    mock_socket = create_mock_socket(request, config.buffer_size)
    result = proxy._handle_connection_request(mock_socket)
    assert result is None
    assert len(mock_socket.sent_data) == 1
    response = mock_socket.sent_data[0]
    assert response[0] == 0x05
    assert response[1] == 0x07


@st.composite
def blacklisted_socks5_request(draw, blacklist: list[str]):
    if not blacklist:
        blacklist_item = draw(st.text(
            alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789.-"),
            min_size=1,
            max_size=50
        ).filter(lambda x: not x.startswith("-") and not x.endswith("-") and ".." not in x))
    else:
        blacklist_item = draw(st.sampled_from(blacklist))
    domain_bytes = blacklist_item.encode('utf-8')
    port = draw(st.integers(min_value=1, max_value=65535))
    port_bytes = struct.pack('!H', port)
    request = bytes([0x05, 0x01, 0x00, 0x03, len(domain_bytes)]) + domain_bytes + port_bytes
    return request, blacklist_item, port


@st.composite
def config_with_blacklist(draw):
    from src.proxy.config import AuthConfig
    blacklist_urls = draw(st.lists(
        st.text(
            alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789.-"),
            min_size=1,
            max_size=50
        ).filter(lambda x: not x.startswith("-") and not x.endswith("-") and ".." not in x),
        min_size=1,
        max_size=10
    ))
    blacklist = tuple(BlacklistItem(domain=url, response=draw(valid_response_codes)) for url in blacklist_urls)
    return ProxyConfig(
        proxy_type=draw(valid_proxy_types),
        host=draw(valid_hosts),
        port=draw(valid_ports),
        buffer_size=draw(valid_buffer_sizes),
        max_connections=draw(valid_max_connections),
        blacklist=blacklist,
        auth=AuthConfig(enabled=False, username="", password=""),
    )


@settings(deadline=None)
@given(data=st.data())
def test_property_12_socks5_blacklist_error_response(data):
    """
    **Validates: Requirement 5.7**
    """
    config = data.draw(config_with_blacklist())
    blacklist_item = data.draw(st.sampled_from(config.blacklist))
    domain_bytes = blacklist_item.domain.encode('utf-8')
    port = data.draw(st.integers(min_value=1, max_value=65535))
    port_bytes = struct.pack('!H', port)
    request = bytes([0x05, 0x01, 0x00, 0x03, len(domain_bytes)]) + domain_bytes + port_bytes
    
    proxy = SOCKS5Proxy(config)
    mock_socket = create_mock_socket(request, config.buffer_size)
    
    result = proxy._handle_connection_request(mock_socket)
    assert result is not None
    host, _ = result
    
    assert proxy.is_blacklisted(host) is True
