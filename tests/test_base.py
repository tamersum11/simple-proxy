import socket

from hypothesis import given, settings, strategies as st

from src.proxy.base import Proxy
from src.proxy.config import ProxyConfig, BlacklistItem


class ConcreteProxy(Proxy):
    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def handle_client(self, client_socket: socket.socket, client_addr: tuple) -> None:
        pass


valid_proxy_types = st.sampled_from(["http", "socks5"])
valid_hosts = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789.-"),
    min_size=1,
    max_size=50
).filter(lambda x: not x.startswith("-") and not x.endswith("-") and ".." not in x)
valid_ports = st.integers(min_value=1, max_value=65535)
valid_buffer_sizes = st.integers(min_value=1, max_value=1048576)
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
valid_urls = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789.-/:_?=&"),
    min_size=0,
    max_size=200
)


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


@settings(deadline=None)
@given(config=valid_proxy_configs(), url=valid_urls)
def test_property_7_blacklist_matching_correctness(config: ProxyConfig, url: str):
    """
    **Validates: Requirements 3.3, 3.4, 6.2, 6.3**
    """
    proxy = ConcreteProxy(config)
    result = proxy.is_blacklisted(url)
    expected = any(item.domain in url for item in config.blacklist)
    assert result == expected


@settings(deadline=None)
@given(config=valid_proxy_configs())
def test_property_8_blacklist_initialization(config: ProxyConfig):
    """
    **Validates: Requirement 6.1**
    """
    proxy = ConcreteProxy(config)
    assert list(proxy._blacklist) == list(config.blacklist)
