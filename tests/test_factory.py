import json
import os
import tempfile

import pytest
from hypothesis import given, settings, strategies as st

from src.proxy.factory import ProxyFactory
from src.proxy.http_proxy import HTTPProxy
from src.proxy.socks5_proxy import SOCKS5Proxy
from src.proxy.config import BlacklistItem


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
def valid_blacklist_item_dict(draw):
    return {"domain": draw(valid_blacklist_urls), "response": draw(valid_response_codes)}


valid_blacklists = st.lists(valid_blacklist_item_dict(), min_size=0, max_size=10)


@st.composite
def valid_config_data(draw):
    proxy_type = draw(valid_proxy_types)
    return {
        "proxy_type": proxy_type,
        "proxy_host": draw(valid_hosts),
        "proxy_port": draw(valid_ports),
        "buffer_size": draw(valid_buffer_sizes),
        "max_connections": draw(valid_max_connections),
        "blacklist": draw(valid_blacklists),
    }


@settings(deadline=None)
@given(config_data=valid_config_data())
def test_property_5_factory_configuration_preservation(config_data: dict):
    """
    **Validates: Requirement 2.1**
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        proxy = ProxyFactory.create_from_config(temp_path)

        assert proxy.config.proxy_type == config_data["proxy_type"]
        assert proxy.config.host == config_data["proxy_host"]
        assert proxy.config.port == config_data["proxy_port"]
        assert proxy.config.buffer_size == config_data["buffer_size"]
        assert proxy.config.max_connections == config_data["max_connections"]
        assert len(proxy.config.blacklist) == len(config_data["blacklist"])
        for loaded, original in zip(proxy.config.blacklist, config_data["blacklist"]):
            assert loaded.domain == original["domain"]
            assert loaded.response == original["response"]

        if config_data["proxy_type"] == "http":
            assert isinstance(proxy, HTTPProxy)
        elif config_data["proxy_type"] == "socks5":
            assert isinstance(proxy, SOCKS5Proxy)
    finally:
        os.unlink(temp_path)


unsupported_proxy_types = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789_-"),
    min_size=1,
    max_size=20
).filter(lambda x: x not in ("http", "socks5"))


@settings(deadline=None)
@given(unsupported_type=unsupported_proxy_types)
def test_property_6_unsupported_proxy_type_rejection(unsupported_type: str):
    """
    **Validates: Requirement 2.4**
    """
    config_data = {
        "proxy_type": unsupported_type,
        "proxy_host": "localhost",
        "proxy_port": 8080,
        "buffer_size": 8192,
        "max_connections": 10,
        "blacklist": [],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        temp_path = f.name

    try:
        with pytest.raises(ValueError) as exc_info:
            ProxyFactory.create_from_config(temp_path)

        assert unsupported_type in str(exc_info.value)
    finally:
        os.unlink(temp_path)
