import json
import os
import tempfile
from dataclasses import FrozenInstanceError

import pytest
from hypothesis import given, settings, strategies as st, assume

from src.proxy.config import ConfigLoader, ConfigurationError, ProxyConfig, BlacklistItem


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
@given(config=valid_proxy_configs())
def test_property_1_configuration_round_trip(config: ProxyConfig):
    """
    **Validates: Requirement 1.1**
    """
    json_data = {
        "proxy_type": config.proxy_type,
        "proxy_host": config.host,
        "proxy_port": config.port,
        "buffer_size": config.buffer_size,
        "max_connections": config.max_connections,
        "blacklist": [{"domain": item.domain, "response": item.response} for item in config.blacklist],
    }
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(json_data, f)
        temp_path = f.name
    
    try:
        loaded_config = ConfigLoader.load(temp_path)
        assert loaded_config.proxy_type == config.proxy_type
        assert loaded_config.host == config.host
        assert loaded_config.port == config.port
        assert loaded_config.buffer_size == config.buffer_size
        assert loaded_config.max_connections == config.max_connections
        assert len(loaded_config.blacklist) == len(config.blacklist)
        for loaded, original in zip(loaded_config.blacklist, config.blacklist):
            assert loaded.domain == original.domain
            assert loaded.response == original.response
    finally:
        os.unlink(temp_path)


attribute_names = st.sampled_from(["proxy_type", "host", "port", "buffer_size", "max_connections", "blacklist"])


@given(config=valid_proxy_configs(), attr_name=attribute_names)
def test_property_2_proxyconfig_immutability(config: ProxyConfig, attr_name: str):
    """
    **Validates: Requirement 1.5**
    """
    original_value = getattr(config, attr_name)
    
    with pytest.raises(FrozenInstanceError):
        setattr(config, attr_name, "modified_value")
    
    assert getattr(config, attr_name) == original_value


malformed_json_strings = st.one_of(
    st.text(alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]\\;',./"), min_size=1, max_size=50).filter(
        lambda x: x.strip() and not x.strip().startswith("{") and not x.strip().startswith("[")
    ),
    st.just("{invalid json}"),
    st.just('{"key": }'),
    st.just('{"key": "value",}'),
    st.just("{"),
    st.just('{"unclosed": "string'),
)


@settings(deadline=None)
@given(malformed_content=malformed_json_strings)
def test_property_3_malformed_json_detection(malformed_content: str):
    """
    **Validates: Requirement 1.3**
    """
    try:
        json.loads(malformed_content)
        assume(False)
    except json.JSONDecodeError:
        pass
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(malformed_content)
        temp_path = f.name
    
    try:
        with pytest.raises(ConfigurationError) as exc_info:
            ConfigLoader.load(temp_path)
        assert "malformed" in str(exc_info.value).lower()
    finally:
        os.unlink(temp_path)


required_fields = ["proxy_type", "proxy_host", "proxy_port", "buffer_size", "max_connections", "blacklist"]


@st.composite
def configs_with_missing_fields(draw):
    all_fields = {
        "proxy_type": "http",
        "proxy_host": "localhost",
        "proxy_port": 8080,
        "buffer_size": 8192,
        "max_connections": 10,
        "blacklist": [],
    }
    
    fields_to_remove = draw(st.lists(
        st.sampled_from(required_fields),
        min_size=1,
        max_size=len(required_fields),
        unique=True
    ))
    
    config = {k: v for k, v in all_fields.items() if k not in fields_to_remove}
    return config, fields_to_remove


@settings(deadline=None)
@given(config_and_missing=configs_with_missing_fields())
def test_property_4_missing_fields_detection(config_and_missing: tuple):
    """
    **Validates: Requirement 1.4**
    """
    config, missing_fields = config_and_missing
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        temp_path = f.name
    
    try:
        with pytest.raises(ConfigurationError) as exc_info:
            ConfigLoader.load(temp_path)
        
        error_message = str(exc_info.value).lower()
        assert "missing" in error_message
        
        for field in missing_fields:
            assert field in error_message
    finally:
        os.unlink(temp_path)
