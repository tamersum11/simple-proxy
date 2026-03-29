import socket
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.proxy.http_proxy import HTTPProxy
from src.proxy.config import ProxyConfig, BlacklistItem


@pytest.fixture
def config():
    from src.proxy.config import AuthConfig
    return ProxyConfig(
        proxy_type="http",
        host="127.0.0.1",
        port=8080,
        buffer_size=8192,
        max_connections=10,
        blacklist=(
            BlacklistItem(domain="blocked.com", response=401),
            BlacklistItem(domain="forbidden.org", response=204),
        ),
        auth=AuthConfig(enabled=False, username="", password=""),
    )


@pytest.fixture
def http_proxy(config):
    return HTTPProxy(config)


class TestParseHttpUrl:
    def test_parse_simple_url(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://example.com")
        assert webserver == "example.com"
        assert port == 80

    def test_parse_url_with_path(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://example.com/path/to/resource")
        assert webserver == "example.com"
        assert port == 80

    def test_parse_url_with_custom_port(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://example.com:8080")
        assert webserver == "example.com"
        assert port == 8080

    def test_parse_url_with_port_and_path(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://example.com:3000/api/v1")
        assert webserver == "example.com"
        assert port == 3000

    def test_parse_url_with_query_string(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://example.com/search?q=test")
        assert webserver == "example.com"
        assert port == 80

    def test_parse_url_with_port_and_query(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://example.com:9000/api?key=value")
        assert webserver == "example.com"
        assert port == 9000

    def test_parse_url_with_subdomain(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://api.example.com/v1")
        assert webserver == "api.example.com"
        assert port == 80

    def test_parse_url_with_ip_address(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://192.168.1.1/resource")
        assert webserver == "192.168.1.1"
        assert port == 80

    def test_parse_url_with_ip_and_port(self, http_proxy):
        webserver, port = http_proxy._parse_http_url("http://192.168.1.1:8000")
        assert webserver == "192.168.1.1"
        assert port == 8000


class TestBlacklistBlocking:
    def test_blacklisted_url_closes_connection(self, http_proxy):
        mock_socket = Mock(spec=socket.socket)
        mock_socket.recv.return_value = b"GET http://blocked.com/page HTTP/1.1\r\nHost: blocked.com\r\n\r\n"
        
        http_proxy.handle_client(mock_socket, ("127.0.0.1", 12345))
        
        mock_socket.close.assert_called()

    def test_blacklisted_url_in_path_closes_connection(self, http_proxy):
        mock_socket = Mock(spec=socket.socket)
        mock_socket.recv.return_value = b"GET http://example.com/redirect?url=blocked.com HTTP/1.1\r\n\r\n"
        
        http_proxy.handle_client(mock_socket, ("127.0.0.1", 12345))
        
        mock_socket.close.assert_called()

    def test_blacklisted_forbidden_org_closes_connection(self, http_proxy):
        mock_socket = Mock(spec=socket.socket)
        mock_socket.recv.return_value = b"GET http://forbidden.org/resource HTTP/1.1\r\n\r\n"
        
        http_proxy.handle_client(mock_socket, ("127.0.0.1", 12345))
        
        mock_socket.close.assert_called()

    @patch("src.proxy.http_proxy.socket.socket")
    def test_non_blacklisted_url_attempts_connection(self, mock_socket_class, http_proxy):
        mock_client = MagicMock()
        mock_client.recv.return_value = b"GET http://allowed.com/page HTTP/1.1\r\nHost: allowed.com\r\n\r\n"
        
        mock_server = MagicMock()
        mock_server.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n", b""]
        mock_socket_class.return_value = mock_server
        
        http_proxy.handle_client(mock_client, ("127.0.0.1", 12345))
        
        mock_server.connect.assert_called_once_with(("allowed.com", 80))

    def test_empty_request_closes_connection(self, http_proxy):
        mock_socket = Mock(spec=socket.socket)
        mock_socket.recv.return_value = b""
        
        http_proxy.handle_client(mock_socket, ("127.0.0.1", 12345))
        
        mock_socket.close.assert_called()

    def test_malformed_request_closes_connection(self, http_proxy):
        mock_socket = Mock(spec=socket.socket)
        mock_socket.recv.return_value = b"INVALID"
        
        http_proxy.handle_client(mock_socket, ("127.0.0.1", 12345))
        
        mock_socket.close.assert_called()
