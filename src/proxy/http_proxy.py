import base64
import logging
import socket
import threading
from src.proxy.base import Proxy
from src.proxy.config import ProxyConfig

logger = logging.getLogger(__name__)


class HTTPProxy(Proxy):
    HTTP_RESPONSES = {
        0: b"",
        204: b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        401: b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\": \"unauthorized\"}",
        403: b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\": \"forbidden\"}",
        404: b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\": \"not found\"}",
        500: b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\": \"internal server error\"}",
    }

    PROXY_AUTH_REQUIRED = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\n\r\n"

    def __init__(self, config: ProxyConfig) -> None:
        super().__init__(config)
        self._running = False

    def start(self) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.config.host, self.config.port))
        self.server_socket.listen(self.config.max_connections)
        self._running = True
        logger.info(f"HTTP Proxy started on {self.config.host}:{self.config.port}")

        while self._running:
            try:
                client_socket, client_addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_addr)
                )
                client_thread.daemon = True
                client_thread.start()
            except OSError:
                break

    def stop(self) -> None:
        self._running = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

    def handle_client(self, client_socket: socket.socket, client_addr: tuple) -> None:
        try:
            request = client_socket.recv(self.config.buffer_size)
            if not request:
                client_socket.close()
                return

            if self.config.auth.enabled:
                if not self._check_auth(request):
                    logger.warning(f"Auth failed from {client_addr[0]}:{client_addr[1]}")
                    client_socket.sendall(self.PROXY_AUTH_REQUIRED)
                    return

            first_line = request.split(b'\n')[0].decode('utf-8', errors='ignore')
            parts = first_line.split(' ')
            if len(parts) < 2:
                client_socket.close()
                return

            method = parts[0]
            url = parts[1]
            logger.info(f"Request from {client_addr[0]}:{client_addr[1]} -> {first_line.strip()}")

            blacklist_match = self.get_blacklist_match(url)
            if blacklist_match:
                logger.warning(f"Blocked: {url} (response: {blacklist_match.response})")
                self._send_blacklist_response(client_socket, blacklist_match.response)
                return

            if method == 'CONNECT':
                self._handle_https_request(first_line, client_socket)
            elif url.startswith('http://'):
                webserver, port = self._parse_http_url(url)
                self._handle_http_request(webserver, port, request, client_socket)
            else:
                host = self._extract_host_header(request)
                if host:
                    webserver, port = self._parse_host_header(host)
                    self._handle_http_request(webserver, port, request, client_socket)
                else:
                    logger.warning(f"Cannot determine target host for request: {first_line.strip()}")
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _parse_http_url(self, url: str) -> tuple[str, int]:
        http_pos = url.find('://')
        temp = url[http_pos + 3:]
        port_pos = temp.find(':')
        webserver = ""
        port = 80

        if port_pos == -1:
            slash_pos = temp.find('/')
            if slash_pos == -1:
                webserver = temp
            else:
                webserver = temp[:slash_pos]
        else:
            webserver = temp[:port_pos]
            slash_pos = temp.find('/')
            if slash_pos == -1:
                port = int(temp[port_pos + 1:])
            else:
                port = int(temp[port_pos + 1:slash_pos])

        return webserver, port

    def _extract_host_header(self, request: bytes) -> str | None:
        try:
            request_str = request.decode('utf-8', errors='ignore')
            for line in request_str.split('\r\n'):
                if line.lower().startswith('host:'):
                    return line.split(':', 1)[1].strip()
            return None
        except Exception:
            return None

    def _parse_host_header(self, host: str) -> tuple[str, int]:
        if ':' in host:
            parts = host.split(':')
            return parts[0], int(parts[1])
        return host, 80

    def _handle_http_request(self, webserver: str, port: int, request: bytes, client_socket: socket.socket) -> None:
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(30)
            server_socket.connect((webserver, port))
            server_socket.send(request)

            while True:
                data = server_socket.recv(self.config.buffer_size)
                if len(data) > 0:
                    client_socket.send(data)
                else:
                    break
        except socket.timeout:
            logger.warning(f"Connection timeout to {webserver}:{port}")
        except Exception as e:
            logger.error(f"Error connecting to {webserver}:{port}: {e}")
        finally:
            if server_socket:
                try:
                    server_socket.close()
                except Exception:
                    pass

    def _handle_https_request(self, connect_line: str, client_socket: socket.socket) -> None:
        server_socket = None
        try:
            parts = connect_line.split(' ')
            address = parts[1]
            host_port = address.split(':')
            webserver = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(30)
            server_socket.connect((webserver, port))

            reply = "HTTP/1.1 200 Connection established\r\n"
            reply += "Proxy-agent: Simple-Proxy\r\n"
            reply += "\r\n"
            client_socket.sendall(reply.encode())

            client_socket.setblocking(False)
            server_socket.setblocking(False)

            self._tunnel_data(client_socket, server_socket)
        except socket.timeout:
            logger.warning(f"Connection timeout to {webserver}:{port}")
        except Exception as e:
            logger.error(f"Error in HTTPS tunnel: {e}")
        finally:
            if server_socket:
                try:
                    server_socket.close()
                except Exception:
                    pass

    def _tunnel_data(self, client_socket: socket.socket, server_socket: socket.socket) -> None:
        import select
        sockets = [client_socket, server_socket]
        timeout = 60
        
        while True:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, timeout)
                
                if exceptional:
                    break
                    
                if not readable:
                    break
                
                for sock in readable:
                    try:
                        data = sock.recv(self.config.buffer_size)
                        if not data:
                            return
                        
                        if sock is client_socket:
                            server_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                    except (socket.error, OSError):
                        return
            except Exception:
                break

    def _forward_data(self, source: socket.socket, destination: socket.socket) -> None:
        try:
            while True:
                data = source.recv(self.config.buffer_size)
                if not data:
                    break
                destination.sendall(data)
        except Exception:
            pass

    def _send_blacklist_response(self, client_socket: socket.socket, response_code: int) -> None:
        try:
            response = self.HTTP_RESPONSES.get(response_code, b"")
            if response:
                client_socket.sendall(response)
        except Exception:
            pass

    def _check_auth(self, request: bytes) -> bool:
        try:
            request_str = request.decode('utf-8', errors='ignore')
            for line in request_str.split('\r\n'):
                if line.lower().startswith('proxy-authorization:'):
                    auth_value = line.split(':', 1)[1].strip()
                    if auth_value.lower().startswith('basic '):
                        encoded = auth_value[6:]
                        decoded = base64.b64decode(encoded).decode('utf-8')
                        username, password = decoded.split(':', 1)
                        return username == self.config.auth.username and password == self.config.auth.password
            return False
        except Exception:
            return False
