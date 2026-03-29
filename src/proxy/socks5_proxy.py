import logging
import socket
import struct
import threading
from src.proxy.base import Proxy
from src.proxy.config import ProxyConfig

logger = logging.getLogger(__name__)


class SOCKS5Proxy(Proxy):
    SOCKS5_VERSION = 0x05
    CMD_CONNECT = 0x01
    ATYP_IPV4 = 0x01
    ATYP_DOMAIN = 0x03
    ATYP_IPV6 = 0x04
    REPLY_SUCCESS = 0x00
    REPLY_CONNECTION_NOT_ALLOWED = 0x02
    REPLY_COMMAND_NOT_SUPPORTED = 0x07
    AUTH_NONE = 0x00
    AUTH_USERNAME_PASSWORD = 0x02
    AUTH_NO_ACCEPTABLE = 0xFF

    def __init__(self, config: ProxyConfig) -> None:
        super().__init__(config)
        self._running = False

    def start(self) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.config.host, self.config.port))
        self.server_socket.listen(self.config.max_connections)
        self._running = True
        logger.info(f"SOCKS5 Proxy started on {self.config.host}:{self.config.port}")

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
        target_socket = None
        try:
            if not self._handle_greeting(client_socket):
                return

            if self.config.auth.enabled:
                if not self._handle_auth(client_socket, client_addr):
                    return

            result = self._handle_connection_request(client_socket)
            if result is None:
                return

            target_host, target_port = result
            logger.info(f"Request from {client_addr[0]}:{client_addr[1]} -> {target_host}:{target_port}")

            if self.is_blacklisted(target_host):
                logger.warning(f"Blocked: {target_host}:{target_port}")
                self._send_reply(client_socket, self.REPLY_CONNECTION_NOT_ALLOWED)
                return

            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.connect((target_host, target_port))
            except Exception:
                return

            self._send_reply(client_socket, self.REPLY_SUCCESS)

            client_to_target = threading.Thread(
                target=self._forward_data,
                args=(client_socket, target_socket)
            )
            target_to_client = threading.Thread(
                target=self._forward_data,
                args=(target_socket, client_socket)
            )

            client_to_target.start()
            target_to_client.start()

            client_to_target.join()
            target_to_client.join()
        except Exception:
            pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            if target_socket:
                try:
                    target_socket.close()
                except Exception:
                    pass

    def _handle_greeting(self, client_socket: socket.socket) -> bool:
        try:
            greeting = client_socket.recv(self.config.buffer_size)
            if not greeting or len(greeting) < 2:
                return False

            version = greeting[0]
            if version != self.SOCKS5_VERSION:
                return False

            if self.config.auth.enabled:
                client_socket.send(bytes([self.SOCKS5_VERSION, self.AUTH_USERNAME_PASSWORD]))
            else:
                client_socket.send(bytes([self.SOCKS5_VERSION, self.AUTH_NONE]))
            return True
        except Exception:
            return False

    def _handle_auth(self, client_socket: socket.socket, client_addr: tuple) -> bool:
        try:
            auth_request = client_socket.recv(self.config.buffer_size)
            if not auth_request or len(auth_request) < 3:
                return False

            version = auth_request[0]
            if version != 0x01:
                client_socket.send(bytes([0x01, 0x01]))
                return False

            ulen = auth_request[1]
            if len(auth_request) < 2 + ulen + 1:
                client_socket.send(bytes([0x01, 0x01]))
                return False

            username = auth_request[2:2 + ulen].decode('utf-8')
            plen = auth_request[2 + ulen]

            if len(auth_request) < 3 + ulen + plen:
                client_socket.send(bytes([0x01, 0x01]))
                return False

            password = auth_request[3 + ulen:3 + ulen + plen].decode('utf-8')

            if username == self.config.auth.username and password == self.config.auth.password:
                client_socket.send(bytes([0x01, 0x00]))
                return True
            else:
                logger.warning(f"Auth failed from {client_addr[0]}:{client_addr[1]}")
                client_socket.send(bytes([0x01, 0x01]))
                return False
        except Exception:
            return False

    def _handle_connection_request(self, client_socket: socket.socket) -> tuple[str, int] | None:
        try:
            request = client_socket.recv(self.config.buffer_size)
            if not request or len(request) < 4:
                return None

            version = request[0]
            cmd = request[1]
            atyp = request[3]

            if version != self.SOCKS5_VERSION:
                return None

            if cmd != self.CMD_CONNECT:
                self._send_reply(client_socket, self.REPLY_COMMAND_NOT_SUPPORTED)
                return None

            target_host = ""
            target_port = 0

            if atyp == self.ATYP_IPV4:
                if len(request) < 10:
                    return None
                target_host = socket.inet_ntoa(request[4:8])
                target_port = struct.unpack('!H', request[8:10])[0]
            elif atyp == self.ATYP_DOMAIN:
                domain_len = request[4]
                if len(request) < 5 + domain_len + 2:
                    return None
                target_host = request[5:5 + domain_len].decode('utf-8')
                target_port = struct.unpack('!H', request[5 + domain_len:7 + domain_len])[0]
            elif atyp == self.ATYP_IPV6:
                if len(request) < 22:
                    return None
                target_host = socket.inet_ntop(socket.AF_INET6, request[4:20])
                target_port = struct.unpack('!H', request[20:22])[0]
            else:
                return None

            return target_host, target_port
        except Exception:
            return None

    def _send_reply(self, client_socket: socket.socket, reply_code: int) -> None:
        try:
            response = bytes([
                self.SOCKS5_VERSION,
                reply_code,
                0x00,
                self.ATYP_IPV4,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ])
            client_socket.send(response)
        except Exception:
            pass

    def _forward_data(self, source: socket.socket, destination: socket.socket) -> None:
        try:
            while True:
                data = source.recv(self.config.buffer_size)
                if not data:
                    break
                destination.sendall(data)
        except Exception:
            pass
