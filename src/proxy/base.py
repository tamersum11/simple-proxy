from abc import ABC, abstractmethod
import socket
from src.proxy.config import ProxyConfig, BlacklistItem


class Proxy(ABC):
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self.server_socket: socket.socket | None = None
        self._blacklist = config.blacklist

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def handle_client(self, client_socket: socket.socket, client_addr: tuple) -> None:
        pass

    def get_blacklist_match(self, url: str) -> BlacklistItem | None:
        for item in self._blacklist:
            if item.domain in url:
                return item
        return None

    def is_blacklisted(self, url: str) -> bool:
        return self.get_blacklist_match(url) is not None
