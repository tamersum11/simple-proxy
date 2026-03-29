from src.proxy.config import ConfigLoader
from src.proxy.base import Proxy
from src.proxy.http_proxy import HTTPProxy
from src.proxy.socks5_proxy import SOCKS5Proxy


class ProxyFactory:
    @staticmethod
    def create_from_config(config_path: str = None) -> Proxy:
        config = ConfigLoader.load(config_path)

        if config.proxy_type == "http":
            return HTTPProxy(config)
        elif config.proxy_type == "socks5":
            return SOCKS5Proxy(config)
        else:
            raise ValueError(f"Unsupported proxy type: {config.proxy_type}")
