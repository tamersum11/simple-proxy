from dataclasses import dataclass
import json
import os


class ConfigurationError(Exception):
    pass


@dataclass(frozen=True)
class BlacklistItem:
    domain: str
    response: int


@dataclass(frozen=True)
class AuthConfig:
    enabled: bool
    username: str
    password: str


@dataclass(frozen=True)
class ProxyConfig:
    proxy_type: str
    host: str
    port: int
    buffer_size: int
    max_connections: int
    blacklist: tuple[BlacklistItem, ...]
    auth: AuthConfig


class ConfigLoader:
    REQUIRED_FIELDS = {"proxy_type", "proxy_host", "proxy_port", "buffer_size", "max_connections", "blacklist"}

    @staticmethod
    def load(config_path: str = None) -> ProxyConfig:
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config.json")
        
        try:
            with open(config_path, "r") as f:
                content = f.read()
        except FileNotFoundError:
            raise ConfigurationError(f"Configuration file not found: {config_path}")
        except PermissionError:
            raise ConfigurationError(f"Configuration file is not readable: {config_path}")
        except OSError as e:
            raise ConfigurationError(f"Unable to read configuration file: {config_path} - {e}")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Malformed JSON in configuration file: {e}")

        missing_fields = ConfigLoader.REQUIRED_FIELDS - set(data.keys())
        if missing_fields:
            raise ConfigurationError(f"Missing required configuration fields: {', '.join(sorted(missing_fields))}")

        blacklist_items = tuple(
            BlacklistItem(domain=item["domain"], response=item["response"])
            for item in data["blacklist"]
        )

        auth_data = data.get("auth", {})
        auth_config = AuthConfig(
            enabled=auth_data.get("enabled", False),
            username=auth_data.get("username", ""),
            password=auth_data.get("password", ""),
        )

        return ProxyConfig(
            proxy_type=data["proxy_type"],
            host=data["proxy_host"],
            port=data["proxy_port"],
            buffer_size=data["buffer_size"],
            max_connections=data["max_connections"],
            blacklist=blacklist_items,
            auth=auth_config,
        )
