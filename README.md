# simple-proxy

HTTP/HTTPS and SOCKS5 proxy server with blacklist filtering.

## Usage

```bash
python -m src.main
```

## Docker

```bash
docker build -t proxy-server .
docker run -p 8080:8080 proxy-server
```

## Configuration

The proxy loads configuration from `config.json` in the project root by default.
Absolute path used when not specified in CLI: `./config.json` (same folder as `README.md`, `Dockerfile`, etc.).
If you want a custom path, call `ConfigLoader.load("/path/to/config.json")` in code.

Edit or create `config.json` with this schema:

```json
{
    "proxy_type": "http",
    "proxy_host": "0.0.0.0",
    "proxy_port": 8080,
    "buffer_size": 8192,
    "max_connections": 10,
    "auth": {
        "enabled": true,
        "username": "your-username",
        "password": "your-password"
    },
    "blacklist": [
        {"domain": "blocked-domain.com", "response": 401}
    ]
}
```

Required fields:
- `proxy_type` ("http" or "socks5")
- `proxy_host` (string)
- `proxy_port` (integer)
- `buffer_size` (integer)
- `max_connections` (integer)
- `blacklist` (array of {"domain": string, "response": integer})

[!IMPORTANT]
If you modify proxy_port in the config, ensure the Docker port mapping (e.g., -p 9090:9090) is updated accordingly to maintain connectivity.

Optional:
- `auth` with `enabled`, `username`, `password`
- Response codes for blacklist action: `0` (silent), `204`, `401`, `403`, `404`, `500`

## Tests

```bash
pip install pytest hypothesis
pytest tests/
```
