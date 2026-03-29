import logging
import os
import sys

# Ensure the project root is on sys.path so 'src' package is importable
# regardless of how this file is invoked (python src/main.py vs python -m src.main).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.proxy.factory import ProxyFactory

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def main() -> None:
    proxy = ProxyFactory.create_from_config()
    proxy.start()


if __name__ == "__main__":
    main()
