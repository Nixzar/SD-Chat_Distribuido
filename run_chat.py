"""Entrypoint para iniciar o servidor de chat.

Uso:
  python run_chat.py

Variáveis de ambiente opcionais:
  CHAT_HOST (default 0.0.0.0)
  CHAT_PORT (default 8080)
  MESSAGES_DB (default messages.db)
"""
from __future__ import annotations

import asyncio
import logging
import os

from chat import make_app

logging.basicConfig(level=logging.INFO)


def main():
    host = os.environ.get("CHAT_HOST", "0.0.0.0")
    port = int(os.environ.get("CHAT_PORT", "8080"))
    db_path = os.environ.get("MESSAGES_DB", "messages.db")

    server = make_app(host=host, port=port, db_path=db_path)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(server.start())
    except KeyboardInterrupt:
        print("Shutting down")


if __name__ == "__main__":
    main()
